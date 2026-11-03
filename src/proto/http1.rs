//! HTTP/1.1 (design §7.2): `GET/HEAD/PUT/DELETE /<key>` with `httparse`.
//!
//! Framing rules:
//! * `Transfer-Encoding` present → `Fatal` (the body framing is unknown, so we cannot
//!   find the next request): `LengthRequired` (411) without `Content-Length`,
//!   `BadCommand` (400) with both (request-smuggling guard). The connection replies
//!   and closes.
//! * Invalid or conflicting `Content-Length` → `Fatal{BadCommand}` (400).
//! * `Content-Length` > V + 64 → `Fatal{BadLength}` (413): we never drain big bodies.
//! * Other errors are `Reject` with `discard_body = Content-Length`, except when the
//!   client sent `Expect: 100-continue` (it may never send the body): then nothing is
//!   discarded and the response closes the connection.
//! * Keep-alive: HTTP/1.1 unless `Connection: close`; HTTP/1.0 only with
//!   `Connection: keep-alive`. A closing request sets `CLOSE_AFTER` and
//!   `st.closing`; after that `parse` returns `Incomplete` and consumes nothing.

use super::flags::*;
use super::{
    BodyHeader, FinishErr, Frame, HDR_CAP, HdrWriter, HttpState, Parsed, ProtoErr, ReqCtx, Request,
    Response, SetMode, parse_key,
};

pub const MAX_HEADER: usize = 8192;
const SLACK: u64 = 64;

/// HTTP has no multi-key requests; present for a uniform module shape.
#[derive(Copy, Clone, Debug, Default)]
pub struct MultiCursor;

fn has_token(v: &[u8], tok: &[u8]) -> bool {
    v.split(|&b| b == b',').any(|t| t.trim_ascii().eq_ignore_ascii_case(tok))
}

fn parse_cl(v: &[u8]) -> Option<u64> {
    let v = v.trim_ascii();
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(v.iter().fold(0u64, |a, &c| a * 10 + (c - b'0') as u64))
}

pub fn parse(st: &mut HttpState, buf: &[u8], value_len: u32) -> Parsed {
    if st.closing {
        return Parsed::Incomplete { min_more: 1 };
    }
    let v = value_len as u64;
    let lim = buf.len().min(MAX_HEADER);
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    let consumed = match req.parse(&buf[..lim]) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            return if lim >= MAX_HEADER {
                Parsed::Fatal { err: ProtoErr::TooLarge }
            } else {
                Parsed::Incomplete { min_more: 1 }
            };
        }
        Err(httparse::Error::TooManyHeaders) => return Parsed::Fatal { err: ProtoErr::TooLarge },
        Err(_) => return Parsed::Fatal { err: ProtoErr::BadCommand },
    };
    let (Some(method), Some(path), Some(version)) = (req.method, req.path, req.version) else {
        return Parsed::Fatal { err: ProtoErr::BadCommand };
    };

    let mut cl: Option<u64> = None;
    let mut cl_bad = false;
    let mut te = false;
    let (mut conn_close, mut conn_keep) = (false, false);
    let mut expect = false;
    for h in req.headers.iter() {
        let name = h.name.as_bytes();
        if name.eq_ignore_ascii_case(b"content-length") {
            match parse_cl(h.value) {
                Some(n) if cl.is_none_or(|c| c == n) => cl = Some(n),
                _ => cl_bad = true,
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            te = true;
        } else if name.eq_ignore_ascii_case(b"connection") {
            conn_close |= has_token(h.value, b"close");
            conn_keep |= has_token(h.value, b"keep-alive");
        } else if name.eq_ignore_ascii_case(b"expect") {
            expect |= h.value.trim_ascii().eq_ignore_ascii_case(b"100-continue");
        }
    }
    if te {
        let err = if cl.is_some() || cl_bad { ProtoErr::BadCommand } else { ProtoErr::LengthRequired };
        return Parsed::Fatal { err };
    }
    if cl_bad {
        return Parsed::Fatal { err: ProtoErr::BadCommand };
    }
    let body = cl.unwrap_or(0);
    if body > v + SLACK {
        return Parsed::Fatal { err: ProtoErr::BadLength };
    }
    let close = if version >= 1 { conn_close } else { conn_close || !conn_keep };
    let mut ctx = ReqCtx::default();
    if close {
        ctx.flags |= CLOSE_AFTER;
    }

    let mut reject = |err, mut ctx: ReqCtx| {
        let mut discard = body as u32;
        if expect && body > 0 {
            // The client may be waiting for 100 before sending: don't drain, close.
            discard = 0;
            ctx.flags |= CLOSE_AFTER;
        }
        if ctx.has(CLOSE_AFTER) {
            st.closing = true;
        }
        Parsed::Reject { err, ctx, consumed, discard_body: discard }
    };

    let m = method.as_bytes();
    let is_put = m == b"PUT";
    match m {
        b"GET" | b"HEAD" | b"DELETE" | b"PUT" => {}
        _ => return reject(ProtoErr::MethodNotAllowed, ctx),
    }
    if is_put && cl.is_none() {
        return reject(ProtoErr::LengthRequired, ctx);
    }
    if !is_put && body > 0 {
        return reject(ProtoErr::BadCommand, ctx);
    }
    let Some((key, repr)) = path.as_bytes().strip_prefix(b"/").and_then(parse_key) else {
        return reject(ProtoErr::BadKey, ctx);
    };
    ctx.key = key;
    ctx.repr = repr;
    if is_put && body != v {
        return reject(ProtoErr::BadLength, ctx);
    }
    if close {
        st.closing = true;
    }
    match m {
        b"PUT" => Parsed::Body {
            hdr: BodyHeader { mode: SetMode::Set, ctx, body_len: v as u32, expect_continue: expect },
            consumed,
        },
        b"HEAD" => {
            ctx.flags |= HEAD_ONLY;
            Parsed::Complete { req: Request::Get { ctx }, consumed }
        }
        b"GET" => Parsed::Complete { req: Request::Get { ctx }, consumed },
        _ => Parsed::Complete { req: Request::Delete { ctx }, consumed },
    }
}

/// HTTP bodies have no trailer.
pub fn finish_body(_st: &mut HttpState, _hdr: &mut BodyHeader, _buf: &[u8]) -> Result<usize, FinishErr> {
    Ok(0)
}

pub fn encode(_st: &HttpState, ctx: &ReqCtx, r: &Response, value_len: u32, out: &mut [u8; HDR_CAP]) -> Frame {
    let mut w = HdrWriter::new(out);
    if *r == Response::Continue {
        w.put(b"HTTP/1.1 100 Continue\r\n\r\n");
        return Frame { hdr_len: w.len as u16, value: false, trailer: b"", suppressed: false, close_after: false };
    }
    let mut close = ctx.has(CLOSE_AFTER);
    // (status line, Content-Length or None for 204, value follows)
    let (status, cl, value): (&[u8], Option<u32>, bool) = match r {
        Response::Hit => (b"200 OK", Some(value_len), !ctx.has(HEAD_ONLY)),
        Response::Miss | Response::NotFound => (b"404 Not Found", Some(0), false),
        Response::Stored | Response::Deleted => (b"204 No Content", None, false),
        Response::NotStored => (b"409 Conflict", Some(0), false),
        Response::Proto(e) => {
            let s: &[u8] = match e {
                ProtoErr::MethodNotAllowed => b"405 Method Not Allowed",
                ProtoErr::LengthRequired => b"411 Length Required",
                ProtoErr::BadLength => b"413 Content Too Large",
                ProtoErr::TooLarge => b"431 Request Header Fields Too Large",
                _ => b"400 Bad Request",
            };
            if matches!(e, ProtoErr::LengthRequired | ProtoErr::TooLarge) {
                close = true;
            }
            (s, Some(0), false)
        }
        _ => (b"500 Internal Server Error", Some(0), false),
    };
    w.put(b"HTTP/1.1 ");
    w.put(status);
    w.put(b"\r\n");
    if let Some(n) = cl {
        w.put(b"Content-Length: ");
        w.put_u64(n as u64);
        w.put(b"\r\n");
    }
    if *r == Response::Proto(ProtoErr::MethodNotAllowed) {
        w.put(b"Allow: GET, HEAD, PUT, DELETE\r\n");
    }
    // Always explicit, so HTTP/1.0 keep-alive clients see the persistent connection.
    w.put(if close { b"Connection: close\r\n" } else { b"Connection: keep-alive\r\n" });
    w.put(b"\r\n");
    Frame { hdr_len: w.len as u16, value, trailer: b"", suppressed: false, close_after: close }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::testutil::*;
    use crate::proto::{ProtoKind, ProtoState, parse_key};

    const V: u32 = 65536;
    const V2: u32 = 20000;
    const K1: &str = "00112233445566778899aabbccddeeff";
    const U1: &str = "123E4567-E89B-12D3-A456-426614174000";

    fn run(input: &[u8], v: u32) -> Vec<Ev> {
        drive_all(ProtoKind::Http, input, v)
    }
    fn render(ctx: &ReqCtx, r: Response) -> (String, Frame) {
        let (b, f) = enc(&ProtoState::new(ProtoKind::Http), ctx, r, V);
        (String::from_utf8(b).unwrap(), f)
    }
    fn req(method: &str, path: &str, ver: &str, hdrs: &[&str]) -> Vec<u8> {
        let mut s = format!("{method} {path} HTTP/{ver}\r\nHost: x\r\n");
        for h in hdrs {
            s.push_str(h);
            s.push_str("\r\n");
        }
        s.push_str("\r\n");
        s.into_bytes()
    }
    fn put(key: &str, len: usize, hdrs: &[&str]) -> Vec<u8> {
        let cl = format!("Content-Length: {len}");
        let mut h = vec![cl.as_str()];
        h.extend_from_slice(hdrs);
        let mut v = req("PUT", &format!("/{key}"), "1.1", &h);
        v.extend(std::iter::repeat_n(b'b', len));
        v
    }
    fn rej(e: &Ev) -> (ProtoErr, ReqCtx, u32) {
        match e {
            Ev::Reject { err, ctx, discard } => (*err, *ctx, *discard),
            e => panic!("expected Reject, got {e:?}"),
        }
    }

    #[test]
    fn get_head_delete_put() {
        let mut input = req("GET", &format!("/{K1}"), "1.1", &[]);
        input.extend(req("HEAD", &format!("/{U1}"), "1.1", &[]));
        input.extend(req("DELETE", &format!("/{K1}"), "1.1", &[]));
        input.extend(put(K1, V as usize, &[]));
        input.extend(req("GET", &format!("/{K1}"), "1.1", &[]));
        let evs = run(&input, V);
        assert_eq!(evs.len(), 5, "{evs:?}");
        let Ev::Req(Request::Get { ctx }) = evs[0] else { panic!() };
        assert_eq!(ctx.key, parse_key(K1.as_bytes()).unwrap().0);
        assert!(!ctx.has(HEAD_ONLY) && !ctx.has(CLOSE_AFTER));
        let (s, f) = render(&ctx, Response::Hit);
        assert_eq!(s, "HTTP/1.1 200 OK\r\nContent-Length: 65536\r\nConnection: keep-alive\r\n\r\n");
        assert!(f.value && f.trailer.is_empty() && !f.close_after && !f.suppressed);
        let (s, f) = render(&ctx, Response::Miss);
        assert_eq!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n");
        assert!(!f.value);

        let Ev::Req(Request::Get { ctx }) = evs[1] else { panic!() };
        assert!(ctx.has(HEAD_ONLY));
        let (s, f) = render(&ctx, Response::Hit);
        assert!(s.starts_with("HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n"));
        assert!(!f.value);

        let Ev::Req(Request::Delete { ctx }) = evs[2] else { panic!() };
        assert!(render(&ctx, Response::Deleted).0.starts_with("HTTP/1.1 204 No Content\r\nConnection"));
        assert!(render(&ctx, Response::NotFound).0.starts_with("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"));

        let Ev::Body(h, Ok(0)) = evs[3] else { panic!() };
        assert_eq!((h.mode, h.body_len, h.expect_continue), (SetMode::Set, V, false));
        assert_eq!(render(&h.ctx, Response::Stored).0, "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n");
        assert!(matches!(evs[4], Ev::Req(Request::Get { .. })));
    }

    #[test]
    fn keep_alive_rules() {
        let cases = [
            ("1.1", None, false),
            ("1.1", Some("Connection: close"), true),
            ("1.1", Some("Connection: Keep-Alive, Upgrade"), false),
            ("1.1", Some("connection: foo, CLOSE"), true),
            ("1.0", None, true),
            ("1.0", Some("Connection: keep-alive"), false),
            ("1.0", Some("Connection: close"), true),
        ];
        for (ver, hdr, close) in cases {
            let h: Vec<&str> = hdr.into_iter().collect();
            let mut input = req("GET", &format!("/{K1}"), ver, &h);
            input.extend(req("GET", &format!("/{K1}"), "1.1", &[]));
            let mut st = ProtoState::new(ProtoKind::Http);
            let (evs, pos) = drive(&mut st, &input, V, 0);
            let Ev::Req(Request::Get { ctx }) = evs[0] else { panic!() };
            assert_eq!(ctx.has(CLOSE_AFTER), close, "{ver} {hdr:?}");
            let (s, f) = render(&ctx, Response::Hit);
            assert_eq!(f.close_after, close);
            assert_eq!(s.contains("Connection: close\r\n"), close);
            assert_eq!(s.contains("Connection: keep-alive\r\n"), !close);
            // After a closing request the parser refuses further requests.
            assert_eq!(evs.len(), if close { 1 } else { 2 });
            assert_eq!(pos < input.len(), close);
            let ProtoState::Http(hs) = st else { panic!() };
            assert_eq!(hs.closing, close);
        }
    }

    #[test]
    fn put_length_rules() {
        let mut input = put(K1, 10, &[]);
        input.extend(put(K1, V2 as usize + 64, &[]));
        input.extend(req("PUT", &format!("/{K1}"), "1.1", &[]));
        input.extend(req("GET", &format!("/{K1}"), "1.1", &[]));
        let evs = run(&input, V2);
        assert_eq!(evs.len(), 4, "{evs:?}");
        let (e, ctx, d) = rej(&evs[0]);
        assert_eq!((e, d), (ProtoErr::BadLength, 10));
        assert!(render(&ctx, Response::Proto(e)).0.starts_with("HTTP/1.1 413 "));
        assert_eq!(rej(&evs[1]).2, V2 + 64);
        let (e, ctx, _) = rej(&evs[2]);
        assert_eq!(e, ProtoErr::LengthRequired);
        let (s, f) = render(&ctx, Response::Proto(e));
        assert!(s.starts_with("HTTP/1.1 411 Length Required\r\nContent-Length: 0\r\nConnection: close\r\n"));
        assert!(f.close_after);
        assert!(matches!(evs[3], Ev::Req(Request::Get { .. })));
        // Over V + 64 → Fatal, not drained.
        let evs = run(&put(K1, V2 as usize + 65, &[]), V2);
        assert!(matches!(evs[0], Ev::Fatal(ProtoErr::BadLength)));
    }

    #[test]
    fn transfer_encoding_and_bad_content_length() {
        let te = req("PUT", &format!("/{K1}"), "1.1", &["Transfer-Encoding: chunked"]);
        assert!(matches!(run(&te, V)[0], Ev::Fatal(ProtoErr::LengthRequired)));
        let both = req("PUT", &format!("/{K1}"), "1.1", &["Content-Length: 65536", "Transfer-Encoding: chunked"]);
        assert!(matches!(run(&both, V)[0], Ev::Fatal(ProtoErr::BadCommand)));
        let te_get = req("GET", &format!("/{K1}"), "1.1", &["Transfer-Encoding: chunked"]);
        assert!(matches!(run(&te_get, V)[0], Ev::Fatal(_)));
        let dup = req("PUT", &format!("/{K1}"), "1.1", &["Content-Length: 5", "Content-Length: 6"]);
        assert!(matches!(run(&dup, V)[0], Ev::Fatal(ProtoErr::BadCommand)));
        let neg = req("PUT", &format!("/{K1}"), "1.1", &["Content-Length: -1"]);
        assert!(matches!(run(&neg, V)[0], Ev::Fatal(ProtoErr::BadCommand)));
        let mut same = put(K1, V2 as usize, &["Content-Length: 20000"]);
        same.extend(req("GET", &format!("/{K1}"), "1.1", &[]));
        let evs = run(&same, V2);
        assert!(matches!(evs[0], Ev::Body(_, Ok(0))));
        assert_eq!(evs.len(), 2);
        let (s, f) = render(&ReqCtx::default(), Response::Proto(ProtoErr::LengthRequired));
        assert!(s.starts_with("HTTP/1.1 411 ") && f.close_after);
    }

    #[test]
    fn expect_continue() {
        let input = put(K1, V2 as usize, &["Expect: 100-continue"]);
        let evs = run(&input, V2);
        let Ev::Body(h, _) = evs[0] else { panic!() };
        assert!(h.expect_continue);
        let (s, f) = render(&ReqCtx { flags: CLOSE_AFTER, ..h.ctx }, Response::Continue);
        assert_eq!(s, "HTTP/1.1 100 Continue\r\n\r\n");
        assert!(!f.close_after && !f.value && !f.suppressed);
        // Rejected with Expect: don't wait for (or drain) the body; close instead.
        let mut input = req("PUT", &format!("/{K1}"), "1.1", &["Content-Length: 10", "Expect: 100-Continue"]);
        input.extend(req("GET", &format!("/{K1}"), "1.1", &[]));
        let evs = run(&input, V2);
        let (e, ctx, d) = rej(&evs[0]);
        assert_eq!((e, d), (ProtoErr::BadLength, 0));
        assert!(ctx.has(CLOSE_AFTER));
        assert_eq!(evs.len(), 1);
    }

    #[test]
    fn bad_requests() {
        let mut input = req("GET", "/nope", "1.1", &[]);
        input.extend(req("GET", &format!("/{K1}?x=1"), "1.1", &[]));
        input.extend(req("POST", &format!("/{K1}"), "1.1", &["Content-Length: 3"]));
        input.extend_from_slice(b"abc");
        input.extend(req("GET", &format!("/{K1}"), "1.1", &["Content-Length: 4"]));
        input.extend_from_slice(b"abcd");
        input.extend(put("short", V as usize, &[]));
        input.extend(req("GET", &format!("/{K1}"), "1.1", &[]));
        let evs = run(&input, V);
        assert_eq!(evs.len(), 6, "{evs:?}");
        let errs: Vec<(ProtoErr, u32)> = evs[..5].iter().map(|e| (rej(e).0, rej(e).2)).collect();
        use ProtoErr::*;
        assert_eq!(errs, [(BadKey, 0), (BadKey, 0), (MethodNotAllowed, 3), (BadCommand, 4), (BadKey, V)]);
        let c = ReqCtx::default();
        assert!(render(&c, Response::Proto(BadKey)).0.starts_with("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"));
        let (s, _) = render(&c, Response::Proto(MethodNotAllowed));
        assert!(s.starts_with("HTTP/1.1 405 Method Not Allowed\r\n") && s.contains("Allow: GET, HEAD, PUT, DELETE\r\n"));
        assert!(render(&c, Response::ServerErr).0.starts_with("HTTP/1.1 500 "));
        assert!(matches!(evs[5], Ev::Req(Request::Get { .. })));
        assert!(matches!(run(b"\x01\x02 garbage\r\n\r\n", V)[0], Ev::Fatal(ProtoErr::BadCommand)));
    }

    #[test]
    fn header_limits() {
        let big = format!("X-Big: {}", "a".repeat(MAX_HEADER));
        let input = req("GET", &format!("/{K1}"), "1.1", &[&big]);
        assert!(matches!(run(&input, V)[0], Ev::Fatal(ProtoErr::TooLarge)));
        let many: Vec<String> = (0..40).map(|i| format!("X-{i}: y")).collect();
        let refs: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
        let input = req("GET", &format!("/{K1}"), "1.1", &refs);
        assert!(matches!(run(&input, V)[0], Ev::Fatal(ProtoErr::TooLarge)));
        let (s, f) = render(&ReqCtx::default(), Response::Proto(ProtoErr::TooLarge));
        assert!(s.starts_with("HTTP/1.1 431 ") && f.close_after);
    }

    #[test]
    fn header_fits_worst_case() {
        let st = ProtoState::new(ProtoKind::Http);
        for flags in [0, CLOSE_AFTER, CLOSE_AFTER | HEAD_ONLY] {
            let ctx = ReqCtx { flags, ..Default::default() };
            for v in [u32::MAX, V, V2] {
                for r in ALL_RESPONSES {
                    let (b, _) = enc(&st, &ctx, r, v);
                    assert!(b.len() < HDR_CAP && b.ends_with(b"\r\n\r\n"), "{r:?}");
                }
                for e in ALL_ERRS {
                    let (b, _) = enc(&st, &ctx, Response::Proto(e), v);
                    assert!(b.len() < HDR_CAP && b.ends_with(b"\r\n\r\n"), "{e:?}");
                }
            }
        }
    }

    #[test]
    fn fuzz_no_panic() {
        let a = req("GET", &format!("/{K1}"), "1.1", &[]);
        let b = put(K1, 64, &["Expect: 100-continue"]);
        let c = req("PUT", &format!("/{K1}"), "1.0", &["Content-Length: 10", "Connection: keep-alive"]);
        let d = req("DELETE", &format!("/{U1}"), "1.1", &["Transfer-Encoding: chunked"]);
        let e = req("HEAD", "/x", "1.1", &["Connection: close"]);
        let pieces: Vec<&[u8]> = vec![&a, &b, &c, &d, &e, b"\r\n", b"GET /", b"HTTP/1.1", K1.as_bytes()];
        fuzz(ProtoKind::Http, &pieces, 64, 3000, 42);
        fuzz(ProtoKind::Http, &pieces, V2, 500, 4242);
    }
}
