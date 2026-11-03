//! memcached text + meta protocol (design §7.2).
//!
//! * `get/gets k…` is parsed one key per call: the first call consumes the command
//!   word and the first key, later calls consume one ` key` each (the delimiter after a
//!   key is left in the buffer), and the line end produces `MultiEnd` (`END\r\n`).
//! * A bad key inside a `get` line rejects the rest of the line with
//!   `CLIENT_ERROR`: keys already emitted keep their `VALUE` replies, no `END` is sent
//!   (memcached does the same). If the rest of the line is not in the buffer yet, the
//!   parser consumes what it has and keeps skipping on later calls; those later
//!   skips are returned as `Reject` with `flags::QUIET` (suppressed, no reply).
//! * Every other command needs its whole line in the buffer (at most `MAX_HEADER`).

use super::flags::*;
use super::{
    BodyHeader, Control, FinishErr, Frame, HDR_CAP, HdrWriter, MemcacheState, Opaque, Parsed,
    ProtoErr, ReqCtx, Request, Response, SetMode, parse_key,
};

/// Longest command line we buffer (a `get` line may be longer: it is consumed one
/// key at a time).
pub const MAX_HEADER: usize = 2048;

const MAX_TOKENS: usize = 24;
const MAX_KEY_TOKEN: usize = 36;
/// Accept declared lengths up to V + SLACK as "sane" (drain and reject); above: Fatal.
const SLACK: u64 = 64;

/// Resumable cursor for `get/gets k1 k2 …`.
#[derive(Copy, Clone, Debug, Default)]
pub struct MultiCursor {
    with_cas: bool,
    /// Skipping the rest of a rejected line whose end has not been seen yet.
    skip_line: bool,
}

#[inline]
fn is_sp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

#[inline]
fn is_delim(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\r' || b == b'\n'
}

fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 19 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u64;
    }
    Some(v)
}

fn parse_i64(s: &[u8]) -> Option<i64> {
    match s.split_first() {
        Some((b'-', rest)) => parse_u64(rest).map(|v| -(v as i64)),
        _ => parse_u64(s).map(|v| v as i64),
    }
}

fn incomplete(buf: &[u8]) -> Parsed {
    if buf.len() >= MAX_HEADER {
        Parsed::Fatal { err: ProtoErr::TooLarge }
    } else {
        Parsed::Incomplete { min_more: 1 }
    }
}

fn reject(err: ProtoErr, ctx: ReqCtx, consumed: usize, discard_body: u64) -> Parsed {
    Parsed::Reject { err, ctx, consumed, discard_body: discard_body as u32 }
}

fn complete(req: Request, consumed: usize) -> Parsed {
    Parsed::Complete { req, consumed }
}

/// Split `line` into whitespace-separated tokens. `None` if more than MAX_TOKENS.
fn tokenize<'a>(line: &'a [u8], toks: &mut [&'a [u8]; MAX_TOKENS]) -> Option<usize> {
    let mut n = 0;
    for t in line.split(|&b| is_sp(b)).filter(|t| !t.is_empty()) {
        if n == MAX_TOKENS {
            return None;
        }
        toks[n] = t;
        n += 1;
    }
    Some(n)
}

pub fn parse(st: &mut MemcacheState, buf: &[u8], value_len: u32) -> Parsed {
    if let Some(cur) = st.multi {
        if cur.skip_line {
            return skip_line(st, buf);
        }
        return get_next(st, cur, buf, 0, false);
    }
    if buf.is_empty() {
        return Parsed::Incomplete { min_more: 1 };
    }
    // Command word: `get`/`gets` take the per-key path; everything else needs a line.
    let scan = buf.len().min(5);
    if let Some(i) = buf[..scan].iter().position(|&b| is_delim(b)) {
        let word = &buf[..i];
        if word == b"get" || word == b"gets" {
            let cur = MultiCursor { with_cas: word == b"gets", skip_line: false };
            return get_next(st, cur, buf, i, true);
        }
    }
    parse_line(buf, value_len as u64)
}

/// Continue the rest of a rejected `get` line: consume up to and including `\n`.
fn skip_line(st: &mut MemcacheState, buf: &[u8]) -> Parsed {
    let quiet = ReqCtx { flags: QUIET, ..Default::default() };
    match memchr::memchr(b'\n', buf) {
        Some(nl) => {
            st.multi = None;
            reject(ProtoErr::BadKey, quiet, nl + 1, 0)
        }
        None if buf.is_empty() => Parsed::Incomplete { min_more: 1 },
        None => reject(ProtoErr::BadKey, quiet, buf.len(), 0),
    }
}

/// One step of `get/gets`: at `buf[p..]` expect optional spaces then a key or the line end.
fn get_next(st: &mut MemcacheState, cur: MultiCursor, buf: &[u8], mut p: usize, first: bool) -> Parsed {
    while p < buf.len() && is_sp(buf[p]) {
        p += 1;
    }
    if p >= buf.len() {
        return incomplete(buf);
    }
    let eol = match buf[p] {
        b'\n' => Some(p + 1),
        b'\r' => {
            if p + 1 >= buf.len() {
                return Parsed::Incomplete { min_more: 1 };
            }
            if buf[p + 1] == b'\n' { Some(p + 2) } else { None }
        }
        _ => None,
    };
    if let Some(end) = eol {
        st.multi = None;
        if first {
            // `get` with no keys.
            return reject(ProtoErr::BadCommand, ReqCtx::default(), end, 0);
        }
        return complete(Request::MultiEnd { ctx: ReqCtx::default() }, end);
    }
    let ts = p;
    let mut te = p;
    let mut bad = buf[p] == b'\r'; // stray CR not followed by LF
    if !bad {
        while te < buf.len() && !is_delim(buf[te]) {
            te += 1;
        }
        if te - ts > MAX_KEY_TOKEN {
            bad = true;
        } else if te == buf.len() {
            return incomplete(buf);
        }
    }
    if !bad && let Some((key, repr)) = parse_key(&buf[ts..te]) {
        let mut flags = MULTI;
        if cur.with_cas {
            flags |= WITH_CAS;
        }
        st.multi = Some(cur);
        let ctx = ReqCtx { flags, repr, key, ..Default::default() };
        return complete(Request::Get { ctx }, te);
    }
    // Bad key: reject the rest of the line.
    let ctx = ReqCtx::default();
    match memchr::memchr(b'\n', &buf[ts..]) {
        Some(i) => {
            st.multi = None;
            reject(ProtoErr::BadKey, ctx, ts + i + 1, 0)
        }
        None => {
            st.multi = Some(MultiCursor { skip_line: true, ..cur });
            reject(ProtoErr::BadKey, ctx, buf.len(), 0)
        }
    }
}

fn parse_line(buf: &[u8], v: u64) -> Parsed {
    let lim = buf.len().min(MAX_HEADER);
    let nl = match memchr::memchr(b'\n', &buf[..lim]) {
        Some(i) => i,
        None => return incomplete(buf),
    };
    let consumed = nl + 1;
    let mut line = &buf[..nl];
    if let [rest @ .., b'\r'] = line {
        line = rest;
    }
    let mut toks: [&[u8]; MAX_TOKENS] = [&[]; MAX_TOKENS];
    let n = match tokenize(line, &mut toks) {
        Some(n) => n,
        None => return reject(ProtoErr::WrongArgs, ReqCtx::default(), consumed, 0),
    };
    if n == 0 {
        return reject(ProtoErr::BadCommand, ReqCtx::default(), consumed, 0);
    }
    let toks = &toks[..n];
    let none = ReqCtx::default();
    match toks[0] {
        b"set" => storage(toks, consumed, v, Some(SetMode::Set), false),
        b"add" => storage(toks, consumed, v, Some(SetMode::Add), false),
        b"replace" => storage(toks, consumed, v, Some(SetMode::Replace), false),
        b"append" | b"prepend" => storage(toks, consumed, v, None, false),
        b"cas" => storage(toks, consumed, v, None, true),
        b"delete" => delete(toks, consumed),
        b"incr" | b"decr" | b"touch" | b"gat" | b"gats" | b"flush_all" | b"verbosity" => {
            let ctx = if toks[n - 1] == b"noreply" { ReqCtx { flags: QUIET, ..none } } else { none };
            reject(ProtoErr::Unsupported, ctx, consumed, 0)
        }
        b"version" => complete(Request::Control { ctl: Control::Version, ctx: none }, consumed),
        b"stats" => complete(Request::Control { ctl: Control::Stats, ctx: none }, consumed),
        b"quit" => {
            let ctx = ReqCtx { flags: CLOSE_AFTER, ..none };
            complete(Request::Control { ctl: Control::Quit, ctx }, consumed)
        }
        b"mn" => complete(Request::Noop { ctx: ReqCtx { flags: META, ..none } }, consumed),
        b"mg" => meta_get(toks, consumed),
        b"ms" => meta_set(toks, consumed, v),
        b"md" => meta_delete(toks, consumed),
        _ => reject(ProtoErr::BadCommand, none, consumed, 0),
    }
}

/// `set/add/replace/append/prepend <key> <flags> <exptime> <bytes> [noreply]`
/// and `cas <key> <flags> <exptime> <bytes> <cas> [noreply]`.
/// `mode == None` means a recognized but unsupported store (body is discarded).
fn storage(toks: &[&[u8]], consumed: usize, v: u64, mode: Option<SetMode>, is_cas: bool) -> Parsed {
    let base = if is_cas { 6 } else { 5 };
    let n = toks.len();
    let mut ctx = ReqCtx::default();
    if n == base + 1 {
        if toks[base] != b"noreply" {
            return reject(ProtoErr::WrongArgs, ctx, consumed, 0);
        }
        ctx.flags |= QUIET;
    } else if n != base {
        return reject(ProtoErr::WrongArgs, ctx, consumed, 0);
    }
    let Some(bytes) = parse_u64(toks[4]) else {
        return reject(ProtoErr::WrongArgs, ctx, consumed, 0);
    };
    if bytes > v + SLACK {
        return Parsed::Fatal { err: ProtoErr::BadLength };
    }
    let discard = bytes + 2;
    let Some((key, repr)) = parse_key(toks[1]) else {
        return reject(ProtoErr::BadKey, ctx, consumed, discard);
    };
    ctx.key = key;
    ctx.repr = repr;
    let Some(mode) = mode else {
        return reject(ProtoErr::Unsupported, ctx, consumed, discard);
    };
    match parse_u64(toks[2]) {
        Some(0) => {}
        Some(_) => return reject(ProtoErr::FlagsUnsupported, ctx, consumed, discard),
        None => return reject(ProtoErr::WrongArgs, ctx, consumed, discard),
    }
    if parse_i64(toks[3]).is_none() {
        return reject(ProtoErr::WrongArgs, ctx, consumed, discard);
    }
    if bytes != v {
        return reject(ProtoErr::BadLength, ctx, consumed, discard);
    }
    Parsed::Body {
        hdr: BodyHeader { mode, ctx, body_len: v as u32, expect_continue: false },
        consumed,
    }
}

/// `delete <key> [0] [noreply]`
fn delete(toks: &[&[u8]], consumed: usize) -> Parsed {
    let mut ctx = ReqCtx::default();
    if toks.len() < 2 || toks.len() > 4 {
        return reject(ProtoErr::WrongArgs, ctx, consumed, 0);
    }
    for &t in &toks[2..] {
        match t {
            b"noreply" => ctx.flags |= QUIET,
            b"0" => {}
            _ => return reject(ProtoErr::WrongArgs, ctx, consumed, 0),
        }
    }
    let Some((key, repr)) = parse_key(toks[1]) else {
        return reject(ProtoErr::BadKey, ctx, consumed, 0);
    };
    ctx.key = key;
    ctx.repr = repr;
    complete(Request::Delete { ctx }, consumed)
}

fn set_opaque(ctx: &mut ReqCtx, tok: &[u8]) -> bool {
    let o = &tok[1..];
    if o.len() > 32 {
        return false;
    }
    let mut op = Opaque { len: o.len() as u8, ..Default::default() };
    op.bytes[..o.len()].copy_from_slice(o);
    ctx.opaque = op;
    true
}

/// `mg <key> <flags>*`
fn meta_get(toks: &[&[u8]], consumed: usize) -> Parsed {
    let mut ctx = ReqCtx { flags: META, ..Default::default() };
    if toks.len() < 2 {
        return reject(ProtoErr::WrongArgs, ctx, consumed, 0);
    }
    let mut err = None;
    for &f in &toks[2..] {
        let single = f.len() == 1;
        match f[0] {
            b'v' if single => ctx.flags |= RETURN_VALUE,
            b'k' if single => ctx.flags |= RETURN_KEY,
            b's' if single => ctx.flags |= RETURN_SIZE,
            b'q' if single => ctx.flags |= QUIET,
            b'b' if single => {
                err.get_or_insert(ProtoErr::BadKey);
            }
            b'O' => {
                if !set_opaque(&mut ctx, f) {
                    err.get_or_insert(ProtoErr::WrongArgs);
                }
            }
            _ => {
                err.get_or_insert(ProtoErr::WrongArgs);
            }
        }
    }
    if let Some(e) = err {
        return reject(e, ctx, consumed, 0);
    }
    let Some((key, repr)) = parse_key(toks[1]) else {
        return reject(ProtoErr::BadKey, ctx, consumed, 0);
    };
    ctx.key = key;
    ctx.repr = repr;
    complete(Request::Get { ctx }, consumed)
}

/// `ms <key> <datalen> <flags>*`
fn meta_set(toks: &[&[u8]], consumed: usize, v: u64) -> Parsed {
    let mut ctx = ReqCtx { flags: META, ..Default::default() };
    if toks.len() < 3 {
        return reject(ProtoErr::WrongArgs, ctx, consumed, 0);
    }
    let Some(bytes) = parse_u64(toks[2]) else {
        return reject(ProtoErr::WrongArgs, ctx, consumed, 0);
    };
    if bytes > v + SLACK {
        return Parsed::Fatal { err: ProtoErr::BadLength };
    }
    let discard = bytes + 2;
    let mut mode = SetMode::Set;
    let mut err = None;
    for &f in &toks[3..] {
        let single = f.len() == 1;
        match f[0] {
            b'q' if single => ctx.flags |= QUIET,
            b'k' if single => ctx.flags |= RETURN_KEY,
            b'b' if single => {
                err.get_or_insert(ProtoErr::BadKey);
            }
            b'O' => {
                if !set_opaque(&mut ctx, f) {
                    err.get_or_insert(ProtoErr::WrongArgs);
                }
            }
            b'T' => {
                if parse_i64(&f[1..]).is_none() {
                    err.get_or_insert(ProtoErr::WrongArgs);
                }
            }
            b'F' => match parse_u64(&f[1..]) {
                Some(0) => {}
                Some(_) => {
                    err.get_or_insert(ProtoErr::FlagsUnsupported);
                }
                None => {
                    err.get_or_insert(ProtoErr::WrongArgs);
                }
            },
            b'M' if f.len() == 2 => match f[1] {
                b'S' | b's' => mode = SetMode::Set,
                b'E' | b'e' => mode = SetMode::Add,
                b'R' | b'r' => mode = SetMode::Replace,
                b'A' | b'a' | b'P' | b'p' => {
                    err.get_or_insert(ProtoErr::Unsupported);
                }
                _ => {
                    err.get_or_insert(ProtoErr::WrongArgs);
                }
            },
            b'C' | b'I' | b'N' => {
                err.get_or_insert(ProtoErr::Unsupported);
            }
            _ => {
                err.get_or_insert(ProtoErr::WrongArgs);
            }
        }
    }
    if let Some(e) = err {
        return reject(e, ctx, consumed, discard);
    }
    let Some((key, repr)) = parse_key(toks[1]) else {
        return reject(ProtoErr::BadKey, ctx, consumed, discard);
    };
    ctx.key = key;
    ctx.repr = repr;
    if bytes != v {
        return reject(ProtoErr::BadLength, ctx, consumed, discard);
    }
    Parsed::Body { hdr: BodyHeader { mode, ctx, body_len: v as u32, expect_continue: false }, consumed }
}

/// `md <key> <flags>*`
fn meta_delete(toks: &[&[u8]], consumed: usize) -> Parsed {
    let mut ctx = ReqCtx { flags: META, ..Default::default() };
    if toks.len() < 2 {
        return reject(ProtoErr::WrongArgs, ctx, consumed, 0);
    }
    let mut err = None;
    for &f in &toks[2..] {
        let single = f.len() == 1;
        match f[0] {
            b'q' if single => ctx.flags |= QUIET,
            b'k' if single => ctx.flags |= RETURN_KEY,
            b'b' if single => {
                err.get_or_insert(ProtoErr::BadKey);
            }
            b'O' => {
                if !set_opaque(&mut ctx, f) {
                    err.get_or_insert(ProtoErr::WrongArgs);
                }
            }
            b'C' | b'I' | b'T' | b'x' => {
                err.get_or_insert(ProtoErr::Unsupported);
            }
            _ => {
                err.get_or_insert(ProtoErr::WrongArgs);
            }
        }
    }
    if let Some(e) = err {
        return reject(e, ctx, consumed, 0);
    }
    let Some((key, repr)) = parse_key(toks[1]) else {
        return reject(ProtoErr::BadKey, ctx, consumed, 0);
    };
    ctx.key = key;
    ctx.repr = repr;
    complete(Request::Delete { ctx }, consumed)
}

/// The value must be followed by `\r\n` (a bare `\n` is tolerated).
pub fn finish_body(_st: &mut MemcacheState, _hdr: &mut BodyHeader, buf: &[u8]) -> Result<usize, FinishErr> {
    match buf {
        [b'\r', b'\n', ..] => Ok(2),
        [b'\n', ..] => Ok(1),
        [] | [b'\r'] => Err(FinishErr::Incomplete),
        _ => Err(FinishErr::Fatal { err: ProtoErr::BadLength }),
    }
}

/// Meta return flags (` k<key>`, ` O<opaque>`, ` s<V>`).
fn meta_flags(w: &mut HdrWriter<'_>, ctx: &ReqCtx, v: u32, size: bool) {
    if ctx.has(RETURN_KEY) {
        w.put(b" k");
        w.put_key(ctx);
    }
    if ctx.opaque.len > 0 {
        w.put(b" O");
        w.put(ctx.opaque.as_slice());
    }
    if size && ctx.has(RETURN_SIZE) {
        w.put(b" s");
        w.put_u64(v as u64);
    }
}

fn err_line(e: ProtoErr) -> &'static [u8] {
    match e {
        ProtoErr::BadCommand | ProtoErr::LengthRequired | ProtoErr::MethodNotAllowed => b"ERROR\r\n",
        ProtoErr::BadKey => b"CLIENT_ERROR bad key\r\n",
        ProtoErr::BadLength => b"CLIENT_ERROR bad data chunk\r\n",
        ProtoErr::FlagsUnsupported => b"CLIENT_ERROR client flags must be 0\r\n",
        ProtoErr::TtlUnsupported => b"CLIENT_ERROR ttl not supported\r\n",
        ProtoErr::Unsupported => b"SERVER_ERROR not supported\r\n",
        ProtoErr::TooLarge => b"CLIENT_ERROR line too long\r\n",
        ProtoErr::WrongArgs => b"CLIENT_ERROR bad command line format\r\n",
    }
}

pub fn encode(_st: &MemcacheState, ctx: &ReqCtx, r: &Response, value_len: u32, out: &mut [u8; HDR_CAP]) -> Frame {
    let meta = ctx.has(META);
    let quiet = ctx.has(QUIET);
    let mut w = HdrWriter::new(out);
    let mut value = false;
    let mut suppressed = false;
    match r {
        Response::Hit => {
            if meta {
                if ctx.has(RETURN_VALUE) {
                    w.put(b"VA ");
                    w.put_u64(value_len as u64);
                    value = true;
                } else {
                    w.put(b"HD");
                }
                meta_flags(&mut w, ctx, value_len, true);
                w.put(b"\r\n");
            } else {
                w.put(b"VALUE ");
                w.put_key(ctx);
                w.put(b" 0 ");
                w.put_u64(value_len as u64);
                if ctx.has(WITH_CAS) {
                    w.put(b" 0");
                }
                w.put(b"\r\n");
                value = true;
            }
        }
        Response::Miss => {
            if meta {
                w.put(b"EN\r\n");
                suppressed = quiet;
            } else {
                suppressed = true;
            }
        }
        Response::Stored | Response::NotStored | Response::Deleted | Response::NotFound => {
            if meta {
                let (code, hide): (&[u8], bool) = match r {
                    Response::Stored => (b"HD", quiet),
                    Response::NotStored => (b"NS", false),
                    Response::Deleted => (b"HD", quiet),
                    _ => (b"NF", quiet),
                };
                w.put(code);
                meta_flags(&mut w, ctx, value_len, false);
                w.put(b"\r\n");
                suppressed = hide;
            } else {
                w.put(match r {
                    Response::Stored => b"STORED\r\n",
                    Response::NotStored => b"NOT_STORED\r\n",
                    Response::Deleted => b"DELETED\r\n",
                    _ => b"NOT_FOUND\r\n",
                });
                suppressed = quiet;
            }
        }
        Response::MultiEnd => w.put(b"END\r\n"),
        Response::Noop => w.put(b"MN\r\n"),
        Response::Control(c) => match c {
            Control::Version => w.put(b"VERSION ssdcache-0.1\r\n"),
            Control::Stats => w.put(b"END\r\n"),
            Control::Quit => suppressed = true,
            _ => w.put(b"ERROR\r\n"),
        },
        Response::Count(_) | Response::Continue => w.put(b"SERVER_ERROR unexpected response\r\n"),
        Response::Proto(e) => {
            w.put(err_line(*e));
            suppressed = quiet && !meta;
        }
        Response::ServerErr => {
            w.put(b"SERVER_ERROR temporary failure\r\n");
            suppressed = quiet && !meta;
        }
    }
    let hdr_len = if suppressed { 0 } else { w.len as u16 };
    let value = value && !suppressed;
    Frame {
        hdr_len,
        value,
        trailer: if value { b"\r\n" } else { b"" },
        suppressed,
        close_after: ctx.has(CLOSE_AFTER),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::testutil::*;
    use crate::proto::{KeyRepr, ProtoKind, ProtoState};

    const V: u32 = 65536;
    const V2: u32 = 20000;
    const K1: &str = "00112233445566778899aabbccddeeff";
    const K2: &str = "ffeeddccbbaa99887766554433221100";
    const U1: &str = "123E4567-E89B-12D3-A456-426614174000";

    fn run(input: &[u8], v: u32) -> Vec<Ev> {
        drive_all(ProtoKind::Memcache, input, v)
    }
    fn mc() -> ProtoState {
        ProtoState::new(ProtoKind::Memcache)
    }
    fn render(ctx: &ReqCtx, r: Response) -> (String, Frame) {
        let (b, f) = enc(&mc(), ctx, r, V);
        (String::from_utf8(b).unwrap(), f)
    }
    fn with_body(line: &str, len: usize) -> Vec<u8> {
        let mut v = line.as_bytes().to_vec();
        v.extend(std::iter::repeat_n(b'z', len));
        v.extend_from_slice(b"\r\n");
        v
    }
    fn key_of(s: &str) -> [u8; 16] {
        parse_key(s.as_bytes()).unwrap().0
    }
    fn get(e: &Ev) -> ReqCtx {
        match e {
            Ev::Req(Request::Get { ctx }) => *ctx,
            e => panic!("expected Get, got {e:?}"),
        }
    }
    fn rej(e: &Ev) -> (ProtoErr, ReqCtx, u32) {
        match e {
            Ev::Reject { err, ctx, discard } => (*err, *ctx, *discard),
            e => panic!("expected Reject, got {e:?}"),
        }
    }
    fn body(e: &Ev) -> BodyHeader {
        match e {
            Ev::Body(h, Ok(_)) => *h,
            e => panic!("expected Body, got {e:?}"),
        }
    }

    #[test]
    fn get_single_emits_multi_end() {
        let evs = run(format!("get {K1}\r\n").as_bytes(), V);
        assert_eq!(evs.len(), 2);
        let ctx = get(&evs[0]);
        assert!(ctx.has(MULTI) && !ctx.has(WITH_CAS));
        assert_eq!(ctx.key, key_of(K1));
        assert_eq!(ctx.repr, KeyRepr::Hex32);
        assert!(matches!(evs[1], Ev::Req(Request::MultiEnd { .. })));

        let (s, f) = render(&ctx, Response::Hit);
        assert_eq!(s, format!("VALUE {K1} 0 65536\r\n"));
        assert!(f.value && f.trailer == b"\r\n" && !f.suppressed && !f.close_after);
        let (s, f) = render(&ctx, Response::Miss);
        assert!(s.is_empty() && f.suppressed && f.hdr_len == 0 && !f.value);
        let (s, f) = render(&ReqCtx::default(), Response::MultiEnd);
        assert_eq!(s, "END\r\n");
        assert!(!f.value);
    }

    #[test]
    fn gets_multi_keys_and_case() {
        let evs = run(format!("gets {K1}  {U1}\t{K2} \r\n").as_bytes(), V);
        assert_eq!(evs.len(), 4);
        let c: Vec<ReqCtx> = evs[..3].iter().map(get).collect();
        assert!(c.iter().all(|c| c.has(MULTI | WITH_CAS) && c.has(WITH_CAS)));
        assert_eq!(c[1].repr, KeyRepr::Uuid36 { upper: true });
        assert_eq!(c[2].key, key_of(K2));
        assert!(matches!(evs[3], Ev::Req(Request::MultiEnd { .. })));
        let (s, _) = render(&c[1], Response::Hit);
        assert_eq!(s, format!("VALUE {U1} 0 65536 0\r\n"));
    }

    #[test]
    fn multi_get_consumes_one_key_per_call() {
        let line = format!("get {K1} {K2}\r\n");
        let b = line.as_bytes();
        let mut st = MemcacheState::default();
        let Parsed::Complete { req: Request::Get { ctx }, consumed } = parse(&mut st, b, V) else { panic!() };
        assert_eq!(consumed, 4 + 32);
        assert_eq!(ctx.key, key_of(K1));
        assert!(st.multi.is_some());
        let b = &b[consumed..];
        // A prefix of the next key: Incomplete, nothing consumed, state unchanged.
        assert!(matches!(parse(&mut st, &b[..10], V), Parsed::Incomplete { .. }));
        let Parsed::Complete { req: Request::Get { ctx }, consumed } = parse(&mut st, b, V) else { panic!() };
        assert_eq!(consumed, 33);
        assert_eq!(ctx.key, key_of(K2));
        let b = &b[consumed..];
        assert_eq!(b, b"\r\n");
        assert!(matches!(parse(&mut st, &b[..1], V), Parsed::Incomplete { .. }));
        let Parsed::Complete { req: Request::MultiEnd { .. }, consumed: 2 } = parse(&mut st, b, V) else { panic!() };
        assert!(st.multi.is_none());
    }

    #[test]
    fn raw16_key_in_get() {
        let mut input = b"get ".to_vec();
        input.extend_from_slice(b"0123456789abcdef");
        input.extend_from_slice(b"\r\n");
        let evs = run(&input, V);
        let ctx = get(&evs[0]);
        assert_eq!(ctx.repr, KeyRepr::Raw16);
        assert_eq!(&ctx.key, b"0123456789abcdef");
        let (s, _) = render(&ctx, Response::Hit);
        assert_eq!(s, "VALUE 0123456789abcdef 0 65536\r\n");
    }

    #[test]
    fn bad_key_in_multi_get_rejects_rest_of_line() {
        let evs = run(format!("get {K1} nope {K2}\r\nversion\r\n").as_bytes(), V);
        assert_eq!(evs.len(), 3, "{evs:?}");
        get(&evs[0]);
        let (err, ctx, d) = rej(&evs[1]);
        assert_eq!((err, d), (ProtoErr::BadKey, 0));
        assert_eq!(render(&ctx, Response::Proto(err)).0, "CLIENT_ERROR bad key\r\n");
        assert!(matches!(evs[2], Ev::Req(Request::Control { ctl: Control::Version, .. })));
        // First key bad, too-long tokens, stray CR.
        let evs = run(format!("get {K1}x {K2}\r\nmn\r\n").as_bytes(), V);
        assert_eq!(rej(&evs[0]).0, ProtoErr::BadKey);
        assert!(matches!(evs[1], Ev::Req(Request::Noop { .. })));
        let evs = run(format!("get {K1}\rx\r\nmn\r\n").as_bytes(), V);
        get(&evs[0]);
        assert_eq!(rej(&evs[1]).0, ProtoErr::BadKey);
        assert!(matches!(evs[2], Ev::Req(Request::Noop { .. })));
    }

    #[test]
    fn bad_key_long_line_is_skipped_across_calls() {
        let mut line = format!("get {K1} bad");
        for _ in 0..200 {
            line.push_str(&format!(" {K2}"));
        }
        line.push_str("\r\nmn\r\n");
        let b = line.as_bytes();
        let mut st = MemcacheState::default();
        let Parsed::Complete { consumed, .. } = parse(&mut st, &b[..100], V) else { panic!() };
        let rest = &b[consumed..];
        let Parsed::Reject { err: ProtoErr::BadKey, ctx, consumed, .. } = parse(&mut st, &rest[..300], V) else { panic!() };
        assert_eq!(consumed, 300);
        assert!(!ctx.has(QUIET));
        let rest = &rest[300..];
        let Parsed::Reject { ctx, consumed, .. } = parse(&mut st, &rest[..500], V) else { panic!() };
        assert!(ctx.has(QUIET) && consumed == 500);
        assert!(render(&ctx, Response::Proto(ProtoErr::BadKey)).1.suppressed);
        let rest = &rest[500..];
        let Parsed::Reject { ctx, consumed, .. } = parse(&mut st, rest, V) else { panic!() };
        assert!(ctx.has(QUIET));
        assert_eq!(&rest[consumed..], b"mn\r\n");
        assert!(st.multi.is_none());
        // And the driver agrees at every split.
        let evs = run(b, V);
        assert_eq!(evs.len(), 3);
    }

    #[test]
    fn get_without_keys_is_error() {
        let evs = run(b"get\r\nget  \r\n", V);
        assert_eq!(evs.len(), 2);
        let (err, ctx, _) = rej(&evs[0]);
        assert_eq!(err, ProtoErr::BadCommand);
        assert_eq!(render(&ctx, Response::Proto(err)).0, "ERROR\r\n");
    }

    #[test]
    fn set_add_replace() {
        for (cmd, mode) in [("set", SetMode::Set), ("add", SetMode::Add), ("replace", SetMode::Replace)] {
            for v in [V, V2] {
                let input = with_body(&format!("{cmd} {K1} 0 3600 {v}\r\n"), v as usize);
                let evs = run(&input, v);
                assert_eq!(evs.len(), 1);
                let h = body(&evs[0]);
                assert_eq!(h.mode, mode);
                assert_eq!(h.body_len, v);
                assert_eq!(h.ctx.key, key_of(K1));
                assert!(!h.ctx.has(QUIET));
                assert!(matches!(evs[0], Ev::Body(_, Ok(2))));
            }
        }
        let h = body(&run(&with_body(&format!("set {K1} 0 -1 {V}\r\n"), V as usize), V)[0]);
        assert_eq!(render(&h.ctx, Response::Stored).0, "STORED\r\n");
        assert_eq!(render(&h.ctx, Response::NotStored).0, "NOT_STORED\r\n");
        assert_eq!(render(&h.ctx, Response::ServerErr).0, "SERVER_ERROR temporary failure\r\n");
    }

    #[test]
    fn noreply_suppresses_success_and_failure() {
        let h = body(&run(&with_body(&format!("set {K1} 0 0 {V} noreply\r\n"), V as usize), V)[0]);
        assert!(h.ctx.has(QUIET));
        for r in [Response::Stored, Response::NotStored, Response::ServerErr, Response::Proto(ProtoErr::BadLength)] {
            let (s, f) = render(&h.ctx, r);
            assert!(f.suppressed && s.is_empty(), "{r:?}");
        }
        let evs = run(format!("delete {K1} noreply\r\n").as_bytes(), V);
        let Ev::Req(Request::Delete { ctx }) = evs[0] else { panic!() };
        assert!(render(&ctx, Response::Deleted).1.suppressed);
        assert!(render(&ctx, Response::NotFound).1.suppressed);
        // Rejected noreply store: error suppressed too.
        let evs = run(&with_body(&format!("set {K1} 0 0 5 noreply\r\n"), 5), V);
        let (err, ctx, d) = rej(&evs[0]);
        assert_eq!((err, d), (ProtoErr::BadLength, 7));
        assert!(render(&ctx, Response::Proto(err)).1.suppressed);
        let evs = run(b"incr x 1 noreply\r\n", V);
        let (err, ctx, _) = rej(&evs[0]);
        assert_eq!(err, ProtoErr::Unsupported);
        assert!(render(&ctx, Response::Proto(err)).1.suppressed);
    }

    #[test]
    fn set_wrong_length_discards_body() {
        let mut input = with_body(&format!("set {K1} 0 0 5\r\n"), 5);
        input.extend_from_slice(b"version\r\n");
        let evs = run(&input, V);
        assert_eq!(evs.len(), 2);
        let (err, ctx, d) = rej(&evs[0]);
        assert_eq!((err, d), (ProtoErr::BadLength, 7));
        assert_eq!(render(&ctx, Response::Proto(err)).0, "CLIENT_ERROR bad data chunk\r\n");
        assert!(matches!(evs[1], Ev::Req(Request::Control { ctl: Control::Version, .. })));
        // V + 64 is still drained; V + 65 is fatal.
        let evs = run(&with_body(&format!("set {K1} 0 0 {}\r\n", V + 64), (V + 64) as usize), V);
        assert_eq!(rej(&evs[0]).2, V + 66);
        let evs = run(format!("set {K1} 0 0 {}\r\n", V + 65).as_bytes(), V);
        assert!(matches!(evs[0], Ev::Fatal(ProtoErr::BadLength)));
        let evs = run(format!("set {K1} 0 0 99999999999999999999\r\n").as_bytes(), V);
        assert!(matches!(evs[0], Ev::Reject { err: ProtoErr::WrongArgs, .. }));
    }

    #[test]
    fn set_flags_key_and_syntax_errors() {
        let mut input = with_body(&format!("set {K1} 5 0 {V2}\r\n"), V2 as usize);
        input.extend(with_body("set short 0 0 20000\r\n", V2 as usize));
        input.extend(with_body(&format!("set {K1} 0 abc {V2}\r\n"), V2 as usize));
        input.extend_from_slice(format!("set {K1} 0 0\r\n").as_bytes());
        input.extend(with_body(&format!("set {K1} 0 0 {V2} junk\r\n"), 0));
        input.extend_from_slice(b"mn\r\n");
        let evs = run(&input, V2);
        let e: Vec<_> = evs.iter().take(5).map(|e| (rej(e).0, rej(e).2)).collect();
        assert_eq!(
            e,
            vec![
                (ProtoErr::FlagsUnsupported, V2 + 2),
                (ProtoErr::BadKey, V2 + 2),
                (ProtoErr::WrongArgs, V2 + 2),
                (ProtoErr::WrongArgs, 0),
                (ProtoErr::WrongArgs, 0),
            ]
        );
        assert_eq!(render(&ReqCtx::default(), Response::Proto(ProtoErr::FlagsUnsupported)).0, "CLIENT_ERROR client flags must be 0\r\n");
        // "junk" line: the 2 trailing bytes `\r\n` parse as an empty line → ERROR, then mn.
        assert!(matches!(evs[5], Ev::Reject { err: ProtoErr::BadCommand, .. }));
        assert!(matches!(evs[6], Ev::Req(Request::Noop { .. })));
    }

    #[test]
    fn bad_trailer_is_fatal() {
        let mut input = format!("set {K1} 0 0 {V2}\r\n").into_bytes();
        input.extend(std::iter::repeat_n(b'z', V2 as usize));
        input.extend_from_slice(b"XX");
        let evs = run(&input, V2);
        assert!(matches!(evs[0], Ev::Body(_, Err(FinishErr::Fatal { .. }))));
        let mut st = MemcacheState::default();
        let mut h = BodyHeader { mode: SetMode::Set, ctx: ReqCtx::default(), body_len: 1, expect_continue: false };
        assert_eq!(finish_body(&mut st, &mut h, b""), Err(FinishErr::Incomplete));
        assert_eq!(finish_body(&mut st, &mut h, b"\r"), Err(FinishErr::Incomplete));
        assert_eq!(finish_body(&mut st, &mut h, b"\r\nget"), Ok(2));
        assert_eq!(finish_body(&mut st, &mut h, b"\nget"), Ok(1));
    }

    #[test]
    fn delete_and_misc_commands() {
        let input = format!("delete {K1}\r\ndelete {K1} 0\r\ndelete\r\ndelete bad\r\nversion\r\nstats\r\nstats items\r\nquit\r\n");
        let evs = run(input.as_bytes(), V);
        let Ev::Req(Request::Delete { ctx }) = evs[0] else { panic!() };
        assert_eq!(render(&ctx, Response::Deleted).0, "DELETED\r\n");
        assert_eq!(render(&ctx, Response::NotFound).0, "NOT_FOUND\r\n");
        assert!(matches!(evs[1], Ev::Req(Request::Delete { .. })));
        assert_eq!(rej(&evs[2]).0, ProtoErr::WrongArgs);
        assert_eq!(rej(&evs[3]).0, ProtoErr::BadKey);
        let Ev::Req(Request::Control { ctl: Control::Version, ctx }) = evs[4] else { panic!() };
        assert_eq!(render(&ctx, Response::Control(Control::Version)).0, "VERSION ssdcache-0.1\r\n");
        let Ev::Req(Request::Control { ctl: Control::Stats, ctx }) = evs[5] else { panic!() };
        assert_eq!(render(&ctx, Response::Control(Control::Stats)).0, "END\r\n");
        assert!(matches!(evs[6], Ev::Req(Request::Control { ctl: Control::Stats, .. })));
        let Ev::Req(Request::Control { ctl: Control::Quit, ctx }) = evs[7] else { panic!() };
        assert!(ctx.has(CLOSE_AFTER));
        let (s, f) = render(&ctx, Response::Control(Control::Quit));
        assert!(s.is_empty() && f.suppressed && f.close_after);
    }

    #[test]
    fn unsupported_and_unknown() {
        let mut input = with_body(&format!("cas {K1} 0 0 {V2} 123\r\n"), V2 as usize);
        input.extend(with_body(&format!("append {K1} 0 0 4\r\n"), 4));
        input.extend(with_body(&format!("prepend {K1} 0 0 4 noreply\r\n"), 4));
        input.extend_from_slice(b"incr k 1\r\ndecr k 1\r\ntouch k 0\r\nflush_all\r\nbogus a b\r\nGET x\r\n\r\n");
        let evs = run(&input, V2);
        let got: Vec<_> = evs.iter().map(|e| (rej(e).0, rej(e).2)).collect();
        use ProtoErr::*;
        assert_eq!(
            got,
            vec![
                (Unsupported, V2 + 2),
                (Unsupported, 6),
                (Unsupported, 6),
                (Unsupported, 0),
                (Unsupported, 0),
                (Unsupported, 0),
                (Unsupported, 0),
                (BadCommand, 0),
                (BadCommand, 0),
                (BadCommand, 0),
            ]
        );
        assert_eq!(render(&ReqCtx::default(), Response::Proto(Unsupported)).0, "SERVER_ERROR not supported\r\n");
        assert_eq!(render(&ReqCtx::default(), Response::Proto(BadCommand)).0, "ERROR\r\n");
        assert_eq!(render(&ReqCtx::default(), Response::Proto(WrongArgs)).0, "CLIENT_ERROR bad command line format\r\n");
    }

    #[test]
    fn meta_get() {
        let evs = run(format!("mg {U1} v k s Oabc q\r\nmg {K1}\r\nmg {K1} s\r\n").as_bytes(), V);
        let c = get(&evs[0]);
        assert!(c.has(META | RETURN_VALUE) && c.has(RETURN_KEY) && c.has(RETURN_SIZE) && c.has(QUIET));
        assert!(!c.has(MULTI));
        assert_eq!(c.opaque.as_slice(), b"abc");
        let (s, f) = render(&c, Response::Hit);
        assert_eq!(s, format!("VA 65536 k{U1} Oabc s65536\r\n"));
        assert!(f.value && f.trailer == b"\r\n" && !f.suppressed);
        let (s, f) = render(&c, Response::Miss);
        assert!(f.suppressed && s.is_empty()); // q hides EN
        assert_eq!(render(&c, Response::ServerErr).0, "SERVER_ERROR temporary failure\r\n");
        assert!(!render(&c, Response::Proto(ProtoErr::BadKey)).1.suppressed);

        let c = get(&evs[1]);
        let (s, f) = render(&c, Response::Hit);
        assert_eq!(s, "HD\r\n");
        assert!(!f.value && f.trailer.is_empty());
        assert_eq!(render(&c, Response::Miss).0, "EN\r\n");
        assert_eq!(render(&get(&evs[2]), Response::Hit).0, "HD s65536\r\n");
    }

    #[test]
    fn meta_get_errors() {
        let o33 = "O".to_string() + &"x".repeat(33);
        let o32 = "O".to_string() + &"x".repeat(32);
        let input = format!("mg {K1} b\r\nmg {K1} z\r\nmg {K1} vv\r\nmg {K1} {o33}\r\nmg {K1} {o32}\r\nmg\r\nmg nope v\r\n");
        let evs = run(input.as_bytes(), V);
        use ProtoErr::*;
        assert_eq!(rej(&evs[0]).0, BadKey);
        assert_eq!(rej(&evs[1]).0, WrongArgs);
        assert_eq!(rej(&evs[2]).0, WrongArgs);
        assert_eq!(rej(&evs[3]).0, WrongArgs);
        assert_eq!(get(&evs[4]).opaque.len, 32);
        assert_eq!(rej(&evs[5]).0, WrongArgs);
        assert_eq!(rej(&evs[6]).0, BadKey);
        assert_eq!(render(&rej(&evs[6]).1, Response::Proto(BadKey)).0, "CLIENT_ERROR bad key\r\n");
    }

    #[test]
    fn meta_set() {
        let mut input = with_body(&format!("ms {K1} {V} T0 F0 MS q k O7\r\n"), V as usize);
        input.extend(with_body(&format!("ms {K1} {V} ME\r\n"), V as usize));
        input.extend(with_body(&format!("ms {K1} {V} Mr\r\n"), V as usize));
        input.extend(with_body(&format!("ms {K1} {V} MA\r\n"), V as usize));
        input.extend(with_body(&format!("ms {K1} {V} F3\r\n"), V as usize));
        input.extend(with_body(&format!("ms {K1} 10\r\n"), 10));
        input.extend(with_body(&format!("ms {K1} {V} b\r\n"), V as usize));
        input.extend(with_body(&format!("ms {K1} {V} C5\r\n"), V as usize));
        input.extend_from_slice(b"mn\r\n");
        let evs = run(&input, V);
        let h = body(&evs[0]);
        assert_eq!(h.mode, SetMode::Set);
        assert!(h.ctx.has(META | QUIET) && h.ctx.has(RETURN_KEY));
        let (s, f) = render(&h.ctx, Response::Stored);
        assert!(f.suppressed && s.is_empty());
        let (s, f) = render(&h.ctx, Response::NotStored);
        assert!(!f.suppressed);
        assert_eq!(s, format!("NS k{K1} O7\r\n"));
        assert_eq!(body(&evs[1]).mode, SetMode::Add);
        assert_eq!(body(&evs[2]).mode, SetMode::Replace);
        assert_eq!(render(&body(&evs[2]).ctx, Response::Stored).0, "HD\r\n");
        use ProtoErr::*;
        assert_eq!((rej(&evs[3]).0, rej(&evs[3]).2), (Unsupported, V + 2));
        assert_eq!(rej(&evs[4]).0, FlagsUnsupported);
        assert_eq!((rej(&evs[5]).0, rej(&evs[5]).2), (BadLength, 12));
        assert_eq!(rej(&evs[6]).0, BadKey);
        assert_eq!(rej(&evs[7]).0, Unsupported);
        assert!(matches!(evs[8], Ev::Req(Request::Noop { .. })));
        assert!(matches!(run(format!("ms {K1} {}\r\n", V + 65).as_bytes(), V)[0], Ev::Fatal(BadLength)));
    }

    #[test]
    fn meta_delete_and_noop() {
        let evs = run(format!("md {K1} q Oab\r\nmd {K1} k\r\nmn\r\nmd {K1} x\r\n").as_bytes(), V);
        let Ev::Req(Request::Delete { ctx }) = evs[0] else { panic!() };
        assert!(render(&ctx, Response::Deleted).1.suppressed);
        assert!(render(&ctx, Response::NotFound).1.suppressed);
        let Ev::Req(Request::Delete { ctx }) = evs[1] else { panic!() };
        assert_eq!(render(&ctx, Response::Deleted).0, format!("HD k{K1}\r\n"));
        assert_eq!(render(&ctx, Response::NotFound).0, format!("NF k{K1}\r\n"));
        let Ev::Req(Request::Noop { ctx }) = evs[2] else { panic!() };
        assert_eq!(render(&ctx, Response::Noop).0, "MN\r\n");
        assert_eq!(rej(&evs[3]).0, ProtoErr::Unsupported);
    }

    #[test]
    fn pipelined_mix() {
        let mut input = format!("get {K1} {K2}\r\n").into_bytes();
        input.extend(with_body(&format!("set {K2} 0 0 {V2}\r\n"), V2 as usize));
        input.extend_from_slice(format!("mg {K1} v\r\ndelete {K1}\r\nmn\r\ngets {U1}\r\n").as_bytes());
        input.extend(with_body(&format!("ms {K1} {V2}\r\n"), V2 as usize));
        input.extend_from_slice(b"quit\r\n");
        let evs = run(&input, V2);
        let kinds: Vec<&str> = evs
            .iter()
            .map(|e| match e {
                Ev::Req(Request::Get { .. }) => "get",
                Ev::Req(Request::MultiEnd { .. }) => "end",
                Ev::Req(Request::Delete { .. }) => "del",
                Ev::Req(Request::Noop { .. }) => "mn",
                Ev::Req(Request::Control { .. }) => "ctl",
                Ev::Body(..) => "body",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, ["get", "get", "end", "body", "get", "del", "mn", "get", "end", "body", "ctl"]);
    }

    #[test]
    fn line_too_long_is_fatal() {
        let input = vec![b'a'; MAX_HEADER + 10];
        assert!(matches!(run(&input, V)[0], Ev::Fatal(ProtoErr::TooLarge)));
        // A get line longer than MAX_HEADER is fine: it is consumed key by key.
        let mut line = "get".to_string();
        for _ in 0..200 {
            line.push_str(&format!(" {K1}"));
        }
        line.push_str("\r\n");
        let evs = run(line.as_bytes(), V);
        assert_eq!(evs.len(), 201);
    }

    #[test]
    fn header_fits_worst_case() {
        let (k, r) = parse_key(U1.as_bytes()).unwrap();
        let mut ctx = ReqCtx { flags: META | RETURN_VALUE | RETURN_KEY | RETURN_SIZE, key: k, repr: r, ..Default::default() };
        ctx.opaque = Opaque { len: 32, bytes: [b'o'; 32] };
        for v in [u32::MAX, V, V2] {
            let st = mc();
            for resp in ALL_RESPONSES {
                let (b, _) = enc(&st, &ctx, resp, v);
                assert!(b.len() < HDR_CAP && (b.is_empty() || b.ends_with(b"\r\n")), "{resp:?}");
            }
            let (b, _) = enc(&st, &ctx, Response::Hit, v);
            assert_eq!(b.len(), format!("VA {v} k{U1} O{} s{v}\r\n", "o".repeat(32)).len());
            let tctx = ReqCtx { flags: MULTI | WITH_CAS, key: k, repr: r, ..Default::default() };
            let (b, _) = enc(&st, &tctx, Response::Hit, v);
            assert_eq!(b, format!("VALUE {U1} 0 {v} 0\r\n").as_bytes());
            for e in ALL_ERRS {
                assert!(enc(&st, &ReqCtx::default(), Response::Proto(e), v).0.ends_with(b"\r\n"));
            }
        }
    }

    #[test]
    fn fuzz_no_panic() {
        let k1 = format!("get {K1} {K2}\r\n");
        let k2 = format!("set {K1} 0 0 {V2}\r\n");
        let k3 = format!("ms {K1} {V2} q k O1 MR\r\n");
        let k4 = format!("mg {U1} v k s Oxyz\r\n");
        let k5 = format!("get {K1} bad {K1}\r\n");
        let k6 = format!("set {K1} 0 0 5\r\nhello\r\n");
        let pieces: Vec<&[u8]> = vec![
            k1.as_bytes(),
            k2.as_bytes(),
            k3.as_bytes(),
            k4.as_bytes(),
            k5.as_bytes(),
            k6.as_bytes(),
            b"\r\n",
            b" ",
            b"get ",
            b"gets",
            b"delete ",
            b"md ",
            b"mn\r\n",
            b"version\r\n",
            b"quit\r\n",
            b"cas a 0 0 5 1\r\n",
            K1.as_bytes(),
        ];
        fuzz(ProtoKind::Memcache, &pieces, V2, 3000, 0x9e3779b97f4a7c15);
        fuzz(ProtoKind::Memcache, &pieces, 64, 3000, 12345);
    }
}
