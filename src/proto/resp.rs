//! RESP2 / RESP3 (design §7.2): arrays of bulk strings and inline commands.
//!
//! Multi-key commands are emitted one key per call:
//! * `MGET k…` → one `Get` per key with `MULTI | ARRAY_ELEM`; the first carries
//!   `array_prefix = n`. No end marker.
//! * `DEL k…` / `EXISTS k…` → one `Delete` / `Get(EXISTS)` per key with `MULTI`,
//!   then `AggEnd`. So that `AggEnd` is never left waiting on an empty buffer, the
//!   last key of an array leaves its trailing `\r\n` unconsumed and `AggEnd` consumes
//!   it (inline: `AggEnd` consumes the line end).
//!
//! Bad keys inside a multi-key command (keys are 16 raw bytes / 32 hex / 36 UUID):
//! * MGET: `Reject{BadKey}` whose ctx has `ARRAY_ELEM` (and the array prefix if it is
//!   the first element). It renders as an error *element* (`-ERR invalid key`), so the
//!   reply array stays well-formed and the client sees exactly which key was bad.
//! * DEL / EXISTS: `Reject{BadKey}` whose ctx has `MULTI` (no `ARRAY_ELEM`). It is
//!   suppressed and counts as 0, like a key that does not exist in Redis.
//!
//! Rejected commands with arguments still pending (wrong args, unknown command,
//! `SET` with a bad key or length) leave a skip cursor; the remaining array
//! elements are dropped on later calls with `Reject` + `flags::QUIET` (no reply;
//! large elements are dropped via `discard_body`). Inline `SET` is not supported
//! (the value is V bytes, larger than an inline line).

use super::flags::*;
use super::{
    AggKind, BodyHeader, Control, FinishErr, Frame, HDR_CAP, HdrWriter, Parsed, ProtoErr, ReqCtx,
    Request, RespState, Response, SetMode, parse_key,
};

/// Longest header (inline line / array + command + key headers) we buffer.
pub const MAX_HEADER: usize = 2048;

const SLACK: u64 = 64;
const MAX_KEY_LEN: usize = 36;
const MAX_ARRAY: i64 = 1024 * 1024;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum Kind {
    #[default]
    MGet,
    Del,
    Exists,
    /// After `SET`'s `Body`: `remaining` option elements follow the value.
    SetTail,
    /// Dropping `remaining` elements of a rejected / finished command.
    Skip,
}

/// Resumable cursor for MGET / DEL / EXISTS, SET options, and skipping.
#[derive(Copy, Clone, Debug, Default)]
pub struct MultiCursor {
    kind: Kind,
    remaining: u32,
    total: u32,
    first: bool,
    inline: bool,
}

// ---------------------------------------------------------------------------
// Low-level element parsing.

enum Num {
    Ok(i64, usize),
    Incomplete,
    Bad,
}

/// Parse `[-]digits\r\n` starting at `p`. Returns the value and the index after `\n`.
fn num_line(buf: &[u8], mut p: usize) -> Num {
    let mut neg = false;
    if p < buf.len() && buf[p] == b'-' {
        neg = true;
        p += 1;
    }
    let mut v: i64 = 0;
    let mut digits = 0;
    loop {
        let Some(&c) = buf.get(p) else { return Num::Incomplete };
        if c.is_ascii_digit() {
            if digits >= 12 {
                return Num::Bad;
            }
            v = v * 10 + (c - b'0') as i64;
            digits += 1;
            p += 1;
        } else if c == b'\r' {
            if digits == 0 {
                return Num::Bad;
            }
            let Some(&lf) = buf.get(p + 1) else { return Num::Incomplete };
            if lf != b'\n' {
                return Num::Bad;
            }
            return Num::Ok(if neg { -v } else { v }, p + 2);
        } else {
            return Num::Bad;
        }
    }
}

enum Bulk {
    /// `buf[start..end]` is the data; `next` is past its `\r\n`.
    Full { start: usize, end: usize, next: usize },
    /// Header parsed (`data` is where the data starts) but data not fully buffered.
    Partial { len: u64, data: usize },
    Incomplete,
    Bad,
}

fn bulk(buf: &[u8], p: usize) -> Bulk {
    let Some(&c) = buf.get(p) else { return Bulk::Incomplete };
    if c != b'$' {
        return Bulk::Bad;
    }
    let (len, data) = match num_line(buf, p + 1) {
        Num::Ok(l, e) if l >= 0 => (l as u64, e),
        Num::Ok(..) | Num::Bad => return Bulk::Bad,
        Num::Incomplete => return Bulk::Incomplete,
    };
    let end = data as u64 + len;
    if end + 2 > buf.len() as u64 {
        return Bulk::Partial { len, data };
    }
    let end = end as usize;
    if &buf[end..end + 2] != b"\r\n" {
        return Bulk::Bad;
    }
    Bulk::Full { start: data, end, next: end + 2 }
}

enum KeyElem {
    Ok { ctx_key: ([u8; 16], super::KeyRepr), next: usize },
    /// Fully buffered but not a valid key.
    BadSmall { next: usize },
    /// Too long to be a key; header ends at `data`, `len` data bytes follow.
    BadBig { data: usize, len: u64 },
    Incomplete,
    Bad,
}

fn key_elem(buf: &[u8], p: usize) -> KeyElem {
    match bulk(buf, p) {
        Bulk::Full { start, end, next } => match parse_key(&buf[start..end]) {
            Some(k) => KeyElem::Ok { ctx_key: k, next },
            None => KeyElem::BadSmall { next },
        },
        Bulk::Partial { len, data } if len as usize > MAX_KEY_LEN => KeyElem::BadBig { data, len },
        Bulk::Partial { .. } | Bulk::Incomplete => KeyElem::Incomplete,
        Bulk::Bad => KeyElem::Bad,
    }
}

enum SkipStop {
    Done,
    Incomplete,
    Partial { len: u64, data: usize },
    Bad,
}

/// Skip up to `count` fully buffered elements from `p`. Returns (pos, skipped, why stopped).
fn skip_elems(buf: &[u8], mut p: usize, count: u32) -> (usize, u32, SkipStop) {
    let mut skipped = 0;
    while skipped < count {
        match bulk(buf, p) {
            Bulk::Full { next, .. } => {
                p = next;
                skipped += 1;
            }
            Bulk::Partial { len, data } => return (p, skipped, SkipStop::Partial { len, data }),
            Bulk::Incomplete => return (p, skipped, SkipStop::Incomplete),
            Bulk::Bad => return (p, skipped, SkipStop::Bad),
        }
    }
    (p, skipped, SkipStop::Done)
}

fn skip_cursor(remaining: u32) -> Option<MultiCursor> {
    (remaining > 0).then_some(MultiCursor { kind: Kind::Skip, remaining, ..Default::default() })
}

fn incomplete(buf: &[u8]) -> Parsed {
    if buf.len() >= MAX_HEADER {
        Parsed::Fatal { err: ProtoErr::TooLarge }
    } else {
        Parsed::Incomplete { min_more: 1 }
    }
}

fn fatal(err: ProtoErr) -> Parsed {
    Parsed::Fatal { err }
}

fn quiet() -> ReqCtx {
    ReqCtx { flags: QUIET, ..Default::default() }
}

/// Finish a command at `p` with `remaining` array elements still to drop. The
/// elements that are fully buffered are consumed now; the rest go to a skip cursor.
/// With `allow_discard`, a partially buffered element is dropped via `discard_body`.
/// Returns (consumed, discard) or a fatal error.
fn tail(st: &mut RespState, buf: &[u8], p: usize, remaining: u32, v: u64, allow_discard: bool) -> Result<(usize, u32), Parsed> {
    let (p, skipped, stop) = skip_elems(buf, p, remaining);
    let rem = remaining - skipped;
    match stop {
        SkipStop::Done => {
            st.multi = None;
            Ok((p, 0))
        }
        SkipStop::Bad => Err(fatal(ProtoErr::BadCommand)),
        SkipStop::Partial { len, data } if allow_discard => {
            if len > v + SLACK {
                return Err(fatal(ProtoErr::TooLarge));
            }
            st.multi = skip_cursor(rem - 1);
            Ok((data, (len + 2) as u32))
        }
        SkipStop::Partial { .. } | SkipStop::Incomplete => {
            st.multi = skip_cursor(rem);
            Ok((p, 0))
        }
    }
}

fn reject_tail(st: &mut RespState, buf: &[u8], p: usize, remaining: u32, v: u64, err: ProtoErr, ctx: ReqCtx) -> Parsed {
    match tail(st, buf, p, remaining, v, true) {
        Ok((consumed, discard_body)) => Parsed::Reject { err, ctx, consumed, discard_body },
        Err(f) => f,
    }
}

fn complete_tail(st: &mut RespState, buf: &[u8], p: usize, remaining: u32, v: u64, req: Request) -> Parsed {
    match tail(st, buf, p, remaining, v, false) {
        Ok((consumed, _)) => Parsed::Complete { req, consumed },
        Err(f) => f,
    }
}

fn ctl(ctl: Control) -> Request {
    let flags = if ctl == Control::Quit { CLOSE_AFTER } else { 0 };
    Request::Control { ctl, ctx: ReqCtx { flags, ..Default::default() } }
}

// ---------------------------------------------------------------------------
// Parser.

pub fn parse(st: &mut RespState, buf: &[u8], value_len: u32) -> Parsed {
    let v = value_len as u64;
    if let Some(c) = st.multi {
        match c.kind {
            // finish_body was never called; drop the stale state.
            Kind::SetTail => st.multi = None,
            Kind::Skip => return skip_cont(st, c, buf, v),
            _ if c.inline => return inline_multi_next(st, c, buf, 0),
            _ => return array_multi_next(st, c, buf, 0, v),
        }
    }
    match buf.first() {
        None => Parsed::Incomplete { min_more: 1 },
        Some(b'*') => array(st, buf, v),
        Some(_) => inline(st, buf),
    }
}

/// Drop elements of a rejected/finished command (no reply: `Reject` + QUIET).
fn skip_cont(st: &mut RespState, c: MultiCursor, buf: &[u8], v: u64) -> Parsed {
    let (p, skipped, stop) = skip_elems(buf, 0, c.remaining);
    let rem = c.remaining - skipped;
    let (consumed, discard, rem) = match stop {
        SkipStop::Done => (p, 0, 0),
        SkipStop::Bad => return fatal(ProtoErr::BadCommand),
        SkipStop::Partial { len, data } => {
            if len > v + SLACK {
                return fatal(ProtoErr::TooLarge);
            }
            (data, (len + 2) as u32, rem - 1)
        }
        SkipStop::Incomplete => {
            if p == 0 {
                return incomplete(buf);
            }
            (p, 0, rem)
        }
    };
    st.multi = skip_cursor(rem);
    Parsed::Reject { err: ProtoErr::BadCommand, ctx: quiet(), consumed, discard_body: discard }
}

fn array(st: &mut RespState, buf: &[u8], v: u64) -> Parsed {
    let (n, mut p) = match num_line(buf, 1) {
        Num::Ok(n, e) => (n, e),
        Num::Incomplete => return incomplete(buf),
        Num::Bad => return fatal(ProtoErr::BadCommand),
    };
    if n == 0 || n == -1 {
        // Empty / null array: ignored (as Redis does), no reply.
        return Parsed::Reject { err: ProtoErr::BadCommand, ctx: quiet(), consumed: p, discard_body: 0 };
    }
    if !(1..=MAX_ARRAY).contains(&n) {
        return fatal(ProtoErr::TooLarge);
    }
    let args = (n - 1) as u32;
    let none = ReqCtx::default();
    // Command name.
    let (ns, ne) = match bulk(buf, p) {
        Bulk::Full { start, end, next } => {
            p = next;
            (start, end)
        }
        Bulk::Partial { len, data } if len > 32 => {
            if len > v + SLACK {
                return fatal(ProtoErr::TooLarge);
            }
            st.multi = skip_cursor(args);
            return Parsed::Reject { err: ProtoErr::BadCommand, ctx: none, consumed: data, discard_body: (len + 2) as u32 };
        }
        Bulk::Partial { .. } | Bulk::Incomplete => return incomplete(buf),
        Bulk::Bad => return fatal(ProtoErr::BadCommand),
    };
    let name = &buf[ns..ne];
    let is = |s: &[u8]| name.eq_ignore_ascii_case(s);

    if is(b"GET") {
        if args != 1 {
            return reject_tail(st, buf, p, args, v, ProtoErr::WrongArgs, none);
        }
        return match key_elem(buf, p) {
            KeyElem::Ok { ctx_key: (key, repr), next } => {
                st.multi = None;
                Parsed::Complete { req: Request::Get { ctx: ReqCtx { key, repr, ..none } }, consumed: next }
            }
            KeyElem::BadSmall { next } => {
                st.multi = None;
                Parsed::Reject { err: ProtoErr::BadKey, ctx: none, consumed: next, discard_body: 0 }
            }
            KeyElem::BadBig { .. } => reject_tail(st, buf, p, 1, v, ProtoErr::BadKey, none),
            KeyElem::Incomplete => incomplete(buf),
            KeyElem::Bad => fatal(ProtoErr::BadCommand),
        };
    }
    let multi_kind = if is(b"MGET") {
        Some(Kind::MGet)
    } else if is(b"DEL") {
        Some(Kind::Del)
    } else if is(b"EXISTS") {
        Some(Kind::Exists)
    } else {
        None
    };
    if let Some(kind) = multi_kind {
        if args == 0 {
            return reject_tail(st, buf, p, 0, v, ProtoErr::WrongArgs, none);
        }
        let c = MultiCursor { kind, remaining: args, total: args, first: true, inline: false };
        return array_multi_next(st, c, buf, p, v);
    }
    if is(b"SET") {
        return set(st, buf, p, args, v);
    }
    if is(b"PING") {
        if args > 1 {
            return reject_tail(st, buf, p, args, v, ProtoErr::WrongArgs, none);
        }
        return complete_tail(st, buf, p, args, v, Request::Noop { ctx: none });
    }
    if is(b"QUIT") {
        return complete_tail(st, buf, p, args, v, ctl(Control::Quit));
    }
    if is(b"CLIENT") {
        return complete_tail(st, buf, p, args, v, ctl(Control::Ok));
    }
    if is(b"COMMAND") {
        return complete_tail(st, buf, p, args, v, ctl(Control::CommandStub));
    }
    if is(b"HELLO") || is(b"SELECT") {
        let hello = is(b"HELLO");
        if args == 0 {
            if hello {
                return complete_tail(st, buf, p, 0, v, ctl(Control::Hello { version: st.version }));
            }
            return reject_tail(st, buf, p, 0, v, ProtoErr::WrongArgs, none);
        }
        if !hello && args != 1 {
            return reject_tail(st, buf, p, args, v, ProtoErr::WrongArgs, none);
        }
        let (s, e, next) = match bulk(buf, p) {
            Bulk::Full { start, end, next } => (start, end, next),
            Bulk::Partial { len, .. } if len > 16 => {
                return reject_tail(st, buf, p, args, v, ProtoErr::WrongArgs, none);
            }
            Bulk::Partial { .. } | Bulk::Incomplete => return incomplete(buf),
            Bulk::Bad => return fatal(ProtoErr::BadCommand),
        };
        let arg = &buf[s..e];
        let req = if hello {
            match arg {
                b"2" => Some(ctl(Control::Hello { version: 2 })),
                b"3" => Some(ctl(Control::Hello { version: 3 })),
                _ => None,
            }
        } else {
            (arg == b"0").then(|| ctl(Control::Ok))
        };
        let rest = args - 1; // HELLO AUTH/SETNAME options are accepted and ignored
        return match req {
            Some(req) => complete_tail(st, buf, next, rest, v, req),
            None => reject_tail(st, buf, next, rest, v, ProtoErr::Unsupported, none),
        };
    }
    reject_tail(st, buf, p, args, v, ProtoErr::BadCommand, none)
}

/// `SET k v [opts…]`: returns `Body` once the value's `$V\r\n` header is consumed.
fn set(st: &mut RespState, buf: &[u8], p: usize, args: u32, v: u64) -> Parsed {
    let none = ReqCtx::default();
    if args < 2 {
        return reject_tail(st, buf, p, args, v, ProtoErr::WrongArgs, none);
    }
    let (key, repr, p) = match key_elem(buf, p) {
        KeyElem::Ok { ctx_key: (k, r), next } => (k, r, next),
        KeyElem::BadSmall { next } => return reject_tail(st, buf, next, args - 1, v, ProtoErr::BadKey, none),
        KeyElem::BadBig { .. } => return reject_tail(st, buf, p, args, v, ProtoErr::BadKey, none),
        KeyElem::Incomplete => return incomplete(buf),
        KeyElem::Bad => return fatal(ProtoErr::BadCommand),
    };
    let ctx = ReqCtx { key, repr, ..none };
    // Value header.
    match buf.get(p) {
        None => return incomplete(buf),
        Some(b'$') => {}
        Some(_) => return fatal(ProtoErr::BadCommand),
    }
    let (len, data) = match num_line(buf, p + 1) {
        Num::Ok(l, e) if l >= 0 => (l as u64, e),
        Num::Ok(..) | Num::Bad => return fatal(ProtoErr::BadCommand),
        Num::Incomplete => return incomplete(buf),
    };
    if len > v + SLACK {
        return fatal(ProtoErr::BadLength);
    }
    let rest = args - 2;
    if len != v {
        st.multi = skip_cursor(rest);
        return Parsed::Reject { err: ProtoErr::BadLength, ctx, consumed: data, discard_body: (len + 2) as u32 };
    }
    st.multi = Some(MultiCursor { kind: Kind::SetTail, remaining: rest, ..Default::default() });
    Parsed::Body {
        hdr: BodyHeader { mode: SetMode::Set, ctx, body_len: v as u32, expect_continue: false },
        consumed: data,
    }
}

/// One key of MGET / DEL / EXISTS (array form), or `AggEnd` after the last.
fn array_multi_next(st: &mut RespState, mut c: MultiCursor, buf: &[u8], p: usize, v: u64) -> Parsed {
    let agg = match c.kind {
        Kind::Del => Some(AggKind::DelCount),
        Kind::Exists => Some(AggKind::ExistsCount),
        _ => None,
    };
    if c.remaining == 0 {
        // Only DEL/EXISTS get here: the last key left its `\r\n` for us.
        return match &buf[p..] {
            [b'\r', b'\n', ..] => {
                st.multi = None;
                let kind = agg.unwrap_or(AggKind::DelCount);
                Parsed::Complete { req: Request::AggEnd { kind, ctx: ReqCtx::default() }, consumed: p + 2 }
            }
            [] | [b'\r'] => Parsed::Incomplete { min_more: 1 },
            _ => fatal(ProtoErr::BadCommand),
        };
    }
    let mut ctx = multi_ctx(&c);
    let last = c.remaining == 1;
    let keep = if last && agg.is_some() { 2 } else { 0 };
    let res = match key_elem(buf, p) {
        KeyElem::Ok { ctx_key: (key, repr), next } => {
            ctx.key = key;
            ctx.repr = repr;
            let req = match c.kind {
                Kind::Del => Request::Delete { ctx },
                _ => Request::Get { ctx },
            };
            Parsed::Complete { req, consumed: next - keep }
        }
        KeyElem::BadSmall { next } => Parsed::Reject { err: ProtoErr::BadKey, ctx, consumed: next - keep, discard_body: 0 },
        KeyElem::BadBig { data, len } => {
            if len > v + SLACK {
                return fatal(ProtoErr::TooLarge);
            }
            Parsed::Reject { err: ProtoErr::BadKey, ctx, consumed: data, discard_body: (len + 2 - keep as u64) as u32 }
        }
        KeyElem::Incomplete => return incomplete(buf),
        KeyElem::Bad => return fatal(ProtoErr::BadCommand),
    };
    c.remaining -= 1;
    c.first = false;
    st.multi = if c.remaining == 0 && agg.is_none() { None } else { Some(c) };
    res
}

fn multi_ctx(c: &MultiCursor) -> ReqCtx {
    let flags = match c.kind {
        Kind::MGet => MULTI | ARRAY_ELEM,
        Kind::Exists => MULTI | EXISTS,
        _ => MULTI,
    };
    let array_prefix = if c.first && c.kind == Kind::MGet { c.total } else { 0 };
    ReqCtx { flags, array_prefix, ..Default::default() }
}

// ---------------------------------------------------------------------------
// Inline commands.

#[inline]
fn is_sp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Next token in `line` from `p`: (start, end).
fn next_tok(line: &[u8], mut p: usize) -> Option<(usize, usize)> {
    while p < line.len() && is_sp(line[p]) {
        p += 1;
    }
    if p >= line.len() {
        return None;
    }
    let s = p;
    while p < line.len() && !is_sp(line[p]) {
        p += 1;
    }
    Some((s, p))
}

fn inline(st: &mut RespState, buf: &[u8]) -> Parsed {
    let lim = buf.len().min(MAX_HEADER);
    let Some(nl) = memchr::memchr(b'\n', &buf[..lim]) else { return incomplete(buf) };
    let consumed = nl + 1;
    let mut line = &buf[..nl];
    if let [rest @ .., b'\r'] = line {
        line = rest;
    }
    let none = ReqCtx::default();
    let rej = |err, ctx| Parsed::Reject { err, ctx, consumed, discard_body: 0 };
    let Some((cs, ce)) = next_tok(line, 0) else {
        // Empty line: ignored.
        return rej(ProtoErr::BadCommand, quiet());
    };
    let name = &line[cs..ce];
    let is = |s: &[u8]| name.eq_ignore_ascii_case(s);
    let mut nargs = 0u32;
    let mut first_arg = None;
    let mut q = ce;
    while let Some((s, e)) = next_tok(line, q) {
        if nargs == 0 {
            first_arg = Some(&line[s..e]);
        }
        nargs += 1;
        q = e;
    }
    let done = |req| Parsed::Complete { req, consumed };
    if is(b"GET") {
        if nargs != 1 {
            return rej(ProtoErr::WrongArgs, none);
        }
        return match first_arg.and_then(parse_key) {
            Some((key, repr)) => done(Request::Get { ctx: ReqCtx { key, repr, ..none } }),
            None => rej(ProtoErr::BadKey, none),
        };
    }
    let kind = if is(b"MGET") {
        Some(Kind::MGet)
    } else if is(b"DEL") {
        Some(Kind::Del)
    } else if is(b"EXISTS") {
        Some(Kind::Exists)
    } else {
        None
    };
    if let Some(kind) = kind {
        if nargs == 0 {
            return rej(ProtoErr::WrongArgs, none);
        }
        let c = MultiCursor { kind, remaining: nargs, total: nargs, first: true, inline: true };
        return inline_multi_next(st, c, buf, ce);
    }
    if is(b"SET") {
        return rej(ProtoErr::Unsupported, none);
    }
    if is(b"PING") {
        return if nargs > 1 { rej(ProtoErr::WrongArgs, none) } else { done(Request::Noop { ctx: none }) };
    }
    if is(b"QUIT") {
        return done(ctl(Control::Quit));
    }
    if is(b"CLIENT") {
        return done(ctl(Control::Ok));
    }
    if is(b"COMMAND") {
        return done(ctl(Control::CommandStub));
    }
    if is(b"HELLO") {
        return match first_arg {
            None => done(ctl(Control::Hello { version: st.version })),
            Some(b"2") => done(ctl(Control::Hello { version: 2 })),
            Some(b"3") => done(ctl(Control::Hello { version: 3 })),
            Some(_) => rej(ProtoErr::Unsupported, none),
        };
    }
    if is(b"SELECT") {
        return match (nargs, first_arg) {
            (1, Some(b"0")) => done(ctl(Control::Ok)),
            (1, _) => rej(ProtoErr::Unsupported, none),
            _ => rej(ProtoErr::WrongArgs, none),
        };
    }
    rej(ProtoErr::BadCommand, none)
}

/// One key of an inline MGET / DEL / EXISTS, or the line end.
fn inline_multi_next(st: &mut RespState, mut c: MultiCursor, buf: &[u8], mut p: usize) -> Parsed {
    while p < buf.len() && is_sp(buf[p]) {
        p += 1;
    }
    let at_eol = p >= buf.len() || buf[p] == b'\r' || buf[p] == b'\n';
    if c.remaining == 0 || at_eol {
        let lim = buf.len().min(MAX_HEADER);
        let Some(nl) = memchr::memchr(b'\n', &buf[p.min(lim)..lim]).map(|i| i + p.min(lim)) else {
            return incomplete(buf);
        };
        st.multi = None;
        let ctx = ReqCtx::default();
        return match c.kind {
            Kind::Del => Parsed::Complete { req: Request::AggEnd { kind: AggKind::DelCount, ctx }, consumed: nl + 1 },
            Kind::Exists => Parsed::Complete { req: Request::AggEnd { kind: AggKind::ExistsCount, ctx }, consumed: nl + 1 },
            _ => Parsed::Reject { err: ProtoErr::BadCommand, ctx: quiet(), consumed: nl + 1, discard_body: 0 },
        };
    }
    let s = p;
    while p < buf.len() && !is_sp(buf[p]) && buf[p] != b'\r' && buf[p] != b'\n' {
        p += 1;
    }
    if p >= buf.len() {
        return incomplete(buf);
    }
    let mut ctx = multi_ctx(&c);
    let parsed = parse_key(&buf[s..p]);
    c.remaining -= 1;
    c.first = false;
    let mut consumed = p;
    if c.remaining == 0 && c.kind == Kind::MGet {
        // No end marker for MGET: swallow the line end now if it is buffered.
        let lim = buf.len().min(MAX_HEADER).max(p);
        if let Some(i) = memchr::memchr(b'\n', &buf[p..lim]) {
            consumed = p + i + 1;
            st.multi = None;
        } else {
            st.multi = Some(c);
        }
    } else {
        st.multi = Some(c);
    }
    match parsed {
        Some((key, repr)) => {
            ctx.key = key;
            ctx.repr = repr;
            let req = if c.kind == Kind::Del { Request::Delete { ctx } } else { Request::Get { ctx } };
            Parsed::Complete { req, consumed }
        }
        None => Parsed::Reject { err: ProtoErr::BadKey, ctx, consumed, discard_body: 0 },
    }
}

// ---------------------------------------------------------------------------
// SET trailer.

/// Consume the `\r\n` after SET's value and the remaining options (NX/XX/KEEPTTL…).
pub fn finish_body(st: &mut RespState, hdr: &mut BodyHeader, buf: &[u8]) -> Result<usize, FinishErr> {
    let rem = match st.multi {
        Some(c) if c.kind == Kind::SetTail => c.remaining,
        _ => 0,
    };
    match buf {
        [b'\r', b'\n', ..] => {}
        [] | [b'\r'] => return Err(FinishErr::Incomplete),
        _ => return Err(FinishErr::Fatal { err: ProtoErr::BadLength }),
    }
    let mut p = 2;
    let (mut nx, mut xx) = (false, false);
    let mut err: Option<ProtoErr> = None;
    let mut skip_arg = false;
    for _ in 0..rem {
        let (s, e) = match bulk(buf, p) {
            Bulk::Full { start, end, next } => {
                p = next;
                (start, end)
            }
            Bulk::Partial { len, .. } if len as usize > MAX_HEADER => {
                return Err(FinishErr::Fatal { err: ProtoErr::TooLarge });
            }
            Bulk::Partial { .. } | Bulk::Incomplete => {
                if buf.len() >= MAX_HEADER {
                    return Err(FinishErr::Fatal { err: ProtoErr::TooLarge });
                }
                return Err(FinishErr::Incomplete);
            }
            Bulk::Bad => return Err(FinishErr::Fatal { err: ProtoErr::BadCommand }),
        };
        if skip_arg {
            skip_arg = false;
            continue;
        }
        let o = &buf[s..e];
        let is = |x: &[u8]| o.eq_ignore_ascii_case(x);
        if is(b"NX") {
            nx = true;
        } else if is(b"XX") {
            xx = true;
        } else if is(b"KEEPTTL") {
        } else if is(b"GET") {
            err.get_or_insert(ProtoErr::Unsupported);
        } else if is(b"EX") || is(b"PX") || is(b"EXAT") || is(b"PXAT") {
            err.get_or_insert(ProtoErr::TtlUnsupported);
            skip_arg = true;
        } else {
            err.get_or_insert(ProtoErr::WrongArgs);
        }
    }
    if skip_arg || (nx && xx) {
        err.get_or_insert(ProtoErr::WrongArgs);
    }
    st.multi = None;
    if let Some(err) = err {
        return Err(FinishErr::Reject { err, consumed: p });
    }
    hdr.mode = if nx {
        SetMode::Add
    } else if xx {
        SetMode::Replace
    } else {
        SetMode::Set
    };
    Ok(p)
}

// ---------------------------------------------------------------------------
// Encoder.

fn err_msg(e: ProtoErr) -> &'static [u8] {
    match e {
        ProtoErr::BadCommand => b"-ERR unknown command\r\n",
        ProtoErr::BadKey => b"-ERR invalid key\r\n",
        ProtoErr::BadLength => b"-ERR invalid value length\r\n",
        ProtoErr::FlagsUnsupported => b"-ERR flags not supported\r\n",
        ProtoErr::TtlUnsupported => b"-ERR TTL options are not supported\r\n",
        ProtoErr::Unsupported => b"-ERR not supported\r\n",
        ProtoErr::LengthRequired | ProtoErr::MethodNotAllowed => b"-ERR protocol error\r\n",
        ProtoErr::TooLarge => b"-ERR Protocol error: too big\r\n",
        ProtoErr::WrongArgs => b"-ERR wrong number of arguments or syntax error\r\n",
    }
}

fn put_bulk(w: &mut HdrWriter<'_>, s: &[u8]) {
    w.put(b"$");
    w.put_u64(s.len() as u64);
    w.put(b"\r\n");
    w.put(s);
    w.put(b"\r\n");
}

fn hello(w: &mut HdrWriter<'_>, version: u8) {
    const PAIRS: [(&[u8], &[u8]); 4] =
        [(b"server", b"ssdcache"), (b"version", b"0.1"), (b"mode", b"standalone"), (b"role", b"master")];
    let pairs = PAIRS.len() as u64 + 1;
    if version >= 3 {
        w.put(b"%");
        w.put_u64(pairs);
    } else {
        w.put(b"*");
        w.put_u64(pairs * 2);
    }
    w.put(b"\r\n");
    for (k, val) in PAIRS {
        put_bulk(w, k);
        put_bulk(w, val);
    }
    put_bulk(w, b"proto");
    w.put(b":");
    w.put_u64(version as u64);
    w.put(b"\r\n");
}

pub fn encode(st: &RespState, ctx: &ReqCtx, r: &Response, value_len: u32, out: &mut [u8; HDR_CAP]) -> Frame {
    let nil: &[u8] = if st.version >= 3 { b"_\r\n" } else { b"$-1\r\n" };
    let agg_part = ctx.has(MULTI) && !ctx.has(ARRAY_ELEM);
    let mut w = HdrWriter::new(out);
    if ctx.array_prefix > 0 {
        w.put(b"*");
        w.put_u64(ctx.array_prefix as u64);
        w.put(b"\r\n");
    }
    let mut value = false;
    let mut suppressed = false;
    match r {
        Response::Hit if !agg_part && !ctx.has(EXISTS) => {
            w.put(b"$");
            w.put_u64(value_len as u64);
            w.put(b"\r\n");
            value = true;
        }
        Response::Miss if !agg_part && !ctx.has(EXISTS) => w.put(nil),
        Response::Deleted if !agg_part => w.put(b":1\r\n"),
        Response::NotFound if !agg_part => w.put(b":0\r\n"),
        Response::Hit | Response::Miss | Response::Deleted | Response::NotFound => suppressed = true,
        Response::Stored => w.put(b"+OK\r\n"),
        Response::NotStored => w.put(nil),
        Response::Count(n) => {
            w.put(b":");
            w.put_u64(*n as u64);
            w.put(b"\r\n");
        }
        Response::Noop => w.put(b"+PONG\r\n"),
        Response::Control(c) => match c {
            Control::Ok | Control::Quit | Control::Stats => w.put(b"+OK\r\n"),
            Control::CommandStub => w.put(b"*0\r\n"),
            Control::Hello { version } => hello(&mut w, *version),
            Control::Version => w.put(b"+ssdcache-0.1\r\n"),
        },
        Response::MultiEnd | Response::Continue => suppressed = true,
        Response::Proto(e) => {
            if ctx.has(QUIET) || agg_part {
                suppressed = true;
            } else {
                w.put(err_msg(*e));
            }
        }
        Response::ServerErr => {
            if agg_part {
                suppressed = true;
            } else {
                w.put(b"-ERR internal error\r\n");
            }
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
    use crate::proto::{KeyRepr, Opaque, ProtoKind, ProtoState};

    const V: u32 = 65536;
    const V2: u32 = 20000;
    const K1: &str = "00112233445566778899aabbccddeeff";
    const K2: &str = "ffeeddccbbaa99887766554433221100";
    const U1: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn arr(args: &[&[u8]]) -> Vec<u8> {
        let mut v = format!("*{}\r\n", args.len()).into_bytes();
        for a in args {
            v.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
            v.extend_from_slice(a);
            v.extend_from_slice(b"\r\n");
        }
        v
    }
    fn cmd(s: &str) -> Vec<u8> {
        let a: Vec<&[u8]> = s.split(' ').map(|x| x.as_bytes()).collect();
        arr(&a)
    }
    fn run(input: &[u8], v: u32) -> Vec<Ev> {
        drive_all(ProtoKind::Resp, input, v)
    }
    fn st(version: u8) -> ProtoState {
        let mut s = ProtoState::new(ProtoKind::Resp);
        s.on_control(&Control::Hello { version });
        s
    }
    fn render(ver: u8, ctx: &ReqCtx, r: Response) -> (String, Frame) {
        let (b, f) = enc(&st(ver), ctx, r, V);
        (String::from_utf8_lossy(&b).into_owned(), f)
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
    fn rej(e: &Ev) -> (ProtoErr, ReqCtx) {
        match e {
            Ev::Reject { err, ctx, .. } => (*err, *ctx),
            e => panic!("expected Reject, got {e:?}"),
        }
    }
    fn ctl(e: &Ev) -> Control {
        match e {
            Ev::Req(Request::Control { ctl, .. }) => *ctl,
            e => panic!("expected Control, got {e:?}"),
        }
    }
    fn set_cmd(key: &[u8], len: usize, opts: &[&[u8]]) -> Vec<u8> {
        let val = vec![b'v'; len];
        let mut a: Vec<&[u8]> = vec![b"SET", key, &val];
        a.extend_from_slice(opts);
        arr(&a)
    }
    fn visible_evs(evs: &[Ev]) -> Vec<Ev> {
        visible(evs)
    }

    #[test]
    fn get_hit_miss_resp2_resp3() {
        for input in [cmd(&format!("GET {K1}")), format!("get {K1}\r\n").into_bytes()] {
            let evs = run(&input, V);
            assert_eq!(evs.len(), 1);
            let c = get(&evs[0]);
            assert_eq!(c.key, key_of(K1));
            assert!(!c.has(MULTI));
            let (s, f) = render(2, &c, Response::Hit);
            assert_eq!(s, "$65536\r\n");
            assert!(f.value && f.trailer == b"\r\n");
            assert_eq!(render(2, &c, Response::Miss).0, "$-1\r\n");
            assert_eq!(render(3, &c, Response::Miss).0, "_\r\n");
            assert_eq!(render(2, &c, Response::ServerErr).0, "-ERR internal error\r\n");
        }
    }

    #[test]
    fn binary_raw_key() {
        let k: &[u8] = b"\x00\r\n $*\xff23456789a";
        let evs = run(&arr(&[b"GET", k]), V);
        let c = get(&evs[0]);
        assert_eq!(c.repr, KeyRepr::Raw16);
        assert_eq!(&c.key[..], k);
    }

    #[test]
    fn mget_one_key_per_call() {
        let mut input = cmd(&format!("MGET {K1} {U1} {K2}"));
        input.extend(cmd("PING"));
        let evs = run(&input, V);
        assert_eq!(evs.len(), 4);
        let c: Vec<ReqCtx> = evs[..3].iter().map(get).collect();
        assert!(c.iter().all(|c| c.has(MULTI) && c.has(ARRAY_ELEM) && !c.has(EXISTS)));
        assert_eq!(c.iter().map(|c| c.array_prefix).collect::<Vec<_>>(), [3, 0, 0]);
        assert_eq!(c[1].repr, KeyRepr::Uuid36 { upper: false });
        assert_eq!(render(2, &c[0], Response::Hit).0, "*3\r\n$65536\r\n");
        assert_eq!(render(3, &c[0], Response::Miss).0, "*3\r\n_\r\n");
        assert_eq!(render(2, &c[1], Response::Miss).0, "$-1\r\n");
        assert!(matches!(evs[3], Ev::Req(Request::Noop { .. })));

        // Direct: consumed covers exactly one element per call.
        let input = cmd(&format!("MGET {K1} {K2}"));
        let mut s = RespState::default();
        let Parsed::Complete { consumed, .. } = parse(&mut s, &input, V) else { panic!() };
        assert_eq!(consumed, 4 + 10 + 5 + 32 + 2);
        let rest = &input[consumed..];
        assert!(matches!(parse(&mut s, &rest[..20], V), Parsed::Incomplete { .. }));
        let Parsed::Complete { req, consumed } = parse(&mut s, rest, V) else { panic!() };
        assert_eq!(consumed, rest.len());
        assert_eq!(req.ctx().array_prefix, 0);
        assert!(s.multi.is_none());
    }

    #[test]
    fn mget_bad_key_is_error_element() {
        let long = vec![b'q'; 100];
        let mut input = arr(&[b"MGET", b"bad", K1.as_bytes(), &long, K2.as_bytes()]);
        input.extend(cmd("PING"));
        let evs = run(&input, V);
        assert_eq!(evs.len(), 5, "{evs:?}");
        let (err, c0) = rej(&evs[0]);
        assert_eq!(err, ProtoErr::BadKey);
        assert_eq!(render(2, &c0, Response::Proto(err)).0, "*4\r\n-ERR invalid key\r\n");
        get(&evs[1]);
        let (_, c2) = rej(&evs[2]);
        assert_eq!(render(2, &c2, Response::Proto(ProtoErr::BadKey)).0, "-ERR invalid key\r\n");
        assert_eq!(get(&evs[3]).key, key_of(K2));
        assert!(matches!(evs[4], Ev::Req(Request::Noop { .. })));
    }

    #[test]
    fn del_and_exists_aggregate() {
        let mut input = cmd(&format!("DEL {K1} {K2}"));
        input.extend(cmd(&format!("exists {K1} bad {U1}")));
        let evs = run(&input, V);
        assert_eq!(evs.len(), 7, "{evs:?}");
        let Ev::Req(Request::Delete { ctx }) = evs[0] else { panic!() };
        assert!(ctx.has(MULTI) && !ctx.has(ARRAY_ELEM));
        assert!(render(2, &ctx, Response::Deleted).1.suppressed);
        assert!(render(2, &ctx, Response::NotFound).1.suppressed);
        assert!(matches!(evs[1], Ev::Req(Request::Delete { .. })));
        let Ev::Req(Request::AggEnd { kind: AggKind::DelCount, ctx }) = evs[2] else { panic!() };
        assert_eq!(render(2, &ctx, Response::Count(2)).0, ":2\r\n");
        let c = get(&evs[3]);
        assert!(c.has(EXISTS | MULTI) && c.has(MULTI));
        assert!(render(3, &c, Response::Hit).1.suppressed);
        assert!(render(3, &c, Response::Miss).1.suppressed);
        let (err, c) = rej(&evs[4]);
        assert_eq!(err, ProtoErr::BadKey);
        assert!(render(3, &c, Response::Proto(err)).1.suppressed); // counts as 0
        get(&evs[5]);
        assert!(matches!(evs[6], Ev::Req(Request::AggEnd { kind: AggKind::ExistsCount, .. })));

        // The last key leaves its CRLF for AggEnd, so AggEnd never waits on an empty buffer.
        let input = cmd(&format!("DEL {K1}"));
        let mut s = RespState::default();
        let Parsed::Complete { consumed, .. } = parse(&mut s, &input, V) else { panic!() };
        assert_eq!(&input[consumed..], b"\r\n");
        let Parsed::Complete { req: Request::AggEnd { .. }, consumed: 2 } = parse(&mut s, &input[consumed..], V) else {
            panic!()
        };
        assert!(s.multi.is_none());
    }

    #[test]
    fn del_last_key_too_long_keeps_crlf_for_agg_end() {
        let long = vec![b'q'; 500];
        let input = arr(&[b"DEL", K1.as_bytes(), &long]);
        let evs = run(&input, V);
        assert!(matches!(evs.last(), Some(Ev::Req(Request::AggEnd { .. }))), "{evs:?}");
        let mut s = RespState::default();
        let Parsed::Complete { consumed, .. } = parse(&mut s, &input, V) else { panic!() };
        let rest = &input[consumed..];
        let Parsed::Reject { consumed, discard_body, .. } = parse(&mut s, &rest[..20], V) else { panic!() };
        assert_eq!(discard_body, 500);
        assert_eq!(&rest[consumed + 500..], b"\r\n");
    }

    #[test]
    fn many_keys_one_at_a_time() {
        let keys: Vec<String> = (0..300).map(|i| format!("{i:032x}")).collect();
        let mut a: Vec<&[u8]> = vec![b"DEL"];
        a.extend(keys.iter().map(|k| k.as_bytes()));
        let input = arr(&a);
        assert!(input.len() > MAX_HEADER);
        let evs = run(&input, V);
        assert_eq!(evs.len(), 301);
        let line = format!("MGET {}\r\n", keys[..20].join(" "));
        let evs = run(line.as_bytes(), V);
        assert_eq!(evs.len(), 20);
        assert_eq!(get(&evs[0]).array_prefix, 20);
    }

    #[test]
    fn set_and_options() {
        type Case<'a> = (Vec<&'a [u8]>, Result<SetMode, ProtoErr>);
        let cases: Vec<Case> = vec![
            (vec![], Ok(SetMode::Set)),
            (vec![b"NX"], Ok(SetMode::Add)),
            (vec![b"xx"], Ok(SetMode::Replace)),
            (vec![b"KEEPTTL", b"nx"], Ok(SetMode::Add)),
            (vec![b"GET"], Err(ProtoErr::Unsupported)),
            (vec![b"EX", b"10"], Err(ProtoErr::TtlUnsupported)),
            (vec![b"px", b"10", b"NX"], Err(ProtoErr::TtlUnsupported)),
            (vec![b"EXAT"], Err(ProtoErr::TtlUnsupported)),
            (vec![b"NX", b"XX"], Err(ProtoErr::WrongArgs)),
            (vec![b"BOGUS"], Err(ProtoErr::WrongArgs)),
        ];
        for v in [V, V2] {
            for (opts, want) in &cases {
                let mut input = set_cmd(K1.as_bytes(), v as usize, opts);
                input.extend(cmd("PING"));
                let evs = run(&input, v);
                assert_eq!(evs.len(), 2, "{opts:?} {evs:?}");
                let Ev::Body(h, r) = evs[0] else { panic!("{evs:?}") };
                assert_eq!(h.body_len, v);
                assert_eq!(h.ctx.key, key_of(K1));
                match (want, r) {
                    (Ok(m), Ok(_)) => assert_eq!(h.mode, *m),
                    (Err(e), Err(FinishErr::Reject { err, .. })) => assert_eq!(err, *e),
                    _ => panic!("{opts:?}: {r:?}"),
                }
                assert!(matches!(evs[1], Ev::Req(Request::Noop { .. })));
            }
        }
        let c = ReqCtx::default();
        assert_eq!(render(2, &c, Response::Stored).0, "+OK\r\n");
        assert_eq!(render(2, &c, Response::NotStored).0, "$-1\r\n");
        assert_eq!(render(3, &c, Response::NotStored).0, "_\r\n");
        assert_eq!(render(2, &c, Response::Proto(ProtoErr::TtlUnsupported)).0, "-ERR TTL options are not supported\r\n");
    }

    #[test]
    fn set_body_header_consumed() {
        let input = set_cmd(K1.as_bytes(), V2 as usize, &[b"NX"]);
        let mut s = RespState::default();
        let Parsed::Body { hdr, consumed } = parse(&mut s, &input, V2) else { panic!() };
        assert!(input[..consumed].ends_with(b"$20000\r\n"));
        let mut hdr = hdr;
        let tail = &input[consumed + V2 as usize..];
        assert_eq!(finish_body(&mut s, &mut hdr, &tail[..5]), Err(FinishErr::Incomplete));
        assert!(s.multi.is_some());
        assert_eq!(finish_body(&mut s, &mut hdr, tail), Ok(tail.len()));
        assert_eq!(hdr.mode, SetMode::Add);
        assert!(s.multi.is_none());
        let mut h2 = hdr;
        assert!(matches!(finish_body(&mut s, &mut h2, b"xx"), Err(FinishErr::Fatal { .. })));
    }

    #[test]
    fn set_rejects() {
        let mut input = set_cmd(K1.as_bytes(), 5, &[b"NX"]);
        input.extend(set_cmd(b"badkey", V2 as usize, &[b"XX", b"KEEPTTL"]));
        input.extend(set_cmd(&[b'k'; 80], V2 as usize, &[]));
        input.extend(cmd("SET onlykey"));
        input.extend(cmd("PING"));
        let evs = run(&input, V2);
        let vis = visible_evs(&evs);
        let errs: Vec<ProtoErr> = vis[..4].iter().map(|e| rej(e).0).collect();
        assert_eq!(errs, [ProtoErr::BadLength, ProtoErr::BadKey, ProtoErr::BadKey, ProtoErr::WrongArgs]);
        assert!(matches!(vis[4], Ev::Req(Request::Noop { .. })), "{vis:?}");
        assert_eq!(vis.len(), 5);
        // Over V + 64: fatal, never drained.
        let input = format!("*3\r\n$3\r\nSET\r\n$32\r\n{K1}\r\n${}\r\n", V2 + 65);
        assert!(matches!(run(input.as_bytes(), V2)[0], Ev::Fatal(ProtoErr::BadLength)));
        let input = format!("*3\r\n$3\r\nSET\r\n$32\r\n{K1}\r\n${}\r\n", V2 + 64);
        let evs = run(input.as_bytes(), V2);
        assert!(matches!(evs[0], Ev::Reject { err: ProtoErr::BadLength, discard: 20066, .. }), "{evs:?}");
    }

    #[test]
    fn control_commands() {
        let mut input = Vec::new();
        for c in [
            "PING",
            "ping hello",
            "PING a b",
            "HELLO 3",
            "hello 2 SETNAME x",
            "HELLO",
            "HELLO 4",
            "SELECT 0",
            "SELECT 1",
            "SELECT",
            "CLIENT SETNAME foo",
            "CLIENT SETINFO lib-name x",
            "COMMAND DOCS",
            "COMMAND",
            "FLUSHALL now please",
            "GET a b",
            "MGET",
            "QUIT",
        ] {
            input.extend(cmd(c));
        }
        let evs = visible_evs(&run(&input, V));
        assert_eq!(evs.len(), 18, "{evs:?}");
        assert!(matches!(evs[0], Ev::Req(Request::Noop { .. })));
        assert!(matches!(evs[1], Ev::Req(Request::Noop { .. })));
        assert_eq!(rej(&evs[2]).0, ProtoErr::WrongArgs);
        assert_eq!(ctl(&evs[3]), Control::Hello { version: 3 });
        assert_eq!(ctl(&evs[4]), Control::Hello { version: 2 });
        assert_eq!(ctl(&evs[5]), Control::Hello { version: 2 });
        assert_eq!(rej(&evs[6]).0, ProtoErr::Unsupported);
        assert_eq!(ctl(&evs[7]), Control::Ok);
        assert_eq!(rej(&evs[8]).0, ProtoErr::Unsupported);
        assert_eq!(rej(&evs[9]).0, ProtoErr::WrongArgs);
        assert_eq!(ctl(&evs[10]), Control::Ok);
        assert_eq!(ctl(&evs[11]), Control::Ok);
        assert_eq!(ctl(&evs[12]), Control::CommandStub);
        assert_eq!(ctl(&evs[13]), Control::CommandStub);
        assert_eq!(rej(&evs[14]).0, ProtoErr::BadCommand);
        assert_eq!(rej(&evs[15]).0, ProtoErr::WrongArgs);
        assert_eq!(rej(&evs[16]).0, ProtoErr::WrongArgs);
        let Ev::Req(Request::Control { ctl: Control::Quit, ctx }) = evs[17] else { panic!() };
        assert!(ctx.has(CLOSE_AFTER));
        let (s, f) = render(2, &ctx, Response::Control(Control::Quit));
        assert_eq!(s, "+OK\r\n");
        assert!(f.close_after && !f.suppressed);

        let c = ReqCtx::default();
        assert_eq!(render(2, &c, Response::Noop).0, "+PONG\r\n");
        assert_eq!(render(2, &c, Response::Control(Control::Ok)).0, "+OK\r\n");
        assert_eq!(render(2, &c, Response::Control(Control::CommandStub)).0, "*0\r\n");
        assert_eq!(render(2, &c, Response::Proto(ProtoErr::BadCommand)).0, "-ERR unknown command\r\n");
        let h3 = render(3, &c, Response::Control(Control::Hello { version: 3 })).0;
        assert!(h3.starts_with("%5\r\n$6\r\nserver\r\n$8\r\nssdcache\r\n"), "{h3}");
        assert!(h3.ends_with("$5\r\nproto\r\n:3\r\n"));
        let h2 = render(2, &c, Response::Control(Control::Hello { version: 2 })).0;
        assert!(h2.starts_with("*10\r\n") && h2.ends_with(":2\r\n"));
        assert_eq!(h2[5..h2.len() - 4], h3[4..h3.len() - 4]);
    }

    #[test]
    fn inline_commands() {
        let input = format!(
            "get {K1}\r\nMGET {K1} bad  {K2}\r\ndel {K1} {K2}\nEXISTS {U1}\r\n\r\nping\r\nset {K1} v\r\nGET\r\nhello 3\r\nselect 0\r\nquit\r\n"
        );
        let evs = visible_evs(&run(input.as_bytes(), V));
        get(&evs[0]);
        let c = get(&evs[1]);
        assert_eq!(c.array_prefix, 3);
        assert!(c.has(ARRAY_ELEM));
        assert_eq!(rej(&evs[2]).0, ProtoErr::BadKey);
        assert!(rej(&evs[2]).1.has(ARRAY_ELEM));
        assert_eq!(get(&evs[3]).key, key_of(K2));
        assert!(matches!(evs[4], Ev::Req(Request::Delete { .. })));
        assert!(matches!(evs[5], Ev::Req(Request::Delete { .. })));
        assert!(matches!(evs[6], Ev::Req(Request::AggEnd { kind: AggKind::DelCount, .. })));
        assert!(get(&evs[7]).has(EXISTS));
        assert!(matches!(evs[8], Ev::Req(Request::AggEnd { kind: AggKind::ExistsCount, .. })));
        assert!(matches!(evs[9], Ev::Req(Request::Noop { .. })));
        assert_eq!(rej(&evs[10]).0, ProtoErr::Unsupported);
        assert_eq!(rej(&evs[11]).0, ProtoErr::WrongArgs);
        assert_eq!(ctl(&evs[12]), Control::Hello { version: 3 });
        assert_eq!(ctl(&evs[13]), Control::Ok);
        assert_eq!(ctl(&evs[14]), Control::Quit);
        assert_eq!(evs.len(), 15);
    }

    #[test]
    fn framing_errors() {
        assert!(matches!(run(b"*1\r\n:5\r\n", V)[0], Ev::Fatal(ProtoErr::BadCommand)));
        assert!(matches!(run(b"*x\r\n", V)[0], Ev::Fatal(ProtoErr::BadCommand)));
        assert!(matches!(run(b"*99999999\r\n", V)[0], Ev::Fatal(ProtoErr::TooLarge)));
        assert!(matches!(run(b"*2\r\n$3\r\nGET\r\n$-1\r\n", V)[0], Ev::Fatal(_)));
        assert!(matches!(run(b"*1\r\n$4\r\nPINGxx", V)[0], Ev::Fatal(ProtoErr::BadCommand)));
        let evs = run(b"*0\r\n*1\r\n$4\r\nPING\r\n", V);
        assert!(matches!(evs.last(), Some(Ev::Req(Request::Noop { .. }))));
        assert_eq!(visible_evs(&evs).len(), 1);
        let long = vec![b'a'; MAX_HEADER + 1];
        assert!(matches!(run(&long, V)[0], Ev::Fatal(ProtoErr::TooLarge)));
        // An unknown command with a huge arg is skipped without buffering it.
        let big = vec![b'z'; V2 as usize];
        let mut input = arr(&[b"APPEND", K1.as_bytes(), &big]);
        input.extend(cmd("PING"));
        let evs = visible_evs(&run(&input, V2));
        assert_eq!(rej(&evs[0]).0, ProtoErr::BadCommand);
        assert!(matches!(evs[1], Ev::Req(Request::Noop { .. })));
        assert_eq!(evs.len(), 2);
    }

    #[test]
    fn header_fits_worst_case() {
        for ver in [2u8, 3] {
            let s = st(ver);
            let mut ctx = ReqCtx { array_prefix: u32::MAX, flags: MULTI | ARRAY_ELEM, ..Default::default() };
            ctx.opaque = Opaque { len: 32, bytes: [1; 32] };
            for v in [u32::MAX, V, V2] {
                for r in ALL_RESPONSES {
                    let (b, _) = enc(&s, &ctx, r, v);
                    assert!(b.len() < HDR_CAP && (b.is_empty() || b.ends_with(b"\r\n")), "{r:?}");
                }
                for e in ALL_ERRS {
                    let (b, _) = enc(&s, &ctx, Response::Proto(e), v);
                    assert!(b.len() < HDR_CAP && b.ends_with(b"\r\n"));
                }
                let (b, _) = enc(&s, &ctx, Response::Hit, v);
                assert_eq!(b, format!("*{}\r\n${v}\r\n", u32::MAX).as_bytes());
            }
            for hv in [2u8, 3] {
                let (b, _) = enc(&s, &ReqCtx::default(), Response::Control(Control::Hello { version: hv }), V);
                assert!(b.len() < HDR_CAP && b.ends_with(b"\r\n"));
            }
        }
    }

    #[test]
    fn fuzz_no_panic() {
        let a = cmd(&format!("MGET {K1} {K2} bad"));
        let b = cmd(&format!("DEL {K1} {U1}"));
        let c = set_cmd(K1.as_bytes(), V2 as usize, &[b"NX"]);
        let d = set_cmd(K1.as_bytes(), 64, &[b"EX", b"5"]);
        let e = cmd(&format!("EXISTS {K1}"));
        let f = format!("MGET {K1} {K2}\r\n");
        let g = cmd("HELLO 3");
        let pieces: Vec<&[u8]> = vec![
            &a, &b, &c, &d, &e, f.as_bytes(), &g, b"*", b"$", b"\r\n", b"*3\r\n", b"$32\r\n", b"$20000\r\n",
            b"PING\r\n", b"GET ", K1.as_bytes(), b"*2\r\n$3\r\nDEL\r\n",
        ];
        fuzz(ProtoKind::Resp, &pieces, V2, 3000, 0xdeadbeef);
        fuzz(ProtoKind::Resp, &pieces, 64, 3000, 777);
    }
}
