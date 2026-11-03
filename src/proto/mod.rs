//! Protocol layer (design §7). Parsers are pure: they read a byte slice, return a
//! borrowed `Parsed`, and never allocate. Responses are encoded into a small
//! caller-provided header buffer; the value bytes are never copied (the connection
//! machine gathers `[header, value slot, trailer]` into one `sendmsg`).
//!
//! Multi-key commands (`get k1 k2 …`, `MGET`, `DEL k1 k2 …`) are emitted **one key
//! at a time**: the parser consumes the bytes for one key, keeps the command in its
//! per-connection state, and resumes on the next call. The final call emits an
//! end marker (`Request::MultiEnd` / `Request::AggEnd`). So a request line of any
//! length needs only one key's worth of buffer, and there is no fallback pool.

pub mod key;
pub mod memcache;
pub mod resp;
pub mod http1;
#[cfg(test)]
pub(crate) mod testutil;

pub use key::{Key, KeyRepr, format_key, parse_key};

/// Which protocol a listener speaks. `Memcache` covers both the text protocol
/// (`get/set/...`) and the meta protocol (`mg/ms/md/mn`) on the same port.
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtoKind {
    Memcache,
    Resp,
    Http,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum SetMode {
    #[default]
    Set,
    /// memcache `add`, RESP `NX`, meta `ME` mode.
    Add,
    /// memcache `replace`, RESP `XX`, meta `MR` mode.
    Replace,
}

/// Opaque token echoed back (memcache meta `O` flag). Up to 32 bytes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Opaque {
    pub len: u8,
    pub bytes: [u8; 32],
}

impl Opaque {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Request flags (bit set).
pub mod flags {
    /// Do not send a reply on success (memcache `noreply`, meta `q` on HD/EN/NF).
    pub const QUIET: u16 = 1 << 0;
    /// Echo the key in the reply (meta `k`).
    pub const RETURN_KEY: u16 = 1 << 1;
    /// HTTP HEAD: send headers for a hit, but no body.
    pub const HEAD_ONLY: u16 = 1 << 2;
    /// Close the connection after this response is sent (HTTP `Connection: close`,
    /// HTTP/1.0 without keep-alive, memcache `quit`, RESP `QUIT`).
    pub const CLOSE_AFTER: u16 = 1 << 3;
    /// Part of a multi-key command; the response ends with a separate end marker.
    pub const MULTI: u16 = 1 << 4;
    /// memcache `gets`: include a CAS field (always 0) in `VALUE` lines.
    pub const WITH_CAS: u16 = 1 << 5;
    /// meta `v`: return the value (for `mg`). Without it, `mg` returns `HD` on a hit.
    pub const RETURN_VALUE: u16 = 1 << 6;
    /// meta `s`: return the size (`s<V>`) in the meta reply line.
    pub const RETURN_SIZE: u16 = 1 << 7;
    /// RESP: this GET is part of an MGET (a miss renders as a nil element, not an error).
    pub const ARRAY_ELEM: u16 = 1 << 8;
    /// RESP EXISTS: owner answers found / not found; nothing is pinned or sent.
    pub const EXISTS: u16 = 1 << 9;
    /// memcache meta command (`mg/ms/md/mn`): replies use `HD/EN/NS/NF/VA` and the
    /// meta quiet rules (`q` hides success codes only; errors are always sent).
    pub const META: u16 = 1 << 10;
}

/// Per-request context carried through dispatch and back into `encode`.
/// `Copy` and small: it lives inside each response-ring entry.
#[derive(Copy, Clone, Debug, Default)]
pub struct ReqCtx {
    pub flags: u16,
    pub repr: KeyRepr,
    pub key: Key,
    pub opaque: Opaque,
    /// RESP: for the first element of an MGET, the array length to prefix (`*n\r\n`).
    /// 0 = no prefix. RESP DEL / EXISTS use `AggEnd` instead.
    pub array_prefix: u32,
}

impl ReqCtx {
    pub fn has(&self, f: u16) -> bool {
        self.flags & f != 0
    }
}

/// What the aggregated end marker sums (RESP `DEL k…` → `:n`, `EXISTS k…` → `:n`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AggKind {
    DelCount,
    ExistsCount,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Control {
    /// memcache `version`.
    Version,
    /// memcache `quit`, RESP `QUIT` (RESP replies `+OK` first; memcache closes silently).
    Quit,
    /// RESP `HELLO 2|3` (switches the connection's RESP version; reply is a map/array).
    Hello { version: u8 },
    /// RESP `SELECT 0`, `CLIENT SETNAME/SETINFO …` and other accepted no-ops → `+OK`.
    Ok,
    /// RESP `COMMAND …` stub → empty array.
    CommandStub,
    /// memcache `stats` → `END` (real stats are on the admin port).
    Stats,
}

/// One parsed request (or one key of a multi-key request).
#[derive(Copy, Clone, Debug)]
pub enum Request {
    /// Single-key read. For `get k1 k2` there is one `Get` per key, each with `flags::MULTI`,
    /// followed by `MultiEnd`. RESP `EXISTS k` uses `Get` with `flags::EXISTS`.
    Get { ctx: ReqCtx },
    Delete { ctx: ReqCtx },
    /// End of a multi-key memcache `get`/`gets` (renders `END\r\n`). For memcache single
    /// `get k` the parser also emits `MultiEnd` after the one `Get`.
    MultiEnd { ctx: ReqCtx },
    /// End of a RESP aggregated command: renders `:<count>\r\n` where count is summed by
    /// the connection machine over the preceding parts (each part has `flags::MULTI`).
    AggEnd { kind: AggKind, ctx: ReqCtx },
    /// memcache meta `mn` → `MN\r\n`; RESP `PING` → `+PONG`.
    Noop { ctx: ReqCtx },
    Control { ctl: Control, ctx: ReqCtx },
}

impl Request {
    pub fn ctx(&self) -> &ReqCtx {
        match self {
            Request::Get { ctx }
            | Request::Delete { ctx }
            | Request::MultiEnd { ctx }
            | Request::AggEnd { ctx, .. }
            | Request::Noop { ctx }
            | Request::Control { ctx, .. } => ctx,
        }
    }
}

/// A store command whose value follows. The connection machine receives exactly
/// `body_len` bytes into a slot, then calls `finish_body` for the trailer.
#[derive(Copy, Clone, Debug)]
pub struct BodyHeader {
    pub mode: SetMode,
    pub ctx: ReqCtx,
    pub body_len: u32,
    /// HTTP `Expect: 100-continue`: the connection pushes a `Continue` response first.
    pub expect_continue: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProtoErr {
    /// Unknown command / malformed line.
    BadCommand,
    /// Key is not 16 raw bytes / 32 hex / 36-char UUID.
    BadKey,
    /// Value length != configured V.
    BadLength,
    /// memcache client flags must be 0 (design Q2).
    FlagsUnsupported,
    /// TTL options are not supported (RESP EX/PX/…; memcache exptime is ignored, not rejected).
    TtlUnsupported,
    /// Unsupported command that we recognize (cas, incr, …).
    Unsupported,
    /// HTTP: Transfer-Encoding present (411), or CL+TE (400).
    LengthRequired,
    /// HTTP: method not allowed.
    MethodNotAllowed,
    /// Header block or line too long for MAX_HEADER.
    TooLarge,
    /// Wrong number of arguments.
    WrongArgs,
}

/// Parser output. `consumed` counts bytes of `buf` that the caller must drop.
#[derive(Copy, Clone, Debug)]
pub enum Parsed {
    Complete { req: Request, consumed: usize },
    /// A store command; the body (`hdr.body_len` bytes) starts right after `consumed`.
    Body { hdr: BodyHeader, consumed: usize },
    /// Need more bytes. `min_more` is a hint (≥ 1).
    Incomplete { min_more: usize },
    /// Bad request that can be answered: reply with `err`, drop `consumed` bytes, then
    /// discard `discard_body` more bytes (a rejected store's value) before parsing again.
    Reject { err: ProtoErr, ctx: ReqCtx, consumed: usize, discard_body: u32 },
    /// Unrecoverable framing error: reply with `err` if possible, then close.
    Fatal { err: ProtoErr },
}

/// `finish_body` failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FinishErr {
    /// Need more bytes for the trailer.
    Incomplete,
    /// Trailer is malformed or has unsupported options. Reply with the error; the body
    /// slot is aborted, `consumed` bytes are dropped. Framing is intact.
    Reject { err: ProtoErr, consumed: usize },
    /// Framing is broken: close.
    Fatal { err: ProtoErr },
}

/// Outcome from the storage core, rendered by `encode`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// Value found; `encode` writes the header and `Frame.value = true` tells the
    /// connection to gather the V value bytes after it (unless HEAD_ONLY / EXISTS / meta
    /// without `v`).
    Hit,
    Miss,
    Stored,
    NotStored,
    Deleted,
    NotFound,
    /// RESP aggregated count (DEL / EXISTS).
    Count(u32),
    /// End of a multi-get.
    MultiEnd,
    Noop,
    /// Control-command reply.
    Control(Control),
    /// HTTP interim `100 Continue`.
    Continue,
    /// Protocol error from the parser.
    Proto(ProtoErr),
    /// Server-side error (SSD read error, overload).
    ServerErr,
}

/// How to send one response: `hdr[..hdr_len]` was written by `encode`, then (if
/// `value`) the V value bytes, then `trailer`.
#[derive(Copy, Clone, Debug)]
pub struct Frame {
    pub hdr_len: u16,
    pub value: bool,
    pub trailer: &'static [u8],
    /// Response is suppressed entirely (noreply / quiet). It still occupies its ring
    /// position (ordering), but nothing is sent.
    pub suppressed: bool,
    pub close_after: bool,
}

/// Size of the per-response header buffer. Every encoder must fit its header in it.
pub const HDR_CAP: usize = 192;

#[derive(Copy, Clone, Debug, Default)]
pub struct MemcacheState {
    /// Resumable multi-key cursor: `Some` while inside `get k1 k2 …`.
    pub multi: Option<memcache::MultiCursor>,
}

#[derive(Copy, Clone, Debug)]
pub struct RespState {
    /// 2 or 3 (switched by HELLO).
    pub version: u8,
    /// Resumable cursor while inside an MGET / DEL / EXISTS array.
    pub multi: Option<resp::MultiCursor>,
}

impl Default for RespState {
    fn default() -> Self {
        RespState { version: 2, multi: None }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct HttpState {
    /// Set once a request asked to close; the parser then refuses further requests.
    pub closing: bool,
}

/// Per-connection protocol state.
#[derive(Copy, Clone, Debug)]
pub enum ProtoState {
    Memcache(MemcacheState),
    Resp(RespState),
    Http(HttpState),
}

impl ProtoState {
    pub fn new(kind: ProtoKind) -> Self {
        match kind {
            ProtoKind::Memcache => ProtoState::Memcache(MemcacheState::default()),
            ProtoKind::Resp => ProtoState::Resp(RespState::default()),
            ProtoKind::Http => ProtoState::Http(HttpState::default()),
        }
    }

    /// Maximum header/line size this protocol needs to buffer before it can make
    /// progress. Callers must provide at least this much buffer.
    pub fn max_header(&self) -> usize {
        match self {
            ProtoState::Memcache(_) => memcache::MAX_HEADER,
            ProtoState::Resp(_) => resp::MAX_HEADER,
            ProtoState::Http(_) => http1::MAX_HEADER,
        }
    }

    /// Parse the next request from `buf`. `value_len` is the configured V.
    pub fn parse(&mut self, buf: &[u8], value_len: u32) -> Parsed {
        match self {
            ProtoState::Memcache(st) => memcache::parse(st, buf, value_len),
            ProtoState::Resp(st) => resp::parse(st, buf, value_len),
            ProtoState::Http(st) => http1::parse(st, buf, value_len),
        }
    }

    /// Consume the bytes that follow a store command's value (memcache `\r\n`,
    /// RESP `\r\n` + trailing options like `NX`/`XX`, HTTP nothing). May update
    /// `hdr.mode` (RESP NX/XX come after the value). Returns bytes consumed.
    pub fn finish_body(&mut self, hdr: &mut BodyHeader, buf: &[u8]) -> Result<usize, FinishErr> {
        match self {
            ProtoState::Memcache(st) => memcache::finish_body(st, hdr, buf),
            ProtoState::Resp(st) => resp::finish_body(st, hdr, buf),
            ProtoState::Http(st) => http1::finish_body(st, hdr, buf),
        }
    }

    /// Render the response header into `out` (len `HDR_CAP`).
    pub fn encode(&self, ctx: &ReqCtx, r: &Response, value_len: u32, out: &mut [u8; HDR_CAP]) -> Frame {
        match self {
            ProtoState::Memcache(st) => memcache::encode(st, ctx, r, value_len, out),
            ProtoState::Resp(st) => resp::encode(st, ctx, r, value_len, out),
            ProtoState::Http(st) => http1::encode(st, ctx, r, value_len, out),
        }
    }

    /// Apply side effects of a control request that was answered (RESP HELLO switches
    /// the version). Called by the connection machine when the request is dispatched.
    pub fn on_control(&mut self, ctl: &Control) {
        if let (ProtoState::Resp(st), Control::Hello { version }) = (self, ctl) {
            st.version = *version;
        }
    }
}

/// Small helper for encoders: a cursor over the fixed header buffer.
pub struct HdrWriter<'a> {
    pub buf: &'a mut [u8; HDR_CAP],
    pub len: usize,
}

impl<'a> HdrWriter<'a> {
    pub fn new(buf: &'a mut [u8; HDR_CAP]) -> Self {
        HdrWriter { buf, len: 0 }
    }
    pub fn put(&mut self, s: &[u8]) {
        let n = s.len().min(HDR_CAP - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }
    pub fn put_u64(&mut self, mut v: u64) {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        if v == 0 {
            i -= 1;
            tmp[i] = b'0';
        }
        while v > 0 {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        self.put(&tmp[i..]);
    }
    pub fn put_key(&mut self, ctx: &ReqCtx) {
        let mut tmp = [0u8; 36];
        let n = format_key(&ctx.key, ctx.repr, &mut tmp);
        self.put(&tmp[..n]);
    }
}
