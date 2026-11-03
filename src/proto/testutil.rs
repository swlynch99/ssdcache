//! Test-only driver shared by the protocol unit tests (allocates freely).

use super::*;

#[derive(Debug, Clone, Copy)]
pub enum Ev {
    Req(Request),
    /// A store: header after `finish_body`, and the `finish_body` result.
    Body(BodyHeader, Result<usize, FinishErr>),
    Reject { err: ProtoErr, ctx: ReqCtx, discard: u32 },
    Fatal(ProtoErr),
    /// Input ended inside a body / trailer.
    Truncated,
}

/// Feed `input` to the parser, `step` bytes at a time (0 = all at once), acting like
/// the connection machine: drop `consumed`, receive bodies, discard rejected bodies.
/// Returns the events and the number of input bytes fully processed.
pub fn drive(st: &mut ProtoState, input: &[u8], v: u32, step: usize) -> (Vec<Ev>, usize) {
    let grow = step.max(1);
    let mut avail = if step == 0 { input.len() } else { step.min(input.len()) };
    let mut pos = 0usize;
    let mut evs = Vec::new();
    let mut zero_progress = 0;
    loop {
        let buf = &input[pos..avail];
        let before = format!("{:?}", st);
        let p = st.parse(buf, v);
        match p {
            Parsed::Complete { req, consumed } => {
                assert!(consumed <= buf.len(), "consumed {consumed} > {}", buf.len());
                if consumed == 0 {
                    zero_progress += 1;
                    assert!(zero_progress < 4, "no progress: {req:?}");
                } else {
                    zero_progress = 0;
                }
                pos += consumed;
                evs.push(Ev::Req(req));
            }
            Parsed::Body { hdr, consumed } => {
                assert!(consumed <= buf.len() && consumed > 0);
                zero_progress = 0;
                pos += consumed;
                let mut hdr = hdr;
                let end = pos + hdr.body_len as usize;
                if end > input.len() {
                    evs.push(Ev::Truncated);
                    return (evs, pos);
                }
                pos = end;
                avail = avail.max(pos);
                loop {
                    match st.finish_body(&mut hdr, &input[pos..avail]) {
                        Err(FinishErr::Incomplete) => {
                            if avail >= input.len() {
                                evs.push(Ev::Truncated);
                                return (evs, pos);
                            }
                            avail = (avail + grow).min(input.len());
                        }
                        r => {
                            evs.push(Ev::Body(hdr, r));
                            match r {
                                Ok(n) | Err(FinishErr::Reject { consumed: n, .. }) => {
                                    assert!(pos + n <= avail);
                                    pos += n;
                                }
                                _ => return (evs, pos),
                            }
                            break;
                        }
                    }
                }
            }
            Parsed::Incomplete { min_more } => {
                assert!(min_more >= 1);
                assert_eq!(before, format!("{:?}", st), "state mutated on Incomplete");
                if avail >= input.len() {
                    return (evs, pos);
                }
                avail = (avail + grow).min(input.len());
            }
            Parsed::Reject { err, ctx, consumed, discard_body } => {
                assert!(consumed <= buf.len());
                if consumed == 0 && discard_body == 0 {
                    zero_progress += 1;
                    assert!(zero_progress < 4, "no progress reject {err:?}");
                } else {
                    zero_progress = 0;
                }
                pos += consumed;
                let end = pos + discard_body as usize;
                evs.push(Ev::Reject { err, ctx, discard: discard_body });
                if end > input.len() {
                    evs.push(Ev::Truncated);
                    return (evs, input.len());
                }
                pos = end;
                avail = avail.max(pos);
            }
            Parsed::Fatal { err } => {
                evs.push(Ev::Fatal(err));
                return (evs, pos);
            }
        }
    }
}

/// Drive with several step sizes and assert all agree with the one-shot result.
pub fn drive_all(kind: ProtoKind, input: &[u8], v: u32) -> Vec<Ev> {
    let mut st = ProtoState::new(kind);
    let (evs, pos) = drive(&mut st, input, v, 0);
    let want = format!("{:?} {pos}", normalize(&evs));
    for step in [1usize, 2, 3, 7, 64] {
        let mut st = ProtoState::new(kind);
        let (e2, p2) = drive(&mut st, input, v, step);
        assert_eq!(want, format!("{:?} {p2}", normalize(&e2)), "step {step} differs");
    }
    evs
}

/// Drop suppressed (QUIET) rejects: whether bytes are skipped by one or several
/// quiet rejects depends on how input is split.
pub fn visible(evs: &[Ev]) -> Vec<Ev> {
    evs.iter()
        .filter(|e| !matches!(e, Ev::Reject { ctx, .. } if ctx.has(flags::QUIET) && !ctx.has(flags::META)))
        .copied()
        .collect()
}

/// For comparing one-shot vs incremental runs: how a rejected element is dropped
/// (consumed vs discarded) depends on what is buffered, so ignore `discard`.
fn normalize(evs: &[Ev]) -> Vec<Ev> {
    visible(evs)
        .into_iter()
        .map(|e| match e {
            Ev::Reject { err, ctx, .. } => Ev::Reject { err, ctx, discard: 0 },
            e => e,
        })
        .collect()
}

/// Encode `r` for `ctx` and return (header bytes, frame).
pub fn enc(st: &ProtoState, ctx: &ReqCtx, r: Response, v: u32) -> (Vec<u8>, Frame) {
    let mut out = [0u8; HDR_CAP];
    let f = st.encode(ctx, &r, v, &mut out);
    assert!(f.hdr_len as usize <= HDR_CAP);
    if f.suppressed {
        assert_eq!(f.hdr_len, 0);
        assert!(!f.value);
    }
    (out[..f.hdr_len as usize].to_vec(), f)
}

pub fn ctx_of(e: &Ev) -> ReqCtx {
    match e {
        Ev::Req(r) => *r.ctx(),
        Ev::Body(h, _) => h.ctx,
        Ev::Reject { ctx, .. } => *ctx,
        _ => ReqCtx::default(),
    }
}

/// Deterministic xorshift RNG.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

pub const ALL_RESPONSES: [Response; 17] = [
    Response::Hit,
    Response::Miss,
    Response::Stored,
    Response::NotStored,
    Response::Deleted,
    Response::NotFound,
    Response::Count(u32::MAX),
    Response::MultiEnd,
    Response::Noop,
    Response::Control(Control::Version),
    Response::Control(Control::Quit),
    Response::Control(Control::Hello { version: 3 }),
    Response::Control(Control::Ok),
    Response::Control(Control::CommandStub),
    Response::Control(Control::Stats),
    Response::Continue,
    Response::ServerErr,
];

pub const ALL_ERRS: [ProtoErr; 10] = [
    ProtoErr::BadCommand,
    ProtoErr::BadKey,
    ProtoErr::BadLength,
    ProtoErr::FlagsUnsupported,
    ProtoErr::TtlUnsupported,
    ProtoErr::Unsupported,
    ProtoErr::LengthRequired,
    ProtoErr::MethodNotAllowed,
    ProtoErr::TooLarge,
    ProtoErr::WrongArgs,
];

/// Fuzz: random streams built from `pieces` and random bytes, fed with random steps.
/// Also encodes every produced ctx with every response.
pub fn fuzz(kind: ProtoKind, pieces: &[&[u8]], v: u32, iters: usize, seed: u64) {
    let mut rng = Rng(seed);
    for _ in 0..iters {
        let mut input = Vec::new();
        for _ in 0..rng.below(12) + 1 {
            match rng.below(4) {
                0 => {
                    for _ in 0..rng.below(40) {
                        input.push(rng.next() as u8);
                    }
                }
                1 => {
                    let p = pieces[rng.below(pieces.len())];
                    let cut = rng.below(p.len() + 1);
                    input.extend_from_slice(&p[..cut]);
                }
                _ => input.extend_from_slice(pieces[rng.below(pieces.len())]),
            }
            if rng.below(8) == 0 {
                input.extend(std::iter::repeat_n(b'x', rng.below(v as usize + 200)));
            }
        }
        let step = [0, 1, 2, 5, 17, 100][rng.below(6)];
        let mut st = ProtoState::new(kind);
        let (evs, _) = drive(&mut st, &input, v, step);
        for e in &evs {
            let ctx = ctx_of(e);
            for st_v in [2u8, 3] {
                let mut s = st;
                s.on_control(&Control::Hello { version: st_v });
                for r in ALL_RESPONSES {
                    enc(&s, &ctx, r, v);
                }
                for e in ALL_ERRS {
                    enc(&s, &ctx, Response::Proto(e), v);
                }
            }
        }
    }
}
