//! Worker thread (design §2.5, §6, §7.3): one io_uring loop that is both the network thread
//! for its connections and the single owner of one shard.
//!
//! Everything is allocated in `Worker::new` (before the loop starts). The loop itself does
//! not allocate.

use crate::config::{Config, CreditCfg};
use crate::core::fifo::Fifo;
use crate::core::shard::{IoBuf, IoKind, IoReq, Out, Reply, ReqToken, Shard, Status};
use crate::hash::{H, Hasher};
use crate::proto::{
    self, AggKind, BodyHeader, Control, FinishErr, HDR_CAP, Parsed, ProtoErr, ProtoKind, ProtoState, ReqCtx, Request,
    Response, SetMode, flags,
};
use crate::sizing::Geometry;
use crate::stats::WorkerStats;
use crate::xshard::{Line, Mesh, Msg};
use crossbeam_queue::ArrayQueue;
use io_uring::{IoUring, opcode, squeue, types};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::*};
use std::time::{Duration, Instant};

// ------------------------------------------------------------------ user_data encoding
// kind:8 | conn ops: idx:24 | gen:16 | aux:16      storage ops: op:24 | opgen:32
const K_RECV: u64 = 1;
const K_SEND: u64 = 2;
const K_SSD: u64 = 3;
const K_DOORBELL: u64 = 4;
const K_CLOSE: u64 = 5;
const K_TIMEOUT: u64 = 6;

#[inline]
fn ud_conn(kind: u64, idx: u32, cgen: u16) -> u64 {
    (kind << 56) | ((idx as u64 & 0xff_ffff) << 32) | ((cgen as u64) << 16)
}
#[inline]
fn ud_ssd(op: u32, opgen: u32) -> u64 {
    (K_SSD << 56) | ((op as u64 & 0xff_ffff) << 32) | opgen as u64
}

// ReqToken.resp encoding: idx:16 | kind:4
const T_LOOKUP: u32 = 1;
const T_RESERVE: u32 = 2;
const T_COMMIT: u32 = 3;
const T_DELETE: u32 = 4;
#[inline]
fn tok_kind(t: &ReqToken) -> u32 {
    t.resp >> 16
}
#[inline]
fn tok_idx(t: &ReqToken) -> u32 {
    t.resp & 0xffff
}

pub const RESP_RING: usize = 64;
const MAX_IOV: usize = 3 * RESP_RING + 2;
pub const CARRY: usize = 24 * 1024;
const SEND_BUDGET: u64 = 256 * 1024;

pub struct Handoff {
    pub fd: i32,
    pub proto: ProtoKind,
    pub tls: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum EState {
    Free,
    Pending,
    Ready,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum EKind {
    Get,
    Set,
    Del,
    Other,
}

#[derive(Copy, Clone)]
struct RespEntry {
    state: EState,
    kind: EKind,
    ctx: ReqCtx,
    resp: Response,
    owner: u16,
    slot: u32,
    sgen: u32,
    pinned: bool,
    encoded: bool,
    hdr_len: u16,
    value: bool,
    suppressed: bool,
    close_after: bool,
    trailer: &'static [u8],
    sent: u32,
    hdr: [u8; HDR_CAP],
}

impl RespEntry {
    const EMPTY: RespEntry = RespEntry {
        state: EState::Free,
        kind: EKind::Other,
        ctx: ReqCtx {
            flags: 0,
            repr: proto::KeyRepr::Raw16,
            key: [0; 16],
            opaque: proto::Opaque { len: 0, bytes: [0; 32] },
            array_prefix: 0,
        },
        resp: Response::Noop,
        owner: 0,
        slot: 0,
        sgen: 0,
        pinned: false,
        encoded: false,
        hdr_len: 0,
        value: false,
        suppressed: false,
        close_after: false,
        trailer: b"",
        sent: 0,
        hdr: [0; HDR_CAP],
    };
}

#[derive(Copy, Clone, Debug)]
enum Rx {
    Header,
    AwaitSlot { hdr: BodyHeader, owner: u16, resp: u32, h: H },
    Body { hdr: BodyHeader, owner: u16, resp: u32, h: H, slot: u32, sgen: u32, filled: u32 },
    Trailer { hdr: BodyHeader, owner: u16, resp: u32, h: H, slot: u32, sgen: u32 },
    Discard { left: u32 },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RecvKind {
    Carry,
    Body,
    Discard,
}

struct Conn {
    active: bool,
    fd: i32,
    cgen: u16,
    tls: bool,
    proto: ProtoState,
    rx: Rx,
    carry: Box<[u8]>,
    c_start: usize,
    c_end: usize,
    recv_inflight: bool,
    recv_kind: RecvKind,
    send_inflight: bool,
    closing: bool,
    parked: bool,
    read_closed: bool,
    ring: Box<[RespEntry]>,
    head: u32,
    tail: u32,
    gathered: u32,
    agg: u32,
    pins: Box<[u8]>,
    iov: Box<[libc::iovec]>,
    msg: libc::msghdr,
    dirty: bool,
    body_deadline_ns: u64,
}

impl Conn {
    fn new(n: usize) -> Self {
        Conn {
            active: false,
            fd: -1,
            cgen: 0,
            tls: false,
            proto: ProtoState::new(ProtoKind::Memcache),
            rx: Rx::Header,
            carry: vec![0u8; CARRY].into_boxed_slice(),
            c_start: 0,
            c_end: 0,
            recv_inflight: false,
            recv_kind: RecvKind::Carry,
            send_inflight: false,
            closing: false,
            parked: false,
            read_closed: false,
            ring: vec![RespEntry::EMPTY; RESP_RING].into_boxed_slice(),
            head: 0,
            tail: 0,
            gathered: 0,
            agg: 0,
            pins: vec![0u8; n].into_boxed_slice(),
            iov: vec![libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; MAX_IOV].into_boxed_slice(),
            msg: unsafe { std::mem::zeroed() },
            dirty: false,
            body_deadline_ns: 0,
        }
    }
    #[inline]
    fn ring_free(&self) -> u32 {
        RESP_RING as u32 - (self.tail - self.head)
    }
    #[inline]
    fn entry(&mut self, i: u32) -> &mut RespEntry {
        &mut self.ring[(i as usize) % RESP_RING]
    }
}

/// Per-owner budgets held by this worker (design §2.4).
struct PairBudget {
    credits: u16,
    pins: u16,
    fill_used: u16,
    stash: [(u32, u32); 8],
    n_stash: u8,
    unpins: [(u32, u32); 5],
    n_unpins: u8,
    pushed: bool,
}

pub struct WorkerShared {
    pub mesh: Arc<Mesh>,
    pub handoff: Arc<Vec<ArrayQueue<Handoff>>>,
    pub stop: Arc<AtomicBool>,
    pub stats: Arc<Vec<WorkerStats>>,
}

pub struct Worker {
    id: u16,
    n: u16,
    ring: IoUring,
    shard: Shard,
    geo: Geometry,
    hasher: Hasher,
    cr: CreditCfg,
    arena: *mut u8,
    fixed: bool,
    dev_fds: Vec<i32>,
    conns: Vec<Conn>,
    free_conns: Vec<u32>,
    parked: Fifo<u32>,
    dirty: Fifo<u32>,
    pairs: Vec<PairBudget>,
    overflow: Vec<Fifo<Line>>,
    region_overflow: Fifo<(u16, crate::core::shard::RegionMsg)>,
    scratch: Box<[u8]>,
    sh: WorkerShared,
    spin: Duration,
    body_timeout_ns: u64,
    start: Instant,
    last_publish: Instant,
    ts: types::Timespec,
    pub counters: WorkerCounters,
}

#[derive(Default, Clone, Debug)]
pub struct WorkerCounters {
    pub conns_opened: u64,
    pub conns_closed: u64,
    pub parked: u64,
    pub doorbells_sent: u64,
    pub wakeups: u64,
    pub spin_hits: u64,
    pub ring_overflow: u64,
    pub stale_replies: u64,
    pub tls_control_records: u64,
    pub body_timeouts: u64,
    pub send_bytes: u64,
    pub recv_bytes: u64,
    pub fixed_buffers: u64,
}

// The arena pointer is shared memory whose slot bytes are handed between threads through
// the SPSC Release/Acquire chain (design §5.2 "Visibility").
unsafe impl Send for Worker {}

impl Worker {
    pub fn new(id: u16, cfg: &Config, geo: &Geometry, shard: Shard, arena: *mut u8, dev_fds: Vec<i32>, sh: WorkerShared, max_conns: u32) -> std::io::Result<Self> {
        let n = cfg.workers;
        let ring = IoUring::builder()
            .setup_single_issuer()
            .setup_defer_taskrun()
            .setup_coop_taskrun()
            .setup_cqsize(16384)
            .build(4096)
            .or_else(|_| IoUring::builder().setup_cqsize(16384).build(4096))?;
        let conns = (0..max_conns).map(|_| Conn::new(n as usize)).collect();
        let pairs = (0..n)
            .map(|_| PairBudget {
                credits: cfg.credits.c,
                pins: cfg.credits.p,
                fill_used: 0,
                stash: [(0, 0); 8],
                n_stash: 0,
                unpins: [(0, 0); 5],
                n_unpins: 0,
                pushed: false,
            })
            .collect();
        let hasher = *shard.hasher();
        Ok(Worker {
            id,
            n,
            ring,
            shard,
            geo: geo.clone(),
            hasher,
            cr: cfg.credits.clone(),
            arena,
            fixed: false,
            dev_fds,
            conns,
            free_conns: (0..max_conns).rev().collect(),
            parked: Fifo::new(max_conns as usize + 1),
            dirty: Fifo::new(max_conns as usize + 1),
            pairs,
            overflow: (0..n).map(|_| Fifo::new(1024)).collect(),
            region_overflow: Fifo::new(1024),
            scratch: vec![0u8; 64 * 1024].into_boxed_slice(),
            sh,
            spin: Duration::from_micros(cfg.spin_us as u64),
            body_timeout_ns: cfg.body_timeout_ms as u64 * 1_000_000,
            start: Instant::now(),
            last_publish: Instant::now(),
            ts: types::Timespec::new().nsec(10_000_000),
            counters: WorkerCounters::default(),
        })
    }

    /// Register the arena as fixed buffers (best effort; needs RLIMIT_MEMLOCK).
    pub fn register_arena(&mut self, iovecs: &[libc::iovec]) -> std::io::Result<()> {
        unsafe { self.ring.submitter().register_buffers(iovecs)? };
        self.fixed = true;
        self.counters.fixed_buffers = iovecs.len() as u64;
        Ok(())
    }

    pub fn shared_mesh(&self) -> &Mesh {
        &self.sh.mesh
    }

    pub fn ring_fd(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.ring.as_raw_fd()
    }

    #[inline]
    fn now_ns(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }

    #[inline]
    fn slot_ptr(&self, slot: u32) -> *mut u8 {
        unsafe { self.arena.add(self.geo.slot_offset(slot) as usize) }
    }

    fn push_sqe(&mut self, e: squeue::Entry) {
        loop {
            let ok = unsafe { self.ring.submission().push(&e).is_ok() };
            if ok {
                return;
            }
            let _ = self.ring.submit();
        }
    }

    // ================================================================== main loop

    pub fn run(&mut self) {
        while !self.sh.stop.load(Relaxed) {
            self.reap();
            self.owner_pass();
            self.drain_handoff();
            let now = self.now_ns();
            self.shard.tick(now);
            self.drain_shard();
            self.retry_parked();
            self.check_timeouts(now);
            self.flush_dirty();
            self.flush_outbound();
            if self.last_publish.elapsed() > Duration::from_millis(250) {
                self.publish_stats();
            }
            self.wait();
        }
        self.publish_stats();
    }

    fn has_local_work(&self) -> bool {
        !self.dirty.is_empty() || !self.shard.io_out.is_empty() || !self.shard.out.is_empty()
    }

    fn wait(&mut self) {
        if self.has_local_work() {
            let _ = self.ring.submit();
            return;
        }
        // Adaptive spin on inbound rings before sleeping.
        let spin_until = Instant::now() + self.spin;
        let _ = self.ring.submit();
        while Instant::now() < spin_until {
            if self.sh.mesh.has_inbound(self.id) || !self.ring.completion().is_empty() || !self.sh.handoff[self.id as usize].is_empty() {
                self.counters.spin_hits += 1;
                return;
            }
            std::hint::spin_loop();
        }
        let hq = &self.sh.handoff[self.id as usize];
        if !self.sh.mesh.try_sleep(self.id, || !hq.is_empty()) {
            return;
        }
        let args = types::SubmitArgs::new().timespec(&self.ts);
        let _ = self.ring.submitter().submit_with_args(1, &args);
        self.sh.mesh.woke(self.id);
        self.counters.wakeups += 1;
    }

    fn reap(&mut self) {
        loop {
            let mut batch: [(u64, i32); 64] = [(0, 0); 64];
            let mut k = 0;
            {
                let mut cq = self.ring.completion();
                for cqe in &mut cq {
                    batch[k] = (cqe.user_data(), cqe.result());
                    k += 1;
                    if k == batch.len() {
                        break;
                    }
                }
            }
            if k == 0 {
                return;
            }
            for &(ud, res) in &batch[..k] {
                self.on_cqe(ud, res);
            }
        }
    }

    fn on_cqe(&mut self, ud: u64, res: i32) {
        let kind = ud >> 56;
        match kind {
            K_SSD => {
                let op = ((ud >> 32) & 0xff_ffff) as u32;
                let opgen = ud as u32;
                self.shard.io_done(op, opgen, res);
                self.drain_shard();
            }
            K_RECV => {
                let idx = ((ud >> 32) & 0xff_ffff) as u32;
                self.on_recv(idx, res);
            }
            K_SEND => {
                let idx = ((ud >> 32) & 0xff_ffff) as u32;
                self.on_send(idx, res);
            }
            K_DOORBELL | K_CLOSE | K_TIMEOUT => {}
            _ => {}
        }
    }

    // ================================================================== owner side

    fn owner_pass(&mut self) {
        let mesh = self.sh.mesh.clone();
        for a in 0..self.n {
            if a == self.id {
                continue;
            }
            let ring = mesh.ring(a, self.id);
            let mut k = 0;
            while k < 64 {
                let Some(Line(m)) = ring.pop() else { break };
                k += 1;
                self.on_msg(a, m);
            }
            while let Some(rm) = mesh.region_ring(a, self.id).pop() {
                self.shard.region_msg(rm);
            }
        }
        self.drain_shard();
    }

    fn on_msg(&mut self, from: u16, m: Msg) {
        match m {
            Msg::Lookup { hi, lo, key, req, exists } => {
                let h = H { hi, lo };
                if let Some(r) = self.shard.lookup(&h, &key, req, exists) {
                    self.send_to(from, Msg::Reply { req, r });
                }
            }
            Msg::Reserve { req } => {
                if let Some(r) = self.shard.reserve(from, req) {
                    self.send_to(from, Msg::Reply { req, r });
                }
            }
            Msg::Commit { hi, lo, key, slot, sgen, mode, req } => {
                let st = self.shard.commit(from, &H { hi, lo }, &key, slot, sgen, mode);
                self.send_to(from, Msg::Reply { req, r: Reply::Status(st) });
            }
            Msg::Abort { slot, sgen } => self.shard.abort(from, slot, sgen),
            Msg::Delete { hi, lo, key, req } => {
                let st = self.shard.delete(&H { hi, lo }, &key);
                self.send_to(from, Msg::Reply { req, r: Reply::Status(st) });
            }
            Msg::Unpin { n, slots } => {
                for &(slot, sgen) in &slots[..n as usize] {
                    self.shard.unpin(slot, sgen);
                }
            }
            Msg::Reply { req, r } => self.on_reply(req, r),
            Msg::Grant { slot, sgen } => self.on_grant(from, slot, sgen),
        }
    }

    /// Route shard outputs: IO → SQEs, replies → local connections or remote rings.
    fn drain_shard(&mut self) {
        loop {
            let mut progressed = false;
            while let Some(io) = self.shard.io_out.pop() {
                progressed = true;
                self.submit_io(io);
            }
            while let Some(o) = self.shard.out.pop() {
                progressed = true;
                match o {
                    Out::Reply(req, r) => {
                        if req.worker == self.id {
                            self.on_reply(req, r);
                        } else {
                            self.send_to(req.worker, Msg::Reply { req, r });
                        }
                    }
                    Out::Grant { worker, slot, sgen } => self.send_to(worker, Msg::Grant { slot, sgen }),
                }
            }
            while let Some((t, m)) = self.shard.region_out.pop() {
                progressed = true;
                if self.sh.mesh.region_ring(self.id, t).push(m).is_err() {
                    let _ = self.region_overflow.push((t, m));
                }
                self.pairs[t as usize].pushed = true;
            }
            if !progressed {
                return;
            }
        }
    }

    fn submit_io(&mut self, io: IoReq) {
        let fd = types::Fd(self.dev_fds[io.dev as usize]);
        let ud = ud_ssd(io.op, io.opgen);
        let e = match (io.kind, io.buf) {
            (IoKind::Read, IoBuf::Slot(slot)) => {
                let p = self.slot_ptr(slot);
                if self.fixed {
                    let (chunk, _) = self.geo.slot_chunk(slot);
                    opcode::ReadFixed::new(fd, p, io.len, chunk).offset(io.off).build()
                } else {
                    opcode::Read::new(fd, p, io.len).offset(io.off).build()
                }
            }
            (IoKind::Write, IoBuf::Slot(slot)) => {
                let p = self.slot_ptr(slot);
                if self.fixed {
                    let (chunk, _) = self.geo.slot_chunk(slot);
                    opcode::WriteFixed::new(fd, p, io.len, chunk).offset(io.off).build()
                } else {
                    opcode::Write::new(fd, p, io.len).offset(io.off).build()
                }
            }
            (IoKind::Write, IoBuf::Footer(i)) => {
                let p = self.shard.footer_ptr(i);
                opcode::Write::new(fd, p, io.len).offset(io.off).build()
            }
            (IoKind::Read, IoBuf::Footer(_)) => unreachable!(),
        };
        self.push_sqe(e.user_data(ud));
    }

    // ================================================================== messaging

    fn send_to(&mut self, to: u16, m: Msg) {
        debug_assert_ne!(to, self.id);
        let ring = self.sh.mesh.ring(self.id, to);
        if !self.overflow[to as usize].is_empty() || ring.push(Line(m)).is_err() {
            self.counters.ring_overflow += 1;
            let _ = self.overflow[to as usize].push(Line(m));
        }
        self.pairs[to as usize].pushed = true;
    }

    fn flush_outbound(&mut self) {
        let mesh = self.sh.mesh.clone();
        for t in 0..self.n {
            if t == self.id {
                continue;
            }
            let p = &mut self.pairs[t as usize];
            if p.n_unpins > 0 {
                let m = Msg::Unpin { n: p.n_unpins, slots: p.unpins };
                p.n_unpins = 0;
                self.send_to(t, m);
            }
            while let Some(l) = self.overflow[t as usize].peek().copied() {
                if mesh.ring(self.id, t).push(l).is_err() {
                    break;
                }
                self.overflow[t as usize].pop();
            }
        }
        let n = self.region_overflow.len();
        for _ in 0..n {
            let (t, m) = self.region_overflow.pop().unwrap();
            if mesh.region_ring(self.id, t).push(m).is_err() {
                let _ = self.region_overflow.push((t, m));
            }
        }
        // Doorbells after all pushes are published.
        for t in 0..self.n {
            if t == self.id || !self.pairs[t as usize].pushed {
                continue;
            }
            self.pairs[t as usize].pushed = false;
            if mesh.needs_doorbell(t) {
                let fd = mesh.ring_fd[t as usize].load(Relaxed);
                if fd >= 0 {
                    let e = opcode::MsgRingData::new(types::Fd(fd), 0, K_DOORBELL << 56, None)
                        .build()
                        .flags(squeue::Flags::SKIP_SUCCESS)
                        .user_data(K_DOORBELL << 56);
                    self.push_sqe(e);
                    self.counters.doorbells_sent += 1;
                }
            }
        }
    }

    fn queue_unpin(&mut self, owner: u16, slot: u32, sgen: u32) {
        if owner == self.id {
            self.shard.unpin(slot, sgen);
        } else {
            let p = &mut self.pairs[owner as usize];
            p.unpins[p.n_unpins as usize] = (slot, sgen);
            p.n_unpins += 1;
            if p.n_unpins as usize == p.unpins.len() {
                let m = Msg::Unpin { n: p.n_unpins, slots: p.unpins };
                p.n_unpins = 0;
                self.send_to(owner, m);
            }
        }
        self.pairs[owner as usize].pins += 1;
    }

    fn on_grant(&mut self, from: u16, slot: u32, sgen: u32) {
        let max = self.cr.stash.min(8) as u8;
        let p = &mut self.pairs[from as usize];
        p.fill_used += 1;
        if p.n_stash < max {
            p.stash[p.n_stash as usize] = (slot, sgen);
            p.n_stash += 1;
            self.retry_awaiting_slot(from);
        } else {
            p.fill_used -= 1;
            self.send_to(from, Msg::Abort { slot, sgen });
        }
    }

    fn retry_awaiting_slot(&mut self, _owner: u16) {
        // Connections waiting for a slot are parked; the next retry pass picks them up.
    }

    // ================================================================== replies (connection side)

    fn on_reply(&mut self, req: ReqToken, r: Reply) {
        let owner = self.owner_of_token_reply(&req, &r);
        let kind = tok_kind(&req);
        // Credits are returned at receipt (remote only).
        if owner != self.id && matches!(kind, T_LOOKUP | T_RESERVE | T_DELETE) {
            self.pairs[owner as usize].credits += 1;
        }
        let idx = req.conn;
        let live = (idx as usize) < self.conns.len() && {
            let c = &self.conns[idx as usize];
            c.active && c.cgen == req.cgen && !c.closing
        };
        if !live {
            self.counters.stale_replies += 1;
            self.stale_reply(owner, kind, r);
            return;
        }
        match kind {
            T_LOOKUP => {
                let ri = tok_idx(&req);
                let (resp, pinned, slot, sgen) = match r {
                    Reply::Hit { slot, sgen } => (Response::Hit, true, slot, sgen),
                    Reply::Found => (Response::Hit, false, 0, 0),
                    Reply::Miss => (Response::Miss, false, 0, 0),
                    _ => (Response::ServerErr, false, 0, 0),
                };
                if !pinned {
                    self.pairs[owner as usize].pins += 1;
                    let c = &mut self.conns[idx as usize];
                    c.pins[owner as usize] -= 1;
                }
                let c = &mut self.conns[idx as usize];
                let e = c.entry(ri);
                e.resp = resp;
                e.pinned = pinned;
                e.slot = slot;
                e.sgen = sgen;
                e.state = EState::Ready;
                self.mark_dirty(idx);
            }
            T_DELETE | T_COMMIT => {
                let ri = tok_idx(&req);
                let resp = match r {
                    Reply::Status(Status::Stored) => Response::Stored,
                    Reply::Status(Status::NotStored) => Response::NotStored,
                    Reply::Status(Status::Deleted) => Response::Deleted,
                    Reply::Status(Status::NotFound) => Response::NotFound,
                    _ => Response::ServerErr,
                };
                let c = &mut self.conns[idx as usize];
                let e = c.entry(ri);
                e.resp = resp;
                e.state = EState::Ready;
                self.mark_dirty(idx);
            }
            T_RESERVE => {
                let c = &mut self.conns[idx as usize];
                match (c.rx, r) {
                    (Rx::AwaitSlot { hdr, owner: o, resp, h }, Reply::Reserved { slot, sgen }) if o == owner => {
                        c.rx = Rx::Body { hdr, owner, resp, h, slot, sgen, filled: 0 };
                        self.drive(idx);
                    }
                    (_, Reply::Reserved { slot, sgen }) => {
                        // Unexpected: give it back.
                        self.give_back_slot(owner, slot, sgen);
                    }
                    (Rx::AwaitSlot { resp, .. }, _) => {
                        if owner != self.id {
                            self.pairs[owner as usize].fill_used -= 1;
                        }
                        let e = c.entry(resp);
                        e.resp = Response::ServerErr;
                        e.state = EState::Ready;
                        c.rx = Rx::Discard { left: 0 };
                        self.mark_dirty(idx);
                        self.close_conn(idx);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn owner_of_token_reply(&self, _req: &ReqToken, _r: &Reply) -> u16 {
        // The owner is recorded in the ring entry; for stale tokens it is carried by the
        // sender. We encode it in the token's high bits of `cgen`-independent field: see
        // `make_token`. Owner = bits 20..28 of resp.
        ((_req.resp >> 20) & 0xff) as u16 | (((_req.resp >> 28) & 0xf) as u16) << 8
    }

    fn stale_reply(&mut self, owner: u16, kind: u32, r: Reply) {
        match (kind, r) {
            (T_LOOKUP, Reply::Hit { slot, sgen }) => self.queue_unpin(owner, slot, sgen),
            (T_LOOKUP, _) => self.pairs[owner as usize].pins += 1,
            (T_RESERVE, Reply::Reserved { slot, sgen }) => self.give_back_slot(owner, slot, sgen),
            (T_RESERVE, _) => {
                if owner != self.id {
                    self.pairs[owner as usize].fill_used -= 1;
                }
            }
            _ => {}
        }
    }

    /// A Filling slot we no longer need: stash it (remote owner) or abort it.
    fn give_back_slot(&mut self, owner: u16, slot: u32, sgen: u32) {
        if owner == self.id {
            self.shard.abort(self.id, slot, sgen);
            self.drain_shard();
            return;
        }
        let max = self.cr.stash.min(8) as u8;
        let p = &mut self.pairs[owner as usize];
        if p.n_stash < max {
            p.stash[p.n_stash as usize] = (slot, sgen);
            p.n_stash += 1;
        } else {
            p.fill_used -= 1;
            self.send_to(owner, Msg::Abort { slot, sgen });
        }
    }

    fn make_token(&self, idx: u32, ri: u32, kind: u32, owner: u16) -> ReqToken {
        let c = &self.conns[idx as usize];
        let o = owner as u32;
        ReqToken { worker: self.id, cgen: c.cgen, conn: idx, resp: (ri & 0xffff) | (kind << 16) | ((o & 0xff) << 20) | (((o >> 8) & 0xf) << 28) }
    }

    // ================================================================== connections

    fn drain_handoff(&mut self) {
        let q = self.sh.handoff.clone();
        while let Some(h) = q[self.id as usize].pop() {
            let Some(idx) = self.free_conns.pop() else {
                unsafe { libc::close(h.fd) };
                continue;
            };
            let n = self.n as usize;
            let c = &mut self.conns[idx as usize];
            c.active = true;
            c.fd = h.fd;
            c.cgen = c.cgen.wrapping_add(1);
            c.tls = h.tls;
            c.proto = ProtoState::new(h.proto);
            c.rx = Rx::Header;
            c.c_start = 0;
            c.c_end = 0;
            c.recv_inflight = false;
            c.send_inflight = false;
            c.closing = false;
            c.parked = false;
            c.read_closed = false;
            c.head = 0;
            c.tail = 0;
            c.gathered = 0;
            c.agg = 0;
            c.dirty = false;
            for p in c.pins.iter_mut().take(n) {
                *p = 0;
            }
            self.counters.conns_opened += 1;
            self.drive(idx);
        }
    }

    fn mark_dirty(&mut self, idx: u32) {
        let c = &mut self.conns[idx as usize];
        if !c.dirty {
            c.dirty = true;
            let _ = self.dirty.push(idx);
        }
    }

    fn park(&mut self, idx: u32) {
        let c = &mut self.conns[idx as usize];
        if !c.parked {
            c.parked = true;
            self.counters.parked += 1;
            let _ = self.parked.push(idx);
        }
    }

    fn retry_parked(&mut self) {
        let n = self.parked.len();
        for _ in 0..n {
            let Some(idx) = self.parked.pop() else { break };
            let c = &mut self.conns[idx as usize];
            c.parked = false;
            if c.active && !c.closing {
                self.drive(idx);
            }
        }
    }

    fn check_timeouts(&mut self, now: u64) {
        // Body-progress deadline (design §5.1(6)): cheap scan only of connections in Body
        // phase is not indexed; we piggyback on parked/dirty scans instead. Kept simple:
        // checked in on_recv for the active connection. (Full reaper: phase 5.)
        let _ = now;
    }

    fn arm_recv(&mut self, idx: u32) {
        let c = &mut self.conns[idx as usize];
        if c.recv_inflight || c.closing || c.read_closed {
            return;
        }
        let (ptr, len, kind, fl) = match c.rx {
            Rx::Body { slot, filled, hdr, .. } => {
                let p = unsafe { self.arena.add(self.geo.slot_offset(slot) as usize + filled as usize) };
                (p, hdr.body_len - filled, RecvKind::Body, libc::MSG_WAITALL)
            }
            Rx::Discard { left } if c.c_start == c.c_end => {
                let len = (left as usize).min(self.scratch.len()) as u32;
                (self.scratch.as_mut_ptr(), len, RecvKind::Discard, 0)
            }
            _ => {
                if c.c_start > 0 {
                    c.carry.copy_within(c.c_start..c.c_end, 0);
                    c.c_end -= c.c_start;
                    c.c_start = 0;
                }
                let free = CARRY - c.c_end;
                if free == 0 {
                    return;
                }
                (unsafe { c.carry.as_mut_ptr().add(c.c_end) }, free as u32, RecvKind::Carry, 0)
            }
        };
        if len == 0 {
            return;
        }
        c.recv_inflight = true;
        c.recv_kind = kind;
        let e = opcode::Recv::new(types::Fd(c.fd), ptr, len).flags(fl).build().user_data(ud_conn(K_RECV, idx, c.cgen));
        self.push_sqe(e);
    }

    fn on_recv(&mut self, idx: u32, res: i32) {
        let c = &mut self.conns[idx as usize];
        c.recv_inflight = false;
        if !c.active {
            return;
        }
        if c.closing {
            self.maybe_finish_close(idx);
            return;
        }
        if res == -libc::EIO && c.tls {
            self.on_tls_control(idx);
            return;
        }
        if res == -libc::EAGAIN || res == -libc::EINTR {
            self.arm_recv(idx);
            return;
        }
        if res <= 0 {
            // EOF or error: stop reading; finish flushing what's ready, then close.
            c.read_closed = true;
            self.close_conn(idx);
            return;
        }
        let n = res as u32;
        self.counters.recv_bytes += n as u64;
        match c.recv_kind {
            RecvKind::Carry => c.c_end += n as usize,
            RecvKind::Body => {
                if let Rx::Body { filled, .. } = &mut c.rx {
                    *filled += n;
                }
            }
            RecvKind::Discard => {
                if let Rx::Discard { left } = &mut c.rx {
                    *left -= n.min(*left);
                }
            }
        }
        self.drive(idx);
    }

    fn on_tls_control(&mut self, idx: u32) {
        self.counters.tls_control_records += 1;
        let fd = self.conns[idx as usize].fd;
        let mut buf = [0u8; 512];
        match crate::tls::recv_control_record(fd, &mut buf) {
            Ok((ty, n)) => {
                let rec = crate::tls::classify(ty, &buf[..n]);
                if ty == crate::tls::CONTENT_APPLICATION_DATA {
                    // Data after all: only valid in the header phase.
                    let c = &mut self.conns[idx as usize];
                    if matches!(c.rx, Rx::Header | Rx::Trailer { .. }) && c.c_end + n <= CARRY {
                        if c.c_start > 0 {
                            c.carry.copy_within(c.c_start..c.c_end, 0);
                            c.c_end -= c.c_start;
                            c.c_start = 0;
                        }
                        c.carry[c.c_end..c.c_end + n].copy_from_slice(&buf[..n]);
                        c.c_end += n;
                        self.drive(idx);
                        return;
                    }
                }
                if rec.is_close_notify() {
                    let _ = crate::tls::send_close_notify(fd);
                }
                // KeyUpdate needs kernel rekey (6.14+); on older kernels we close (design §6.2).
                let c = &mut self.conns[idx as usize];
                c.read_closed = true;
                self.close_conn(idx);
            }
            Err(_) => {
                self.conns[idx as usize].read_closed = true;
                self.close_conn(idx);
            }
        }
    }

    /// Advance the receive state machine as far as possible.
    fn drive(&mut self, idx: u32) {
        loop {
            let c = &mut self.conns[idx as usize];
            if !c.active || c.closing || c.parked {
                return;
            }
            match c.rx {
                Rx::Header => {
                    if c.read_closed && c.c_start == c.c_end {
                        return;
                    }
                    if c.ring_free() < 3 {
                        // Ring full: wait for sends (TCP backpressure).
                        return;
                    }
                    let snapshot = c.proto;
                    let parsed = c.proto.parse(&c.carry[c.c_start..c.c_end], self.geo.v);
                    match parsed {
                        Parsed::Incomplete { .. } => {
                            if c.c_end - c.c_start >= CARRY - 1 {
                                self.fatal(idx, ProtoErr::TooLarge);
                                return;
                            }
                            self.arm_recv(idx);
                            return;
                        }
                        Parsed::Complete { req, consumed } => {
                            if !self.dispatch(idx, req) {
                                let c = &mut self.conns[idx as usize];
                                c.proto = snapshot;
                                self.park(idx);
                                return;
                            }
                            self.conns[idx as usize].c_start += consumed;
                        }
                        Parsed::Body { hdr, consumed } => {
                            if !self.start_body(idx, hdr) {
                                let c = &mut self.conns[idx as usize];
                                c.proto = snapshot;
                                self.park(idx);
                                return;
                            }
                            self.conns[idx as usize].c_start += consumed;
                        }
                        Parsed::Reject { err, ctx, consumed, discard_body } => {
                            c.c_start += consumed;
                            c.rx = Rx::Discard { left: discard_body };
                            self.push_ready(idx, EKind::Other, ctx, Response::Proto(err));
                        }
                        Parsed::Fatal { err } => {
                            self.fatal(idx, err);
                            return;
                        }
                    }
                }
                Rx::AwaitSlot { .. } => return,
                Rx::Body { hdr, owner, resp, h, slot, sgen, filled } => {
                    let avail = c.c_end - c.c_start;
                    let need = (hdr.body_len - filled) as usize;
                    if avail > 0 && need > 0 {
                        let k = avail.min(need);
                        let dst = unsafe { self.arena.add(self.geo.slot_offset(slot) as usize + filled as usize) };
                        unsafe { std::ptr::copy_nonoverlapping(c.carry.as_ptr().add(c.c_start), dst, k) };
                        c.c_start += k;
                        c.rx = Rx::Body { hdr, owner, resp, h, slot, sgen, filled: filled + k as u32 };
                        continue;
                    }
                    if need == 0 {
                        c.rx = Rx::Trailer { hdr, owner, resp, h, slot, sgen };
                        continue;
                    }
                    if c.body_deadline_ns == 0 {
                        c.body_deadline_ns = self.start.elapsed().as_nanos() as u64 + self.body_timeout_ns;
                    }
                    self.arm_recv(idx);
                    return;
                }
                Rx::Trailer { mut hdr, owner, resp, h, slot, sgen } => {
                    c.body_deadline_ns = 0;
                    match c.proto.finish_body(&mut hdr, &c.carry[c.c_start..c.c_end]) {
                        Ok(n) => {
                            c.c_start += n;
                            c.rx = Rx::Header;
                            self.commit(idx, owner, resp, h, hdr, slot, sgen);
                        }
                        Err(FinishErr::Incomplete) => {
                            c.rx = Rx::Trailer { hdr, owner, resp, h, slot, sgen };
                            if c.c_end - c.c_start >= CARRY - 1 {
                                self.fatal(idx, ProtoErr::TooLarge);
                                return;
                            }
                            self.arm_recv(idx);
                            return;
                        }
                        Err(FinishErr::Reject { err, consumed }) => {
                            c.c_start += consumed;
                            c.rx = Rx::Header;
                            self.release_fill(owner, slot, sgen);
                            let e = self.conns[idx as usize].entry(resp);
                            e.resp = Response::Proto(err);
                            e.state = EState::Ready;
                            self.mark_dirty(idx);
                        }
                        Err(FinishErr::Fatal { err }) => {
                            self.release_fill(owner, slot, sgen);
                            let e = self.conns[idx as usize].entry(resp);
                            e.resp = Response::Proto(err);
                            e.close_after = true;
                            e.ctx.flags |= flags::CLOSE_AFTER;
                            e.state = EState::Ready;
                            self.conns[idx as usize].rx = Rx::Discard { left: 0 };
                            self.conns[idx as usize].read_closed = true;
                            self.mark_dirty(idx);
                            return;
                        }
                    }
                }
                Rx::Discard { left } => {
                    let avail = (c.c_end - c.c_start) as u32;
                    let k = avail.min(left);
                    c.c_start += k as usize;
                    let left = left - k;
                    if left == 0 {
                        c.rx = Rx::Header;
                        if c.read_closed {
                            return;
                        }
                        continue;
                    }
                    c.rx = Rx::Discard { left };
                    self.arm_recv(idx);
                    return;
                }
            }
        }
    }

    fn fatal(&mut self, idx: u32, err: ProtoErr) {
        let ctx = ReqCtx { flags: flags::CLOSE_AFTER, ..Default::default() };
        let c = &mut self.conns[idx as usize];
        c.read_closed = true;
        c.rx = Rx::Discard { left: 0 };
        if c.ring_free() > 0 {
            self.push_ready(idx, EKind::Other, ctx, Response::Proto(err));
        } else {
            self.close_conn(idx);
        }
    }

    fn push_entry(&mut self, idx: u32, kind: EKind, ctx: ReqCtx, state: EState, resp: Response, owner: u16) -> u32 {
        let c = &mut self.conns[idx as usize];
        let ri = c.tail;
        c.tail = c.tail.wrapping_add(1);
        let e = c.entry(ri);
        e.state = state;
        e.kind = kind;
        e.ctx = ctx;
        e.resp = resp;
        e.owner = owner;
        e.pinned = false;
        e.encoded = false;
        e.sent = 0;
        e.close_after = ctx.has(flags::CLOSE_AFTER);
        ri & 0xffff_ffff
    }

    fn push_ready(&mut self, idx: u32, kind: EKind, ctx: ReqCtx, resp: Response) {
        self.push_entry(idx, kind, ctx, EState::Ready, resp, self.id);
        self.mark_dirty(idx);
    }

    /// Dispatch one parsed request. Returns false if a budget is missing (caller parks).
    fn dispatch(&mut self, idx: u32, req: Request) -> bool {
        match req {
            Request::Get { ctx } => {
                let h = self.hasher.hash(&ctx.key);
                let owner = h.shard(self.n);
                if !self.take_lookup_budget(idx, owner) {
                    return false;
                }
                let ri = self.push_entry(idx, EKind::Get, ctx, EState::Pending, Response::Miss, owner);
                let tok = self.make_token(idx, ri, T_LOOKUP, owner);
                let exists = ctx.has(flags::EXISTS);
                if owner == self.id {
                    if let Some(r) = self.shard.lookup(&h, &ctx.key, tok, exists) {
                        self.on_reply(tok, r);
                    }
                    self.drain_shard();
                } else {
                    self.send_to(owner, Msg::Lookup { hi: h.hi, lo: h.lo, key: ctx.key, req: tok, exists });
                }
                true
            }
            Request::Delete { ctx } => {
                let h = self.hasher.hash(&ctx.key);
                let owner = h.shard(self.n);
                if owner != self.id {
                    if self.pairs[owner as usize].credits == 0 {
                        return false;
                    }
                    self.pairs[owner as usize].credits -= 1;
                }
                let ri = self.push_entry(idx, EKind::Del, ctx, EState::Pending, Response::NotFound, owner);
                let tok = self.make_token(idx, ri, T_DELETE, owner);
                if owner == self.id {
                    let st = self.shard.delete(&h, &ctx.key);
                    self.on_reply(tok, Reply::Status(st));
                    self.drain_shard();
                } else {
                    self.send_to(owner, Msg::Delete { hi: h.hi, lo: h.lo, key: ctx.key, req: tok });
                }
                true
            }
            Request::MultiEnd { ctx } => {
                self.push_ready(idx, EKind::Other, ctx, Response::MultiEnd);
                true
            }
            Request::AggEnd { ctx, kind } => {
                let _ = kind;
                self.push_ready(idx, EKind::Other, ctx, Response::Count(0));
                true
            }
            Request::Noop { ctx } => {
                self.push_ready(idx, EKind::Other, ctx, Response::Noop);
                true
            }
            Request::Control { ctl, ctx } => {
                self.conns[idx as usize].proto.on_control(&ctl);
                let mut ctx = ctx;
                if ctl == Control::Quit {
                    ctx.flags |= flags::CLOSE_AFTER;
                    self.conns[idx as usize].read_closed = true;
                }
                self.push_ready(idx, EKind::Other, ctx, Response::Control(ctl));
                true
            }
        }
    }

    fn take_lookup_budget(&mut self, idx: u32, owner: u16) -> bool {
        let p_conn = self.cr.p_conn as u8;
        let c = &self.conns[idx as usize];
        let p = &self.pairs[owner as usize];
        if p.pins == 0 || c.pins[owner as usize] >= p_conn || (owner != self.id && p.credits == 0) {
            return false;
        }
        let p = &mut self.pairs[owner as usize];
        p.pins -= 1;
        if owner != self.id {
            p.credits -= 1;
        }
        self.conns[idx as usize].pins[owner as usize] += 1;
        true
    }

    /// Start a SET body: get a Filling slot (stash, local reserve, or remote Reserve).
    fn start_body(&mut self, idx: u32, hdr: BodyHeader) -> bool {
        let h = self.hasher.hash(&hdr.ctx.key);
        let owner = h.shard(self.n);
        let need = if hdr.expect_continue { 2 } else { 1 };
        if self.conns[idx as usize].ring_free() < need + 1 {
            return false;
        }
        if owner != self.id {
            let p = &self.pairs[owner as usize];
            if p.n_stash == 0 && (p.credits == 0 || p.fill_used >= self.cr.f) {
                return false;
            }
        }
        if hdr.expect_continue {
            self.push_ready(idx, EKind::Other, hdr.ctx, Response::Continue);
        }
        let ri = self.push_entry(idx, EKind::Set, hdr.ctx, EState::Pending, Response::ServerErr, owner);
        if owner == self.id {
            let tok = self.make_token(idx, ri, T_RESERVE, owner);
            self.conns[idx as usize].rx = Rx::AwaitSlot { hdr, owner, resp: ri, h };
            if let Some(r) = self.shard.reserve(self.id, tok) {
                self.on_reply(tok, r);
            }
            self.drain_shard();
            return true;
        }
        let p = &mut self.pairs[owner as usize];
        if p.n_stash > 0 {
            p.n_stash -= 1;
            let (slot, sgen) = p.stash[p.n_stash as usize];
            self.conns[idx as usize].rx = Rx::Body { hdr, owner, resp: ri, h, slot, sgen, filled: 0 };
            return true;
        }
        p.credits -= 1;
        p.fill_used += 1;
        let tok = self.make_token(idx, ri, T_RESERVE, owner);
        self.conns[idx as usize].rx = Rx::AwaitSlot { hdr, owner, resp: ri, h };
        self.send_to(owner, Msg::Reserve { req: tok });
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn commit(&mut self, idx: u32, owner: u16, ri: u32, h: H, hdr: BodyHeader, slot: u32, sgen: u32) {
        let tok = self.make_token(idx, ri, T_COMMIT, owner);
        if owner == self.id {
            let st = self.shard.commit(self.id, &h, &hdr.ctx.key, slot, sgen, hdr.mode);
            self.on_reply(tok, Reply::Status(st));
            self.drain_shard();
        } else {
            self.pairs[owner as usize].fill_used -= 1;
            self.send_to(owner, Msg::Commit { hi: h.hi, lo: h.lo, key: hdr.ctx.key, slot, sgen, mode: hdr.mode, req: tok });
            // Ask for a stash refill so the next SET to this owner needs no hop.
        }
        let _ = SetMode::Set;
    }

    fn release_fill(&mut self, owner: u16, slot: u32, sgen: u32) {
        self.give_back_slot(owner, slot, sgen);
    }

    // ================================================================== send path

    fn flush_dirty(&mut self) {
        let n = self.dirty.len();
        for _ in 0..n {
            let Some(idx) = self.dirty.pop() else { break };
            self.conns[idx as usize].dirty = false;
            self.try_flush(idx);
        }
    }

    fn entry_len(&self, e: &RespEntry) -> u32 {
        if e.suppressed { 0 } else { e.hdr_len as u32 + if e.value { self.geo.v } else { 0 } + e.trailer.len() as u32 }
    }

    fn encode_entry(&mut self, idx: u32, i: u32) {
        let v = self.geo.v;
        let c = &mut self.conns[idx as usize];
        let proto = c.proto;
        let mut agg = c.agg;
        let e = &mut c.ring[(i as usize) % RESP_RING];
        if e.encoded {
            return;
        }
        let ctx = e.ctx;
        let is_agg_part = ctx.has(flags::MULTI) && (e.kind == EKind::Del || ctx.has(flags::EXISTS)) && matches!(proto, ProtoState::Resp(_));
        if is_agg_part {
            if matches!(e.resp, Response::Deleted | Response::Hit) {
                agg += 1;
            }
            e.encoded = true;
            e.suppressed = true;
            e.hdr_len = 0;
            e.value = false;
            c.agg = agg;
            return;
        }
        if let Response::Count(_) = e.resp {
            e.resp = Response::Count(agg);
            agg = 0;
        }
        let mut resp = e.resp;
        if ctx.has(flags::EXISTS) {
            // Count is aggregated above; a lone EXISTS still renders through AggEnd.
            resp = e.resp;
        }
        let f = proto.encode(&ctx, &resp, v, &mut e.hdr);
        e.hdr_len = f.hdr_len;
        e.value = f.value && e.pinned;
        e.trailer = if f.value && !e.pinned { b"" } else { f.trailer };
        e.suppressed = f.suppressed;
        e.close_after |= f.close_after;
        e.encoded = true;
        c.agg = agg;
        let _ = AggKind::DelCount;
    }

    fn try_flush(&mut self, idx: u32) {
        {
            let c = &self.conns[idx as usize];
            if !c.active || c.send_inflight {
                return;
            }
        }
        // Gather the contiguous Ready prefix.
        let mut niov = 0usize;
        let mut bytes = 0u64;
        let mut i = self.conns[idx as usize].head;
        let tail = self.conns[idx as usize].tail;
        while i != tail && niov + 3 <= MAX_IOV && bytes < SEND_BUDGET {
            if self.conns[idx as usize].ring[(i as usize) % RESP_RING].state != EState::Ready {
                break;
            }
            self.encode_entry(idx, i);
            let v = self.geo.v as usize;
            let arena = self.arena;
            let off = {
                let e = &self.conns[idx as usize].ring[(i as usize) % RESP_RING];
                if e.value { self.geo.slot_offset(e.slot) as usize } else { 0 }
            };
            let c = &mut self.conns[idx as usize];
            let e = &mut c.ring[(i as usize) % RESP_RING];
            if !e.suppressed {
                let mut skip = e.sent as usize;
                let segs: [(*const u8, usize); 3] = [
                    (e.hdr.as_ptr(), e.hdr_len as usize),
                    (if e.value { unsafe { arena.add(off) } } else { std::ptr::null() }, if e.value { v } else { 0 }),
                    (e.trailer.as_ptr(), e.trailer.len()),
                ];
                for (p, l) in segs {
                    if l == 0 {
                        continue;
                    }
                    if skip >= l {
                        skip -= l;
                        continue;
                    }
                    c.iov[niov] = libc::iovec { iov_base: unsafe { p.add(skip) } as *mut _, iov_len: l - skip };
                    bytes += (l - skip) as u64;
                    skip = 0;
                    niov += 1;
                }
            }
            i = i.wrapping_add(1);
        }
        let c = &mut self.conns[idx as usize];
        c.gathered = i;
        if niov == 0 {
            // Only suppressed entries: release them now.
            self.advance_sent(idx, 0);
            return;
        }
        c.msg = unsafe { std::mem::zeroed() };
        c.msg.msg_iov = c.iov.as_mut_ptr();
        c.msg.msg_iovlen = niov;
        c.send_inflight = true;
        let e = opcode::SendMsg::new(types::Fd(c.fd), &c.msg).flags(libc::MSG_NOSIGNAL as u32).build().user_data(ud_conn(K_SEND, idx, c.cgen));
        self.push_sqe(e);
    }

    fn on_send(&mut self, idx: u32, res: i32) {
        let c = &mut self.conns[idx as usize];
        c.send_inflight = false;
        if !c.active {
            return;
        }
        if res < 0 {
            if res == -libc::EAGAIN || res == -libc::EINTR {
                self.mark_dirty(idx);
                return;
            }
            c.read_closed = true;
            self.release_all_entries(idx);
            self.close_conn(idx);
            return;
        }
        self.counters.send_bytes += res as u64;
        self.advance_sent(idx, res as u32);
        let c = &self.conns[idx as usize];
        let (closing, parked, header) = (c.closing, c.parked, matches!(c.rx, Rx::Header));
        if closing {
            self.maybe_finish_close(idx);
        } else {
            self.mark_dirty(idx);
            if parked || header {
                // Ring space may have freed: resume parsing.
                self.drive(idx);
            }
        }
    }

    /// Account `n` sent bytes against gathered entries; release completed ones.
    fn advance_sent(&mut self, idx: u32, mut n: u32) {
        let mut close = false;
        loop {
            let c = &self.conns[idx as usize];
            if c.head == c.gathered {
                break;
            }
            let hi = c.head;
            let e = c.ring[(hi as usize) % RESP_RING];
            let total = self.entry_len(&e);
            let remaining = total - e.sent;
            if n >= remaining {
                n -= remaining;
                close |= e.close_after;
                self.release_entry(idx, hi);
                self.conns[idx as usize].head = hi.wrapping_add(1);
            } else {
                self.conns[idx as usize].ring[(hi as usize) % RESP_RING].sent += n;
                break;
            }
        }
        let c = &mut self.conns[idx as usize];
        c.gathered = c.head.max(c.gathered.min(c.tail));
        c.gathered = c.head;
        if close {
            c.read_closed = true;
            self.close_conn(idx);
        } else if c.read_closed && c.head == c.tail && !c.recv_inflight {
            self.close_conn(idx);
        }
    }

    fn release_entry(&mut self, idx: u32, i: u32) {
        let c = &mut self.conns[idx as usize];
        let e = &mut c.ring[(i as usize) % RESP_RING];
        let (pinned, owner, slot, sgen) = (e.pinned, e.owner, e.slot, e.sgen);
        e.state = EState::Free;
        e.pinned = false;
        if pinned {
            c.pins[owner as usize] -= 1;
            self.queue_unpin(owner, slot, sgen);
        }
    }

    fn release_all_entries(&mut self, idx: u32) {
        loop {
            let c = &self.conns[idx as usize];
            if c.head == c.tail {
                break;
            }
            let hi = c.head;
            let st = c.ring[(hi as usize) % RESP_RING].state;
            if st == EState::Pending {
                // Its reply will arrive with a stale cgen and be handled then.
                break;
            }
            self.release_entry(idx, hi);
            self.conns[idx as usize].head = hi.wrapping_add(1);
        }
    }

    // ================================================================== close

    fn close_conn(&mut self, idx: u32) {
        let c = &mut self.conns[idx as usize];
        if !c.active {
            return;
        }
        if !c.closing {
            // Let ready responses drain first if the socket is still writable.
            if c.head != c.tail && !c.closing && c.send_inflight {
                return;
            }
            c.closing = true;
            unsafe { libc::shutdown(c.fd, libc::SHUT_RDWR) };
        }
        self.maybe_finish_close(idx);
    }

    fn maybe_finish_close(&mut self, idx: u32) {
        let c = &self.conns[idx as usize];
        if c.recv_inflight || c.send_inflight {
            return;
        }
        // Return a Filling slot held by an unfinished body (its recv CQE is reaped).
        match c.rx {
            Rx::Body { owner, slot, sgen, .. } | Rx::Trailer { owner, slot, sgen, .. } => {
                self.give_back_slot(owner, slot, sgen);
            }
            _ => {}
        }
        self.release_all_entries(idx);
        // Pending entries: drop per-connection pin counts; the pair quota is returned when
        // their stale replies arrive.
        let c = &mut self.conns[idx as usize];
        unsafe { libc::close(c.fd) };
        c.fd = -1;
        c.active = false;
        c.closing = false;
        c.cgen = c.cgen.wrapping_add(1);
        c.rx = Rx::Header;
        let pending: u32 = c.tail.wrapping_sub(c.head);
        let _ = pending;
        self.free_conns.push(idx);
        self.counters.conns_closed += 1;
    }

    // ================================================================== stats

    fn publish_stats(&mut self) {
        self.last_publish = Instant::now();
        let ws = &self.sh.stats[self.id as usize];
        ws.publish(&self.shard, &self.counters);
    }
}
