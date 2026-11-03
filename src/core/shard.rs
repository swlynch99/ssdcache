//! The owner shard (design §4.4, §5): index, slots, M ring, ghost, sketch, write budget,
//! the SSD regions it wrote, and its IO operation table. Single-threaded and IO-agnostic:
//! it emits `IoReq`s into `io_out` and consumes completions through `io_done`. The worker
//! turns those into io_uring SQEs; the simulator fakes them.
//!
//! Nothing here allocates after `new`.

use super::NONE;
use super::fifo::Fifo;
use super::index::{Index, Slab};
use super::policy::{Budget, Deny, Ghost, MRing, Sketch};
use super::slots::{SlotPool, SlotState};
use crate::config::{CreditCfg, PolicyCfg};
use crate::flash::{self, Flash};
use crate::hash::{H, Hasher};
use crate::proto::{Key, SetMode};
use crate::sizing::Geometry;
use std::sync::Arc;
use std::sync::atomic::Ordering::*;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ReqToken {
    pub worker: u16,
    pub cgen: u16,
    pub conn: u32,
    pub resp: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Stored,
    NotStored,
    Deleted,
    NotFound,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Value at global slot `slot` (cache slot or staging buffer), pinned once for the requester.
    Hit { slot: u32, sgen: u32 },
    /// EXISTS-style lookup: present, nothing pinned.
    Found,
    Miss,
    ServerErr,
    Reserved { slot: u32, sgen: u32 },
    Status(Status),
}

#[derive(Copy, Clone, Debug)]
pub enum Out {
    Reply(ReqToken, Reply),
    /// Unsolicited stash refill for `worker`.
    Grant { worker: u16, slot: u32, sgen: u32 },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoKind {
    Read,
    Write,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoBuf {
    /// Global arena slot (cache slot for writes, staging buffer for reads).
    Slot(u32),
    /// Shard footer buffer index.
    Footer(u8),
}

#[derive(Copy, Clone, Debug)]
pub struct IoReq {
    pub op: u32,
    pub opgen: u32,
    pub kind: IoKind,
    pub dev: u16,
    pub off: u64,
    pub len: u32,
    pub buf: IoBuf,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegionMsg {
    /// Reclaim region `r` if it still holds lap `seq` (sent K regions ahead of the cursor).
    Reclaim { r: u32, seq: u64 },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OpKind {
    Free,
    Read,
    Demote,
    Footer,
}

#[derive(Copy, Clone, Debug)]
struct IoOp {
    kind: OpKind,
    opgen: u32,
    eh: u32,
    ver: u32,
    /// Read: staging buffer (NONE while queued). Demote: memory slot. Footer: buffer idx.
    buf: u32,
    ssd: u32,
    lap: u8,
    region: u32,
    wait_head: u32,
    wait_tail: u32,
    /// Free list / read queue link.
    next: u32,
}

impl IoOp {
    const EMPTY: IoOp = IoOp {
        kind: OpKind::Free,
        opgen: 0,
        eh: NONE,
        ver: 0,
        buf: NONE,
        ssd: NONE,
        lap: 0,
        region: NONE,
        wait_head: NONE,
        wait_tail: NONE,
        next: NONE,
    };
}

struct FooterBuf {
    ptr: *mut u8,
    len: usize,
    /// Footer write in flight.
    busy: bool,
}

struct OpenRegion {
    r: u32,
    seq: u64,
    next: u32,
    opened_ns: u64,
    footer: u8,
}

#[derive(Default, Clone, Debug)]
pub struct ShardStats {
    pub gets: u64,
    pub hits_m: u64,
    pub hits_d: u64,
    pub hits_d_coalesced: u64,
    pub misses: u64,
    pub sets: u64,
    pub not_stored: u64,
    pub deletes: u64,
    pub ghost_hits: u64,
    pub m_evictions: u64,
    pub m_reinsertions: u64,
    pub clean_evictions: u64,
    pub demotions: u64,
    pub demotions_gadmit: u64,
    pub demote_rescued_hot: u64,
    pub drop_no_hit: u64,
    pub drop_theta: u64,
    pub drop_no_tokens: u64,
    pub drop_forced: u64,
    pub drop_no_region: u64,
    pub drop_w_full: u64,
    pub ssd_bytes_written: u64,
    pub ssd_reads: u64,
    pub ssd_read_err: u64,
    pub ssd_write_err: u64,
    pub crc_mismatch: u64,
    pub lap_mismatch: u64,
    pub region_opens: u64,
    pub region_wait: u64,
    pub early_seals: u64,
    pub reclaims: u64,
    pub reclaim_dropped: u64,
    pub d_evictions: u64,
    pub slot_waits: u64,
    pub stale_msgs: u64,
    pub index_overflow: u64,
    pub slab_full: u64,
    pub waiter_overflow: u64,
}


pub struct ShardParams {
    pub id: u16,
    pub n: u16,
    pub policy: PolicyCfg,
    pub credits: CreditCfg,
    /// Bytes per second for this shard's write budget.
    pub write_rate: f64,
    pub burst_s: f64,
    pub hash_seed: u64,
    pub verify_crc: bool,
    /// Arena base (null in the simulator: no value bytes exist, CRC is skipped).
    pub arena: *mut u8,
}

pub struct Shard {
    pub id: u16,
    n: u16,
    pub cfg: PolicyCfg,
    cr: CreditCfg,
    geo: Geometry,
    flash: Arc<Flash>,
    hasher: Hasher,
    arena: *mut u8,
    verify_crc: bool,

    pub slots: SlotPool,
    pub slab: Slab,
    idx: Index,
    m: MRing,
    ghost: Ghost,
    sketch: Sketch,
    pub budget: Budget,

    pub mem_used: u64,
    pending_free: u64,
    pub demote_inflight: u32,
    cache_cap: u64,
    low_wm: u64,
    hard_low: u32,
    want_room: bool,
    m_spins: u16,

    ops: Box<[IoOp]>,
    ops_free: u32,
    read_q_head: u32,
    read_q_tail: u32,
    pub reads_inflight: u32,
    read_of: Box<[(u32, u32)]>,
    read_of_mask: usize,

    waiters: Box<[(ReqToken, u32)]>,
    waiters_free: u32,

    reserve_waiters: Fifo<(u16, ReqToken)>,
    filling_by: Box<[u16]>,
    grant_wanted: Box<[bool]>,

    open: Option<OpenRegion>,
    pending_seq: Option<u64>,
    footers: [FooterBuf; 2],
    reclaim_q: Fifo<(u32, u64)>,
    reclaiming: Option<(u32, u32)>,

    pub io_out: Fifo<IoReq>,
    pub out: Fifo<Out>,
    pub region_out: Fifo<(u16, RegionMsg)>,

    now_ns: u64,
    pub stats: ShardStats,
}

// The raw pointers refer to memory that outlives the shard and is only touched by the
// shard's owner thread (footers) or read for CRC (arena slot owned by this shard).
unsafe impl Send for Shard {}

impl Shard {
    pub fn new(p: ShardParams, geo: &Geometry, flash: Arc<Flash>) -> Self {
        let cache_pool = (geo.cache_cap + geo.h) as u32;
        let base = (p.id as u64 * geo.shard_slots) as u32;
        let slots = SlotPool::new(base, cache_pool, geo.staging as u32);
        let nops = geo.ioops as usize;
        let mut ops = vec![IoOp::EMPTY; nops].into_boxed_slice();
        for (i, op) in ops.iter_mut().enumerate() {
            op.next = if i + 1 < nops { (i + 1) as u32 } else { NONE };
        }
        let nwait = geo.waiters as usize;
        let mut waiters = vec![(ReqToken::default(), NONE); nwait].into_boxed_slice();
        for (i, w) in waiters.iter_mut().enumerate() {
            w.1 = if i + 1 < nwait { (i + 1) as u32 } else { NONE };
        }
        let read_of_cap = (nops * 2).next_power_of_two();
        let ghost_reset = 10 * (geo.cache_cap + geo.ssd_slots / geo.n as u64);
        let mk_footer = || {
            let layout = std::alloc::Layout::from_size_align(geo.footer_bytes as usize, 4096).unwrap();
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            assert!(!ptr.is_null());
            FooterBuf { ptr, len: geo.footer_bytes as usize, busy: false }
        };
        let n = p.n as usize;
        let cr = p.credits.clone();
        Shard {
            id: p.id,
            n: p.n,
            cfg: p.policy.clone(),
            cr: p.credits.clone(),
            geo: geo.clone(),
            hasher: Hasher::new(p.hash_seed),
            arena: p.arena,
            verify_crc: p.verify_crc && !p.arena.is_null(),
            slots,
            slab: Slab::new(geo.entries as u32),
            idx: Index::new(geo.buckets),
            m: MRing::new(geo.m_ring),
            ghost: Ghost::new(geo.ghost_buckets),
            sketch: Sketch::new(geo.sketch_lines, ghost_reset),
            budget: Budget::new(p.write_rate, p.burst_s, geo.demote_cost(), p.policy.sketch),
            mem_used: 0,
            pending_free: 0,
            demote_inflight: 0,
            cache_cap: geo.cache_cap,
            low_wm: (cr.w as u64).min(geo.cache_cap / 32).max(1),
            hard_low: ((geo.h / 8) as u32).clamp(2, 64),
            want_room: false,
            m_spins: 0,
            ops,
            ops_free: 0,
            read_q_head: NONE,
            read_q_tail: NONE,
            reads_inflight: 0,
            read_of: vec![(NONE, NONE); read_of_cap].into_boxed_slice(),
            read_of_mask: read_of_cap - 1,
            waiters,
            waiters_free: 0,
            reserve_waiters: Fifo::new(n * cr.f as usize + 64),
            filling_by: vec![0; n].into_boxed_slice(),
            grant_wanted: vec![false; n].into_boxed_slice(),
            open: None,
            pending_seq: None,
            footers: [mk_footer(), mk_footer()],
            reclaim_q: Fifo::new(geo.regions as usize),
            reclaiming: None,
            io_out: Fifo::new(nops + 8),
            out: Fifo::new(nwait + n * (cr.f as usize + cr.stash as usize) + 256),
            region_out: Fifo::new(256),
            now_ns: 0,
            stats: ShardStats::default(),
            flash,
        }
    }

    pub fn hasher(&self) -> &Hasher {
        &self.hasher
    }

    pub fn footer_ptr(&self, i: u8) -> *mut u8 {
        self.footers[i as usize].ptr
    }

    #[inline]
    fn h_of(&self, eh: u32) -> H {
        self.hasher.hash(&self.slab[eh].key)
    }

    // =================================================================== request-path ops

    /// GET / EXISTS. `None` means the reply comes later through `out` (SSD read).
    pub fn lookup(&mut self, h: &H, key: &Key, req: ReqToken, exists_only: bool) -> Option<Reply> {
        self.stats.gets += 1;
        self.sketch.inc(h);
        let Some(eh) = self.idx.find(h, key, &self.slab) else {
            self.stats.misses += 1;
            return Some(Reply::Miss);
        };
        let e = &mut self.slab[eh];
        e.bump_freq();
        if e.mem != NONE {
            e.set_hit();
            self.stats.hits_m += 1;
            if exists_only {
                return Some(Reply::Found);
            }
            let slot = e.mem;
            let sgen = self.slots.pin(slot);
            return Some(Reply::Hit { slot, sgen });
        }
        if e.ssd == NONE {
            // Cannot happen for an indexed live entry; be defensive.
            self.stats.misses += 1;
            return Some(Reply::Miss);
        }
        if !self.flash.lap_ok(e.ssd, e.lap()) {
            self.stats.lap_mismatch += 1;
            if std::env::var_os("SSDCACHE_DEBUG_LAP").is_some() {
                let r = self.flash.region_of(e.ssd);
                let rm = &self.flash.regions[r as usize];
                eprintln!("lap mismatch lookup: eh={eh} ssd={} r={r} lap={} state={} seq={} R={} reading={} writing={} in_m={}",
                    e.ssd, e.lap(), rm.state.load(Relaxed), rm.seq.load(Relaxed), self.flash.nregions, e.reading(), e.writing(), e.in_m());
            }
            self.stats.misses += 1;
            self.drop_entry(eh, h, false);
            return Some(Reply::Miss);
        }
        if exists_only {
            self.stats.hits_d += 1;
            return Some(Reply::Found);
        }
        let op = if e.reading() {
            self.stats.hits_d_coalesced += 1;
            match self.read_of_get(eh) {
                Some(op) => op,
                None => {
                    debug_assert!(false, "reading without op");
                    return Some(Reply::ServerErr);
                }
            }
        } else {
            let (ver, ssd, lap) = (e.ver, e.ssd, e.lap());
            match self.queue_read(eh, ver, ssd, lap) {
                Some(op) => op,
                None => return Some(Reply::ServerErr),
            }
        };
        if !self.add_waiter(op, req) {
            self.stats.waiter_overflow += 1;
            return Some(Reply::ServerErr);
        }
        self.stats.hits_d += 1;
        None
    }

    /// Allocate a Filling slot for a SET body. `None`: the reply comes later via `out`.
    pub fn reserve(&mut self, from: u16, req: ReqToken) -> Option<Reply> {
        if self.slots.free_slots() > self.hard_low && self.filling_by[from as usize] < self.cr.f {
            let (slot, sgen) = self.slots.alloc_filling().expect("free_slots > 0");
            self.filling_by[from as usize] += 1;
            return Some(Reply::Reserved { slot, sgen });
        }
        self.stats.slot_waits += 1;
        if self.reserve_waiters.push((from, req)).is_err() {
            return Some(Reply::ServerErr);
        }
        self.want_room = true;
        None
    }

    /// Give back a Filling slot without storing (connection died, rejected command).
    pub fn abort(&mut self, from: u16, slot: u32, sgen: u32) {
        if self.slots.check_filling(slot, sgen).is_err() {
            self.stats.stale_msgs += 1;
            debug_assert!(false, "stale abort");
            return;
        }
        self.slots.free_filling(slot);
        self.filling_by[from as usize] = self.filling_by[from as usize].saturating_sub(1);
        self.grant_wanted[from as usize] = true;
    }

    pub fn commit(&mut self, from: u16, h: &H, key: &Key, slot: u32, sgen: u32, mode: SetMode) -> Status {
        if self.slots.check_filling(slot, sgen).is_err() {
            self.stats.stale_msgs += 1;
            debug_assert!(false, "stale commit");
            return Status::NotStored;
        }
        self.filling_by[from as usize] = self.filling_by[from as usize].saturating_sub(1);
        self.grant_wanted[from as usize] = true;
        self.stats.sets += 1;
        self.sketch.inc(h);
        let found = self.idx.find(h, key, &self.slab);
        let allowed = match mode {
            SetMode::Set => true,
            SetMode::Add => found.is_none(),
            SetMode::Replace => found.is_some(),
        };
        if !allowed {
            self.slots.free_filling(slot);
            self.stats.not_stored += 1;
            return Status::NotStored;
        }
        self.slots.mark_live(slot);
        match found {
            Some(eh) => {
                let e = &mut self.slab[eh];
                e.ver = e.ver.wrapping_add(1);
                let old = e.mem;
                e.ssd = NONE; // old SSD copy is dead through the back-map ver mismatch
                e.mem = slot;
                let push = !e.in_m();
                if push {
                    e.set_in_m(true);
                }
                if old != NONE {
                    self.slots.retire(old);
                } else {
                    self.mem_used += 1;
                }
                if push {
                    self.m_push(eh);
                }
            }
            None => {
                let Some(eh) = self.slab.alloc(key) else {
                    self.stats.slab_full += 1;
                    self.slots.retire(slot);
                    return Status::NotStored;
                };
                let gadmit = self.ghost.take(h);
                if gadmit {
                    self.stats.ghost_hits += 1;
                }
                let e = &mut self.slab[eh];
                e.mem = slot;
                e.set_gadmit(gadmit);
                e.set_in_m(true);
                self.mem_used += 1;
                self.m_push(eh);
                if let Err(victim) = self.idx.insert(h, eh) {
                    // Index overflow (far above design load): drop the homeless entry.
                    self.stats.index_overflow += 1;
                    let vh = self.h_of(victim);
                    self.drop_unindexed(victim, &vh);
                }
            }
        }
        // Hard pressure: bounded forced eviction (frees immediately). Soft: one normal step.
        if self.mem_used > self.cache_cap + self.cr.w as u64 || self.slots.free_slots() < self.hard_low {
            self.make_room(4, true);
        } else if self.mem_used - self.pending_free + self.low_wm > self.cache_cap {
            self.make_room(1, false);
        }
        Status::Stored
    }

    pub fn delete(&mut self, h: &H, key: &Key) -> Status {
        self.stats.deletes += 1;
        let Some(eh) = self.idx.remove(h, key, &self.slab) else { return Status::NotFound };
        self.kill(eh);
        Status::Deleted
    }

    /// Release one pin taken for a `Hit`.
    pub fn unpin(&mut self, slot: u32, sgen: u32) {
        if self.slots.unpin(slot, sgen).is_err() {
            self.stats.stale_msgs += 1;
            debug_assert!(false, "stale unpin slot={slot} gen={sgen}");
        }
    }

    // =================================================================== entry helpers

    /// Entry already removed from the index: mark dead, release memory and SSD pointers.
    fn kill(&mut self, eh: u32) {
        let e = &mut self.slab[eh];
        e.ver = e.ver.wrapping_add(1);
        e.set_dead();
        e.ssd = NONE;
        let mem = e.mem;
        e.mem = NONE;
        if mem != NONE {
            self.slots.retire(mem);
            self.mem_used -= 1;
        }
        self.release_if_unref(eh);
    }

    fn drop_entry(&mut self, eh: u32, h: &H, to_ghost: bool) {
        let key = self.slab[eh].key;
        let removed = self.idx.remove(h, &key, &self.slab);
        debug_assert_eq!(removed, Some(eh));
        if to_ghost {
            self.ghost.insert(h);
        }
        self.kill(eh);
    }

    fn drop_unindexed(&mut self, eh: u32, h: &H) {
        self.ghost.insert(h);
        self.kill(eh);
    }

    #[inline]
    fn release_if_unref(&mut self, eh: u32) {
        let e = &self.slab[eh];
        if e.dead() && e.unreferenced() {
            self.slab.free(eh);
        }
    }

    fn m_push(&mut self, eh: u32) {
        if self.m.is_full() {
            self.step_m(true);
        }
        self.m.push(eh);
    }

    // =================================================================== eviction

    fn make_room(&mut self, mut evictions: u32, forced: bool) {
        loop {
            let pressure = self.slots.free_slots() < self.hard_low || self.mem_used > self.cache_cap + self.cr.w as u64;
            let want = self.mem_used.saturating_sub(self.pending_free) + self.low_wm > self.cache_cap || self.want_room;
            if evictions == 0 || !(want || pressure) || self.m.is_empty() {
                break;
            }
            if !pressure && self.demote_inflight >= self.cr.w as u32 {
                // Wait for write CQEs instead of dropping candidates.
                break;
            }
            evictions -= 1;
            self.step_m(forced || pressure);
        }
        self.want_room = !self.reserve_waiters.is_empty() && self.slots.free_slots() <= self.hard_low;
    }

    fn step_m(&mut self, forced: bool) {
        let max_spins = if forced { self.cfg.m_max_spins_forced } else { self.cfg.m_max_spins };
        let eh = loop {
            let Some(eh) = self.m.pop() else { return };
            let e = &mut self.slab[eh];
            if e.dead() {
                e.set_in_m(false);
                self.release_if_unref(eh);
                continue;
            }
            if self.cfg.m_clock && (e.freq() > 0 || e.writing()) && self.m_spins < max_spins {
                if e.freq() > 0 {
                    e.set_freq(e.freq() - 1);
                }
                self.m.push(eh);
                self.m_spins += 1;
                self.stats.m_reinsertions += 1;
                continue;
            }
            break eh;
        };
        self.m_spins = 0;
        self.stats.m_evictions += 1;
        let e = &mut self.slab[eh];
        e.set_in_m(false);
        if e.ssd != NONE {
            // Clean copy: zero writes, frees now.
            let mem = e.mem;
            e.mem = NONE;
            e.set_freq(0);
            self.slots.retire(mem);
            self.mem_used -= 1;
            self.stats.clean_evictions += 1;
            return;
        }
        let h = self.h_of(eh);
        let e = &self.slab[eh];
        let worthy = !self.cfg.admit_requires_hit || e.hit() || e.gadmit();
        let gadmit = e.gadmit();
        let writing = e.writing();
        if !worthy {
            self.stats.drop_no_hit += 1;
        } else if forced {
            self.stats.drop_forced += 1;
        } else if writing {
            self.stats.drop_forced += 1;
        } else if self.demote_inflight >= self.cr.w as u32 {
            self.stats.drop_w_full += 1;
        } else {
            let est = self.sketch.est(&h);
            match self.budget.admit(est, gadmit) {
                Err(Deny::Theta) => self.stats.drop_theta += 1,
                Err(Deny::NoTokens) => self.stats.drop_no_tokens += 1,
                Ok(()) => {
                    if let Some((dst, lap)) = self.next_ssd_slot() {
                        self.submit_demote(eh, dst, lap);
                        return;
                    }
                    // Refund: no region.
                    self.budget.tokens += self.budget.cost;
                    self.stats.drop_no_region += 1;
                }
            }
        }
        self.drop_entry(eh, &h, true);
    }

    fn submit_demote(&mut self, eh: u32, dst: u32, lap: u8) {
        let Some(op) = self.alloc_op() else {
            // Cannot happen: ops ≥ qd + w + waiters.
            let h = self.h_of(eh);
            self.drop_entry(eh, &h, true);
            return;
        };
        let e = &mut self.slab[eh];
        e.set_writing(true);
        let (mem, ver, key) = (e.mem, e.ver, e.key);
        self.slots.pin(mem);
        self.demote_inflight += 1;
        self.pending_free += 1;
        self.flash.set_back(dst, eh, ver);
        let crc = if self.verify_crc { crate::crc::crc32c(self.slot_bytes(mem)) } else { 0 };
        self.flash.crcmap[dst as usize].store(crc, Relaxed);
        // Footer record.
        if let Some(open) = &self.open {
            let i = (dst as u64 % self.geo.slots_per_region) as usize;
            let fb = &self.footers[open.footer as usize];
            let off = crate::sizing::FOOTER_HDR as usize + i * crate::sizing::FOOTER_REC as usize;
            if off + 32 <= fb.len {
                let rec = unsafe { std::slice::from_raw_parts_mut(fb.ptr.add(off), 32) };
                rec[..16].copy_from_slice(&key);
                rec[16..20].copy_from_slice(&ver.to_le_bytes());
                rec[20..24].copy_from_slice(&crc.to_le_bytes());
                rec[24..32].fill(0);
            }
        }
        let r = self.flash.region_of(dst);
        self.flash.regions[r as usize].inflight_writes.fetch_add(1, Relaxed);
        let o = &mut self.ops[op as usize];
        o.kind = OpKind::Demote;
        o.eh = eh;
        o.ver = ver;
        o.buf = mem;
        o.ssd = dst;
        o.lap = lap;
        o.region = r;
        let opgen = o.opgen;
        let (dev, off) = self.geo.ssd_location(dst);
        let _ = self.io_out.push(IoReq {
            op,
            opgen,
            kind: IoKind::Write,
            dev,
            off,
            len: self.geo.s as u32,
            buf: IoBuf::Slot(mem),
        });
        self.stats.demotions += 1;
        if self.slab[eh].gadmit() && !self.slab[eh].hit() {
            self.stats.demotions_gadmit += 1;
        }
        self.stats.ssd_bytes_written += self.geo.s;
    }

    fn on_demote(&mut self, op: u32, res: i32) {
        let o = self.ops[op as usize];
        self.free_op(op);
        let _ = self.slots.unpin(o.buf, self.slots.slot_gen(o.buf));
        self.region_write_done(o.region);
        self.demote_inflight -= 1;
        self.pending_free -= 1;
        let ok = res == self.geo.s as i32;
        let e = &mut self.slab[o.eh];
        e.set_writing(false);
        let region_ok = {
            let rm = &self.flash.regions[o.region as usize];
            let st = rm.state.load(Acquire);
            (st == flash::OPEN || st == flash::SEALED) && self.flash.lap_of_seq(rm.seq.load(Relaxed)) == o.lap
        };
        if ok && region_ok && !e.dead() && e.ver == o.ver && !e.in_m() && e.mem == o.buf {
            e.ssd = o.ssd;
            e.set_lap(o.lap);
            if e.freq() > 0 {
                // Hit during the write: the DRAM copy never left; stay in M as a clean copy.
                let f = e.freq() - 1;
                e.set_freq(f);
                e.set_in_m(true);
                self.stats.demote_rescued_hot += 1;
                self.m_push(o.eh);
            } else {
                e.set_freq(0);
                let mem = e.mem;
                e.mem = NONE;
                self.slots.retire(mem);
                self.mem_used -= 1;
            }
        } else {
            if !ok {
                self.flash.invalidate_back(o.ssd);
                self.stats.ssd_write_err += 1;
            }
            let e = &self.slab[o.eh];
            if !e.dead() && !e.in_m() && e.ver == o.ver {
                // Failed write (or its region was reclaimed meanwhile): drop to G.
                let h = self.h_of(o.eh);
                self.drop_entry(o.eh, &h, true);
            }
        }
        self.release_if_unref(o.eh);
    }

    // =================================================================== SSD reads

    fn queue_read(&mut self, eh: u32, ver: u32, ssd: u32, lap: u8) -> Option<u32> {
        let op = self.alloc_op()?;
        let r = self.flash.region_of(ssd);
        self.flash.regions[r as usize].inflight_reads.fetch_add(1, Relaxed);
        self.slab[eh].set_reading(true);
        let o = &mut self.ops[op as usize];
        o.kind = OpKind::Read;
        o.eh = eh;
        o.ver = ver;
        o.ssd = ssd;
        o.lap = lap;
        o.region = r;
        o.buf = NONE;
        o.wait_head = NONE;
        o.wait_tail = NONE;
        o.next = NONE;
        if self.read_q_tail == NONE {
            self.read_q_head = op;
        } else {
            self.ops[self.read_q_tail as usize].next = op;
        }
        self.read_q_tail = op;
        self.read_of_put(eh, op);
        self.issue_reads();
        Some(op)
    }

    fn issue_reads(&mut self) {
        while self.read_q_head != NONE && self.reads_inflight < self.cr.qd as u32 {
            let Some(buf) = self.slots.alloc_staging() else { break };
            let op = self.read_q_head;
            self.read_q_head = self.ops[op as usize].next;
            if self.read_q_head == NONE {
                self.read_q_tail = NONE;
            }
            let o = &mut self.ops[op as usize];
            o.next = NONE;
            o.buf = buf;
            let (opgen, ssd) = (o.opgen, o.ssd);
            self.reads_inflight += 1;
            self.stats.ssd_reads += 1;
            let (dev, off) = self.geo.ssd_location(ssd);
            let _ = self.io_out.push(IoReq {
                op,
                opgen,
                kind: IoKind::Read,
                dev,
                off,
                len: self.geo.s as u32,
                buf: IoBuf::Slot(buf),
            });
        }
    }

    fn on_ssd_read(&mut self, op: u32, res: i32) {
        let o = self.ops[op as usize];
        self.reads_inflight -= 1;
        self.read_of_del(o.eh);
        self.slab[o.eh].set_reading(false);
        // Check the lap BEFORE releasing the region's read count: the release may move a
        // Draining region to Clean, after which this read would look stale.
        let lap_ok = self.flash.lap_ok(o.ssd, o.lap) || self.region_draining_same_lap(o.region, o.lap);
        self.region_read_done(o.region);
        let ok = res == self.geo.s as i32;
        let crc_ok = !ok
            || !self.verify_crc
            || crate::crc::crc32c(self.slot_bytes(o.buf)) == self.flash.crcmap[o.ssd as usize].load(Relaxed);
        if !ok || !lap_ok || !crc_ok {
            if !ok {
                self.stats.ssd_read_err += 1;
            }
            if !crc_ok {
                self.stats.crc_mismatch += 1;
            }
            if !lap_ok {
                self.stats.lap_mismatch += 1;
            }
            let reply = if lap_ok { Reply::ServerErr } else { Reply::Miss };
            let mut w = o.wait_head;
            while w != NONE {
                let (req, next) = self.waiters[w as usize];
                let _ = self.out.push(Out::Reply(req, reply));
                self.free_waiter(w);
                w = next;
            }
            self.slots.retire_staging(o.buf);
            let e = &self.slab[o.eh];
            if !e.dead() && e.ver == o.ver && e.mem == NONE && e.ssd == o.ssd {
                // No SSD pointer survives a failed read.
                let h = self.h_of(o.eh);
                self.drop_entry(o.eh, &h, false);
            }
        } else {
            let mut w = o.wait_head;
            while w != NONE {
                let (req, next) = self.waiters[w as usize];
                let sgen = self.slots.pin(o.buf);
                let _ = self.out.push(Out::Reply(req, Reply::Hit { slot: o.buf, sgen }));
                self.free_waiter(w);
                w = next;
            }
            // Back to the staging pool at the last unpin; never cached.
            self.slots.retire_staging(o.buf);
        }
        self.free_op(op);
        self.release_if_unref(o.eh);
        self.issue_reads();
    }

    /// A region that reclaim moved to Draining still holds valid bytes for reads that were
    /// queued before reclaim (linearized before the eviction).
    fn region_draining_same_lap(&self, r: u32, lap: u8) -> bool {
        let rm = &self.flash.regions[r as usize];
        let st = rm.state.load(Acquire);
        (st == flash::DRAINING || st == flash::RECLAIMING) && self.flash.lap_of_seq(rm.seq.load(Relaxed)) == lap
    }

    fn add_waiter(&mut self, op: u32, req: ReqToken) -> bool {
        let w = self.waiters_free;
        if w == NONE {
            return false;
        }
        self.waiters_free = self.waiters[w as usize].1;
        self.waiters[w as usize] = (req, NONE);
        let o = &mut self.ops[op as usize];
        if o.wait_tail == NONE {
            o.wait_head = w;
        } else {
            let t = o.wait_tail;
            self.waiters[t as usize].1 = w;
        }
        self.ops[op as usize].wait_tail = w;
        true
    }

    fn free_waiter(&mut self, w: u32) {
        self.waiters[w as usize].1 = self.waiters_free;
        self.waiters_free = w;
    }

    fn alloc_op(&mut self) -> Option<u32> {
        let op = self.ops_free;
        if op == NONE {
            return None;
        }
        self.ops_free = self.ops[op as usize].next;
        let o = &mut self.ops[op as usize];
        o.next = NONE;
        o.opgen = o.opgen.wrapping_add(1);
        Some(op)
    }

    fn free_op(&mut self, op: u32) {
        let o = &mut self.ops[op as usize];
        o.kind = OpKind::Free;
        o.opgen = o.opgen.wrapping_add(1);
        o.next = self.ops_free;
        self.ops_free = op;
    }

    fn read_of_put(&mut self, eh: u32, op: u32) {
        let mut i = (eh as usize).wrapping_mul(0x9E37_79B9) & self.read_of_mask;
        loop {
            if self.read_of[i].0 == NONE {
                self.read_of[i] = (eh, op);
                return;
            }
            i = (i + 1) & self.read_of_mask;
        }
    }

    fn read_of_get(&self, eh: u32) -> Option<u32> {
        let mut i = (eh as usize).wrapping_mul(0x9E37_79B9) & self.read_of_mask;
        loop {
            let (k, v) = self.read_of[i];
            if k == NONE {
                return None;
            }
            if k == eh {
                return Some(v);
            }
            i = (i + 1) & self.read_of_mask;
        }
    }

    fn read_of_del(&mut self, eh: u32) {
        let mask = self.read_of_mask;
        let mut i = (eh as usize).wrapping_mul(0x9E37_79B9) & mask;
        loop {
            let (k, _) = self.read_of[i];
            if k == NONE {
                return;
            }
            if k == eh {
                break;
            }
            i = (i + 1) & mask;
        }
        // Backward-shift deletion.
        let mut j = i;
        loop {
            self.read_of[i] = (NONE, NONE);
            loop {
                j = (j + 1) & mask;
                let (k, _) = self.read_of[j];
                if k == NONE {
                    return;
                }
                let home = (k as usize).wrapping_mul(0x9E37_79B9) & mask;
                // Move j to i if home is cyclically outside (i, j].
                let between = if i <= j { home > i && home <= j } else { home > i || home <= j };
                if !between {
                    self.read_of[i] = self.read_of[j];
                    i = j;
                    break;
                }
            }
        }
    }

    fn slot_bytes(&self, slot: u32) -> &[u8] {
        let off = self.geo.slot_offset(slot) as usize;
        unsafe { std::slice::from_raw_parts(self.arena.add(off), self.geo.v as usize) }
    }

    // =================================================================== IO completions

    pub fn io_done(&mut self, op: u32, opgen: u32, res: i32) {
        let o = &self.ops[op as usize];
        if o.opgen != opgen {
            debug_assert!(false, "stale IO completion");
            self.stats.stale_msgs += 1;
            return;
        }
        match o.kind {
            OpKind::Read => self.on_ssd_read(op, res),
            OpKind::Demote => self.on_demote(op, res),
            OpKind::Footer => {
                let (buf, region) = (o.buf, o.region);
                self.free_op(op);
                self.footers[buf as usize].busy = false;
                if res != self.geo.footer_bytes as i32 {
                    self.stats.ssd_write_err += 1;
                }
                self.region_write_done(region);
            }
            OpKind::Free => {
                debug_assert!(false, "completion for free op");
            }
        }
    }

    // =================================================================== regions

    fn next_ssd_slot(&mut self) -> Option<(u32, u8)> {
        if self.open.is_none() && !self.open_region() {
            return None;
        }
        let spr = self.geo.slots_per_region as u32;
        let open = self.open.as_mut().unwrap();
        let dst = open.r * spr + open.next;
        let lap = self.flash.lap_of_seq(open.seq);
        open.next += 1;
        let r = open.r;
        self.flash.regions[r as usize].fill.store(open.next, Relaxed);
        if open.next == spr {
            self.seal_open();
        }
        Some((dst, lap))
    }

    fn open_region(&mut self) -> bool {
        let Some(fi) = self.footers.iter().position(|f| !f.busy) else {
            self.stats.region_wait += 1;
            return false;
        };
        let seq = match self.pending_seq.take() {
            Some(s) => s,
            None => self.flash.cursor.fetch_add(1, AcqRel),
        };
        let nr = self.flash.nregions;
        let r = (seq % nr) as u32;
        let rm = &self.flash.regions[r as usize];
        if rm.state.load(Acquire) != flash::CLEAN {
            // Never skip: retry the same seq on the next attempt (global FIFO ⇒ DLWA ≈ 1).
            self.pending_seq = Some(seq);
            self.stats.region_wait += 1;
            return false;
        }
        // Reset the back-map for the region (defense in depth against stale records).
        let spr = self.geo.slots_per_region;
        for i in 0..spr {
            self.flash.invalidate_back((r as u64 * spr + i) as u32);
        }
        rm.owner.store(self.id, Relaxed);
        rm.seq.store(seq, Relaxed);
        rm.fill.store(0, Relaxed);
        rm.inflight_writes.store(0, Relaxed);
        rm.state.store(flash::OPEN, Release);
        self.flash.region_opens.fetch_add(1, Relaxed);
        self.stats.region_opens += 1;
        let fb = &self.footers[fi];
        unsafe { std::ptr::write_bytes(fb.ptr, 0, fb.len) };
        self.open = Some(OpenRegion { r, seq, next: 0, opened_ns: self.now_ns, footer: fi as u8 });
        // Keep K regions clean ahead of the cursor: ask the owner of seq+K to reclaim it.
        let ahead_seq = seq + self.flash.k_ahead;
        let ar = (ahead_seq % nr) as u32;
        let am = &self.flash.regions[ar as usize];
        let st = am.state.load(Acquire);
        if st != flash::CLEAN {
            let owner = am.owner.load(Relaxed);
            let aseq = am.seq.load(Relaxed);
            let msg = RegionMsg::Reclaim { r: ar, seq: aseq };
            if owner == self.id {
                self.region_msg(msg);
            } else {
                let _ = self.region_out.push((owner, msg));
            }
        }
        true
    }

    fn seal_open(&mut self) {
        let Some(open) = self.open.take() else { return };
        let flash = self.flash.clone(); // rare path; avoids holding a borrow of self
        let rm = &flash.regions[open.r as usize];
        let fill = open.next;
        // Footer header.
        let fb = &mut self.footers[open.footer as usize];
        let hdr = unsafe { std::slice::from_raw_parts_mut(fb.ptr, 32) };
        hdr[..8].copy_from_slice(b"SSDCFTR1");
        hdr[8..16].copy_from_slice(&open.seq.to_le_bytes());
        hdr[16..18].copy_from_slice(&self.id.to_le_bytes());
        hdr[18..22].copy_from_slice(&self.geo.v.to_le_bytes());
        hdr[22..24].copy_from_slice(&(fill as u16).to_le_bytes());
        fb.busy = true;
        rm.inflight_writes.fetch_add(1, Relaxed);
        rm.state.store(flash::SEALED, Release);
        if fill < self.geo.slots_per_region as u32 {
            self.stats.early_seals += 1;
        }
        let Some(op) = self.alloc_op() else {
            self.footers[open.footer as usize].busy = false;
            rm.inflight_writes.fetch_sub(1, Relaxed);
            return;
        };
        let o = &mut self.ops[op as usize];
        o.kind = OpKind::Footer;
        o.buf = open.footer as u32;
        o.region = open.r;
        let opgen = o.opgen;
        let (dev, off) = self.geo.footer_location(open.r);
        let _ = self.io_out.push(IoReq {
            op,
            opgen,
            kind: IoKind::Write,
            dev,
            off,
            len: self.geo.footer_bytes as u32,
            buf: IoBuf::Footer(open.footer),
        });
    }

    fn region_read_done(&mut self, r: u32) {
        let rm = &self.flash.regions[r as usize];
        rm.inflight_reads.fetch_sub(1, Relaxed);
        self.maybe_clean(r);
    }

    fn region_write_done(&mut self, r: u32) {
        let rm = &self.flash.regions[r as usize];
        rm.inflight_writes.fetch_sub(1, Relaxed);
        self.maybe_clean(r);
    }

    fn maybe_clean(&self, r: u32) {
        let rm = &self.flash.regions[r as usize];
        if rm.state.load(Relaxed) == flash::DRAINING
            && rm.inflight_reads.load(Relaxed) == 0
            && rm.inflight_writes.load(Relaxed) == 0
        {
            rm.state.store(flash::CLEAN, Release);
        }
    }

    /// Region-control message from another shard (or self).
    pub fn region_msg(&mut self, msg: RegionMsg) {
        match msg {
            RegionMsg::Reclaim { r, seq } => {
                let flash = self.flash.clone();
                let rm = &flash.regions[r as usize];
                if rm.owner.load(Relaxed) != self.id || rm.seq.load(Relaxed) != seq {
                    return;
                }
                let st = rm.state.load(Acquire);
                if st == flash::CLEAN || st == flash::RECLAIMING || st == flash::DRAINING {
                    return;
                }
                if st == flash::OPEN {
                    // Age bound failed: close it first (no appends; writes drain below).
                    if self.open.as_ref().map(|o| o.r) == Some(r) {
                        self.seal_open();
                    }
                }
                rm.state.store(flash::RECLAIMING, Release);
                let _ = self.reclaim_q.push((r, seq));
            }
        }
    }

    fn reclaim_step(&mut self, budget: u32) {
        let mut budget = budget;
        while budget > 0 {
            if self.reclaiming.is_none() {
                let Some((r, _)) = self.reclaim_q.pop() else { return };
                self.reclaiming = Some((r, 0));
                self.stats.reclaims += 1;
            }
            let (r, mut cur) = self.reclaiming.unwrap();
            let rm = &self.flash.regions[r as usize];
            let fill = rm.fill.load(Relaxed);
            let spr = self.geo.slots_per_region as u32;
            while cur < fill && budget > 0 {
                let slot = r * spr + cur;
                cur += 1;
                budget -= 1;
                let Some((eh, ver)) = self.flash.back(slot) else { continue };
                if eh >= self.slab.capacity() || !self.slab.is_allocated(eh) {
                    continue;
                }
                let e = &mut self.slab[eh];
                if e.dead() || e.ver != ver || e.ssd != slot {
                    continue;
                }
                // SYNCHRONOUS: no SSD pointer into r survives this visit.
                e.ssd = NONE;
                if e.mem != NONE {
                    // Clean DRAM copy becomes dirty in M.
                    continue;
                }
                self.stats.d_evictions += 1;
                self.stats.reclaim_dropped += 1;
                let h = self.h_of(eh);
                let to_ghost = self.cfg.ghost_d_evictees;
                self.drop_entry(eh, &h, to_ghost);
            }
            if cur >= fill {
                self.reclaiming = None;
                let rm = &self.flash.regions[r as usize];
                rm.state.store(flash::DRAINING, Release);
                self.maybe_clean(r);
            } else {
                self.reclaiming = Some((r, cur));
            }
        }
    }

    // =================================================================== background tick

    /// Bounded background work. Call once per loop iteration.
    pub fn tick(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
        self.budget.refill(now_ns);
        self.sketch.age_step(64);
        self.make_room(64, false);
        self.serve_reserve_waiters();
        self.reclaim_step(64);
        // Open-region age bound and cursor lag.
        if let Some(open) = &self.open {
            let age_ns = now_ns.saturating_sub(open.opened_ns);
            let lag = self.flash.cursor().saturating_sub(open.seq);
            if age_ns > self.cfg.open_max_age_s as u64 * 1_000_000_000 || lag > self.flash.nregions / 4 {
                self.seal_open();
            }
        }
        if self.pending_seq.is_some() && self.open.is_none() {
            // Retry a pending region open so the global cursor keeps moving.
            let _ = self.open_region();
        }
        self.issue_reads();
    }

    fn serve_reserve_waiters(&mut self) {
        let mut i = 0;
        while i < self.reserve_waiters.len() && self.slots.free_slots() > self.hard_low {
            let (from, _) = *self.reserve_waiters.get(i).unwrap();
            if self.filling_by[from as usize] >= self.cr.f {
                i += 1;
                continue;
            }
            let (from, req) = self.reserve_waiters.remove_at(i).unwrap();
            let (slot, sgen) = self.slots.alloc_filling().unwrap();
            self.filling_by[from as usize] += 1;
            let _ = self.out.push(Out::Reply(req, Reply::Reserved { slot, sgen }));
        }
        // Stash refills.
        if self.reserve_waiters.is_empty() {
            for w in 0..self.n as usize {
                if w == self.id as usize || !self.grant_wanted[w] {
                    continue;
                }
                self.grant_wanted[w] = false;
                while self.filling_by[w] < self.cr.stash && self.slots.free_slots() > 2 * self.hard_low {
                    let (slot, sgen) = self.slots.alloc_filling().unwrap();
                    self.filling_by[w] += 1;
                    if self.out.push(Out::Grant { worker: w as u16, slot, sgen }).is_err() {
                        self.slots.free_filling(slot);
                        self.filling_by[w] -= 1;
                        break;
                    }
                }
            }
        }
        self.want_room = !self.reserve_waiters.is_empty();
    }

    /// Ask for a stash refill for worker `w` at the next tick.
    pub fn want_grant(&mut self, w: u16) {
        self.grant_wanted[w as usize] = true;
    }

    // =================================================================== debug

    pub fn m_len(&self) -> u64 {
        self.m.len()
    }

    pub fn index_len(&self) -> u64 {
        self.idx.len
    }

    pub fn cache_cap(&self) -> u64 {
        self.cache_cap
    }

    /// Full consistency check (O(entries)). For tests and the simulator.
    pub fn check(&self) -> Result<(), String> {
        self.slots.check()?;
        let mut mem_live = 0u64;
        for eh in 0..self.slab.capacity() {
            if !self.slab.is_allocated(eh) {
                continue;
            }
            let e = &self.slab[eh];
            if e.dead() {
                if e.mem != NONE || e.ssd != NONE {
                    return Err(format!("dead entry {eh} with location"));
                }
                if e.unreferenced() {
                    return Err(format!("dead unreferenced entry {eh} not freed"));
                }
                continue;
            }
            if e.mem != NONE {
                mem_live += 1;
                let st = self.slots.state(e.mem);
                if st != SlotState::Live {
                    return Err(format!("entry {eh} mem {} in state {st:?}", e.mem));
                }
            } else if e.ssd == NONE {
                return Err(format!("live entry {eh} with no location"));
            }
            if e.mem != NONE && !e.in_m() && !e.writing() {
                return Err(format!("entry {eh} has DRAM copy but is not in M"));
            }
            let h = self.hasher.hash(&e.key);
            if self.idx.find(&h, &e.key, &self.slab) != Some(eh) {
                return Err(format!("live entry {eh} not indexed"));
            }
        }
        if mem_live != self.mem_used {
            return Err(format!("mem_used {} != live mem {}", self.mem_used, mem_live));
        }
        Ok(())
    }
}

impl Drop for Shard {
    fn drop(&mut self) {
        for f in &self.footers {
            let layout = std::alloc::Layout::from_size_align(f.len, 4096).unwrap();
            unsafe { std::alloc::dealloc(f.ptr, layout) };
        }
    }
}
