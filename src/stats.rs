//! Per-worker counters published with relaxed stores and read by the control thread
//! (design §9.2). Workers never take locks to publish.

use crate::core::shard::Shard;
use crate::worker::WorkerCounters;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

macro_rules! fields {
    ($($s:ident).* ; $($w:ident),* ; $($g:ident),*) => {
        pub const SHARD_FIELDS: &[&str] = &[$(stringify!($s)),*];
        pub const WORKER_FIELDS: &[&str] = &[$(stringify!($w)),*];
        pub const GAUGE_FIELDS: &[&str] = &[$(stringify!($g)),*];
        fn shard_values(sh: &Shard) -> Vec<u64> { vec![$(sh.stats.$s),*] }
        fn worker_values(c: &WorkerCounters) -> Vec<u64> { vec![$(c.$w),*] }
    };
}

fields!(
    gets.hits_m.hits_d.hits_d_coalesced.misses.sets.not_stored.deletes.ghost_hits.m_evictions.m_reinsertions
        .clean_evictions.demotions.demotions_gadmit.demote_rescued_hot.drop_no_hit.drop_theta.drop_no_tokens
        .drop_forced.drop_no_region.drop_w_full.ssd_bytes_written.ssd_reads.ssd_read_err.ssd_write_err
        .crc_mismatch.lap_mismatch.region_opens.region_wait.early_seals.reclaims.d_evictions.slot_waits
        .stale_msgs.index_overflow.slab_full.waiter_overflow;
    conns_opened, conns_closed, parked, doorbells_sent, wakeups, spin_hits, ring_overflow, stale_replies,
    tls_control_records, body_timeouts, send_bytes, recv_bytes, fixed_buffers;
    mem_used, cache_cap, index_len, m_len, zombies, filling, staging_held, demote_inflight, reads_inflight,
    theta, free_slots
);

pub struct WorkerStats {
    shard: Box<[AtomicU64]>,
    worker: Box<[AtomicU64]>,
    gauges: Box<[AtomicU64]>,
}

impl Default for WorkerStats {
    fn default() -> Self {
        let mk = |n: usize| (0..n).map(|_| AtomicU64::new(0)).collect();
        WorkerStats { shard: mk(SHARD_FIELDS.len()), worker: mk(WORKER_FIELDS.len()), gauges: mk(GAUGE_FIELDS.len()) }
    }
}

impl WorkerStats {
    /// Called by the worker every ~250 ms. (The `Vec`s are tiny and this is off the request
    /// path; a fixed-array version is a phase-5 cleanup.)
    pub fn publish(&self, sh: &Shard, c: &WorkerCounters) {
        for (a, v) in self.shard.iter().zip(shard_values(sh)) {
            a.store(v, Relaxed);
        }
        for (a, v) in self.worker.iter().zip(worker_values(c)) {
            a.store(v, Relaxed);
        }
        let g = [
            sh.mem_used,
            sh.cache_cap(),
            sh.index_len(),
            sh.m_len(),
            sh.slots.zombies as u64,
            sh.slots.filling as u64,
            sh.slots.staging_held as u64,
            sh.demote_inflight as u64,
            sh.reads_inflight as u64,
            sh.budget.theta as u64,
            sh.slots.free_slots() as u64,
        ];
        for (a, v) in self.gauges.iter().zip(g) {
            a.store(v, Relaxed);
        }
    }
}

/// JSON: totals plus per-worker values.
pub fn render_json(all: &[WorkerStats], extra: &[(&str, u64)]) -> String {
    let mut s = String::from("{\n");
    let sum = |arr: &dyn Fn(&WorkerStats) -> &[AtomicU64], i: usize| -> u64 { all.iter().map(|w| arr(w)[i].load(Relaxed)).sum() };
    for (i, f) in SHARD_FIELDS.iter().enumerate() {
        s += &format!("  \"{f}\": {},\n", sum(&|w| &w.shard, i));
    }
    for (i, f) in WORKER_FIELDS.iter().enumerate() {
        s += &format!("  \"{f}\": {},\n", sum(&|w| &w.worker, i));
    }
    for (i, f) in GAUGE_FIELDS.iter().enumerate() {
        s += &format!("  \"{f}\": {},\n", sum(&|w| &w.gauges, i));
    }
    for (k, v) in extra {
        s += &format!("  \"{k}\": {v},\n");
    }
    let gets = sum(&|w| &w.shard, 0).max(1) as f64;
    s += &format!(
        "  \"hit_ratio_m\": {:.4},\n  \"hit_ratio_d\": {:.4},\n  \"workers\": {}\n}}\n",
        sum(&|w| &w.shard, 1) as f64 / gets,
        sum(&|w| &w.shard, 2) as f64 / gets,
        all.len()
    );
    s
}
