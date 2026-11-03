//! Global SSD region table, back-map and CRC map (design §3.4).
//!
//! One global region FIFO across all shards. `state`, `owner` and `seq` are the
//! cross-thread fields; ownership passes through Release/Acquire on `state`. The
//! remaining fields are owner-exclusive and use Relaxed atomics only so the table can be
//! shared without `unsafe`.

use crate::sizing::Geometry;
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering::*};

pub const CLEAN: u8 = 0;
pub const OPEN: u8 = 1;
pub const SEALED: u8 = 2;
pub const RECLAIMING: u8 = 3;
pub const DRAINING: u8 = 4;

pub const INVALID_BACK: u64 = u64::MAX;

#[repr(C, align(64))]
#[derive(Default)]
pub struct RegionMeta {
    pub state: AtomicU8,
    pub owner: AtomicU16,
    pub seq: AtomicU64,
    // owner-exclusive
    pub fill: AtomicU32,
    pub inflight_reads: AtomicU32,
    pub inflight_writes: AtomicU32,
}

pub struct Flash {
    pub regions: Box<[RegionMeta]>,
    pub cursor: crossbeam_utils::CachePadded<AtomicU64>,
    /// Per SSD slot: `(eh << 32) | ver`, written by the region owner at demotion submit.
    pub backmap: Box<[AtomicU64]>,
    /// Per SSD slot: crc32c of the value, written at demotion submit.
    pub crcmap: Box<[AtomicU32]>,
    pub nregions: u64,
    pub spr: u64,
    pub k_ahead: u64,
    /// Stats: global.
    pub region_opens: AtomicU64,
}

impl Flash {
    pub fn new(geo: &Geometry) -> Self {
        let regions: Vec<RegionMeta> = (0..geo.regions).map(|_| RegionMeta::default()).collect();
        let backmap: Vec<AtomicU64> = (0..geo.ssd_slots).map(|_| AtomicU64::new(INVALID_BACK)).collect();
        let crcmap: Vec<AtomicU32> = (0..geo.ssd_slots).map(|_| AtomicU32::new(0)).collect();
        Flash {
            regions: regions.into_boxed_slice(),
            cursor: crossbeam_utils::CachePadded::new(AtomicU64::new(0)),
            backmap: backmap.into_boxed_slice(),
            crcmap: crcmap.into_boxed_slice(),
            nregions: geo.regions,
            spr: geo.slots_per_region,
            k_ahead: geo.k_ahead,
            region_opens: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn region_of(&self, ssd: u32) -> u32 {
        (ssd as u64 / self.spr) as u32
    }

    #[inline]
    pub fn lap_of_seq(&self, seq: u64) -> u8 {
        (seq / self.nregions) as u8
    }

    /// Lap check (design §3.3): the region still holds the lap the entry was written in.
    /// RECLAIMING counts: slots not yet visited by reclaim still hold valid bytes, and a read
    /// queued now holds the region out of Clean via `inflight_reads`.
    #[inline]
    pub fn lap_ok(&self, ssd: u32, lap: u8) -> bool {
        let r = &self.regions[self.region_of(ssd) as usize];
        let st = r.state.load(Acquire);
        (st == OPEN || st == SEALED || st == RECLAIMING) && self.lap_of_seq(r.seq.load(Acquire)) == lap
    }

    #[inline]
    pub fn set_back(&self, ssd: u32, eh: u32, ver: u32) {
        self.backmap[ssd as usize].store(((eh as u64) << 32) | ver as u64, Relaxed);
    }

    #[inline]
    pub fn back(&self, ssd: u32) -> Option<(u32, u32)> {
        let v = self.backmap[ssd as usize].load(Relaxed);
        if v == INVALID_BACK { None } else { Some(((v >> 32) as u32, v as u32)) }
    }

    pub fn invalidate_back(&self, ssd: u32) {
        self.backmap[ssd as usize].store(INVALID_BACK, Relaxed);
    }

    /// D-tier age: seconds are tracked by the control plane; here, the cursor lag.
    pub fn cursor(&self) -> u64 {
        self.cursor.load(Relaxed)
    }

    pub fn count_states(&self) -> [u64; 5] {
        let mut c = [0u64; 5];
        for r in self.regions.iter() {
            c[r.state.load(Relaxed) as usize] += 1;
        }
        c
    }
}
