//! Geometry derived from V and the config (design §3.1, §3.5). Every table, pool and id
//! width in the server comes from here; nothing is hard-coded for one value size.

use crate::config::Config;

pub const PAGE: u64 = 4096;
pub const CHUNK: u64 = 1 << 30;
pub const SUPERBLOCK_BYTES: u64 = 1 << 20;
pub const FOOTER_HDR: u64 = 32;
pub const FOOTER_REC: u64 = 32;

pub fn round_up(x: u64, a: u64) -> u64 {
    x.div_ceil(a) * a
}

pub fn next_pow2(x: u64) -> u64 {
    x.max(1).next_power_of_two()
}

#[derive(Clone, Debug)]
pub struct Geometry {
    pub n: u16,
    /// V, wire length.
    pub v: u32,
    /// S, slot stride.
    pub s: u64,
    pub slots_per_chunk: u64,
    /// Arena slots across all shards.
    pub arena_slots: u64,
    pub arena_bytes: u64,
    /// Per-shard slot partition: `[cache pool (cache_cap + h) | staging]`.
    pub shard_slots: u64,
    pub h: u64,
    pub staging: u64,
    pub cache_cap: u64,
    pub m_ring: u64,
    // SSD
    pub devices: u64,
    pub device_bytes: u64,
    pub region_bytes: u64,
    pub slots_per_region: u64,
    pub footer_bytes: u64,
    pub regions: u64,
    pub regions_per_device: u64,
    pub ssd_slots: u64,
    /// Regions kept clean ahead of the global cursor.
    pub k_ahead: u64,
    /// An open region is sealed when the cursor is more than this many regions past it.
    pub open_lag_limit: u64,
    // Per-shard metadata
    pub entries: u64,
    pub buckets: u64,
    pub ghost_buckets: u64,
    pub sketch_lines: u64,
    pub ioops: u64,
    pub waiters: u64,
}

impl Geometry {
    pub fn compute(cfg: &Config, device_bytes: u64) -> Result<Geometry, String> {
        let n = cfg.workers as u64;
        let v = cfg.value_size;
        let s = round_up(v as u64, PAGE);
        let slots_per_chunk = (CHUNK / s).max(1);
        // Slots never straddle a 1 GiB chunk.
        let full_chunks = cfg.memory_bytes / CHUNK;
        let tail = (cfg.memory_bytes % CHUNK) / s;
        let arena_slots = full_chunks * slots_per_chunk + tail;
        let shard_slots = arena_slots / n;
        let cr = &cfg.credits;
        let h = n * cr.p as u64 + n * cr.f as u64 + cr.w as u64;
        let staging = cr.qd as u64 + n * cr.p as u64;
        if shard_slots <= h + staging + 16 {
            return Err(format!(
                "memory_bytes too small: {} slots per shard, need > {} (H={h} + staging={staging} + 16)",
                shard_slots,
                h + staging + 16
            ));
        }
        let cache_cap = shard_slots - h - staging;
        let m_ring = next_pow2(cache_cap * 5 / 4 + 64);

        // SSD geometry.
        let region_bytes = cfg.region_bytes;
        if region_bytes % PAGE != 0 || region_bytes < 2 * s + PAGE {
            return Err("region_bytes must be a multiple of 4096 and hold ≥ 2 slots".into());
        }
        let mut spr = region_bytes / s;
        let footer_bytes = loop {
            let f = round_up(FOOTER_HDR + FOOTER_REC * spr, PAGE);
            if spr * s + f <= region_bytes {
                break f;
            }
            spr -= 1;
        };
        let devices = cfg.devices.len() as u64;
        let usable = ((device_bytes as f64) * (1.0 - cfg.host_op)) as u64;
        if usable <= SUPERBLOCK_BYTES + region_bytes {
            return Err("device too small for one region".into());
        }
        let regions_per_device = (usable - SUPERBLOCK_BYTES) / region_bytes;
        let regions = regions_per_device * devices;
        let k_ahead = (4 * n).max(128).min(regions / 4).max(1);
        // One round of region opens moves the cursor by n. The limit must stay above that or
        // every open region counts as lagging: each gets sealed nearly empty, and the next
        // open moves the cursor again. It must also stay clear of the reclaim point.
        let min_regions = k_ahead + 4 * n + 4;
        if regions < min_regions {
            return Err(format!("need more regions: have {regions}, need ≥ {min_regions}"));
        }
        let open_lag_limit = (regions / 4).max(2 * n).min(regions - k_ahead - 2 * n - 2);
        let ssd_slots = regions * spr;
        if ssd_slots >= (u32::MAX as u64) {
            return Err("too many SSD slots for 32-bit ids".into());
        }

        // Per-shard metadata. D is shared; give each shard 1.25× its fair share of SSD slots
        // so mild imbalance never exhausts the entry slab.
        let d_share = ssd_slots.div_ceil(n) * 5 / 4;
        let max_live = cache_cap + d_share;
        let entries = max_live + m_ring + h + 64;
        let buckets = (max_live as f64 / (8.0 * 0.85)).ceil() as u64 + 1;
        let ghost_entries = ((cache_cap + ssd_slots / n) as f64 * cfg.policy.ghost_factor * 1.25) as u64;
        let ghost_buckets = (ghost_entries / 8).max(8);
        let sketch_counters = next_pow2(max_live).max(1024);
        let sketch_lines = sketch_counters / 128; // 128 4-bit counters per 64 B line
        let waiters = n * cr.p as u64 + 64;
        let ioops = cr.qd as u64 + cr.w as u64 + waiters + 8;

        Ok(Geometry {
            n: cfg.workers,
            v,
            s,
            slots_per_chunk,
            arena_slots,
            arena_bytes: arena_bytes(arena_slots, s, slots_per_chunk),
            shard_slots,
            h,
            staging,
            cache_cap,
            m_ring,
            devices,
            device_bytes,
            region_bytes,
            slots_per_region: spr,
            footer_bytes,
            regions,
            regions_per_device,
            ssd_slots,
            k_ahead,
            open_lag_limit,
            entries,
            buckets,
            ghost_buckets,
            sketch_lines,
            ioops,
            waiters,
        })
    }

    /// Byte offset of global slot `slot` in the arena.
    #[inline]
    pub fn slot_offset(&self, slot: u32) -> u64 {
        let slot = slot as u64;
        (slot / self.slots_per_chunk) * CHUNK + (slot % self.slots_per_chunk) * self.s
    }

    /// (fixed buffer index, offset within it) for io_uring READ_FIXED/WRITE_FIXED.
    #[inline]
    pub fn slot_chunk(&self, slot: u32) -> (u16, u64) {
        let slot = slot as u64;
        ((slot / self.slots_per_chunk) as u16, (slot % self.slots_per_chunk) * self.s)
    }

    /// Device index and byte offset of SSD slot `ssd`.
    #[inline]
    pub fn ssd_location(&self, ssd: u32) -> (u16, u64) {
        let r = ssd as u64 / self.slots_per_region;
        let i = ssd as u64 % self.slots_per_region;
        let (dev, base) = self.region_location(r as u32);
        (dev, base + i * self.s)
    }

    #[inline]
    pub fn region_location(&self, r: u32) -> (u16, u64) {
        let r = r as u64;
        ((r % self.devices) as u16, SUPERBLOCK_BYTES + (r / self.devices) * self.region_bytes)
    }

    #[inline]
    pub fn footer_location(&self, r: u32) -> (u16, u64) {
        let (dev, base) = self.region_location(r);
        (dev, base + self.slots_per_region * self.s)
    }

    /// Bytes charged to the write budget per demotion (slot plus footer share).
    pub fn demote_cost(&self) -> u64 {
        self.s + self.s * self.footer_bytes / self.region_bytes
    }

    pub fn report(&self) -> String {
        let gib = |b: u64| b as f64 / (1u64 << 30) as f64;
        format!(
            "geometry: V={} S={} N={}\n  arena: {} slots ({:.2} GiB), per shard {} = cache {} + H {} + staging {}\n  M ring {} | entries/shard {} | buckets/shard {} | ghost buckets/shard {} | sketch lines/shard {}\n  SSD: {} device(s) × {:.2} GiB, region {} MiB = {} slots + {} KiB footer, R = {}, SSD slots = {}, K = {}\n  M/(M+D) = {:.2}%",
            self.v,
            self.s,
            self.n,
            self.arena_slots,
            gib(self.arena_bytes),
            self.shard_slots,
            self.cache_cap,
            self.h,
            self.staging,
            self.m_ring,
            self.entries,
            self.buckets,
            self.ghost_buckets,
            self.sketch_lines,
            self.devices,
            gib(self.device_bytes),
            self.region_bytes >> 20,
            self.slots_per_region,
            self.footer_bytes >> 10,
            self.regions,
            self.ssd_slots,
            self.k_ahead,
            100.0 * (self.cache_cap * self.n as u64) as f64
                / ((self.cache_cap * self.n as u64) + self.ssd_slots) as f64
        )
    }
}

fn arena_bytes(slots: u64, s: u64, spc: u64) -> u64 {
    if slots == 0 {
        return 0;
    }
    let last = slots - 1;
    (last / spc) * CHUNK + (last % spc) * s + s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(v: u32, mem: u64, n: u16) -> Config {
        let text = format!(
            "value_size = {v}\nmemory_bytes = {mem}\nworkers = {n}\ndevices = [\"/dev/null\"]\n[[listeners]]\naddr = \"127.0.0.1:0\"\nproto = \"memcache\"\n"
        );
        toml::from_str(&text).unwrap()
    }

    /// Design §3.5, V = 64 KiB column.
    #[test]
    fn example_64k() {
        let c = cfg(65536, 192 << 30, 16);
        let g = Geometry::compute(&c, 4_000_000_000_000).unwrap();
        assert_eq!(g.s, 65536);
        assert_eq!(g.slots_per_chunk, 16384);
        assert_eq!(g.arena_slots, 3_145_728);
        assert_eq!(g.shard_slots, 196_608);
        assert_eq!(g.h, 1216);
        assert_eq!(g.staging, 1152);
        assert_eq!(g.cache_cap, 194_240);
        assert_eq!(g.m_ring, 262_144);
        assert_eq!(g.slots_per_region, 1023);
        assert_eq!(g.footer_bytes, 32768);
        assert_eq!(g.regions, 55_432);
        assert_eq!(g.ssd_slots, 56_706_936);
    }

    /// Design §3.5, V = 20,000 B column.
    #[test]
    fn example_20k() {
        let c = cfg(20_000, 192 << 30, 16);
        let g = Geometry::compute(&c, 4_000_000_000_000).unwrap();
        assert_eq!(g.s, 20480);
        assert_eq!(g.slots_per_chunk, 52_428);
        assert_eq!(g.arena_slots, 10_066_176);
        assert_eq!(g.shard_slots, 629_136);
        assert_eq!(g.cache_cap, 626_768);
        assert_eq!(g.slots_per_region, 3271);
        assert_eq!(g.regions, 55_432);
        assert_eq!(g.ssd_slots, 181_318_072);
    }

    #[test]
    fn open_lag_limit_stays_above_one_round_of_opens() {
        for (n, dev) in [(2u16, 2u64 << 30), (8, 4 << 30), (8, 64 << 30), (64, 32 << 30), (64, 4096 << 30)] {
            let g = Geometry::compute(&cfg(65536, 96 << 30, n), dev).unwrap();
            assert!(g.open_lag_limit >= 2 * n as u64, "{n} {dev}: {}", g.open_lag_limit);
            assert!(g.open_lag_limit + g.k_ahead + 2 * n as u64 + 2 <= g.regions, "{n} {dev}");
        }
        assert!(Geometry::compute(&cfg(65536, 96 << 30, 8), 2 << 30).unwrap_err().contains("need more regions"));
    }

    #[test]
    fn slot_mapping_never_straddles() {
        let c = cfg(100_000, 3 << 30, 2);
        let g = Geometry::compute(&c, 64 << 30).unwrap();
        for slot in [0u32, 1, g.slots_per_chunk as u32 - 1, g.slots_per_chunk as u32, g.arena_slots as u32 - 1] {
            let off = g.slot_offset(slot);
            assert_eq!(off / CHUNK, (off + g.s - 1) / CHUNK, "slot {slot} straddles");
            assert!(off + g.s <= g.arena_bytes);
        }
    }
}
