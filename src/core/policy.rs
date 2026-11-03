//! Pure policy structures (design §4): the M CLOCK ring, the ghost G, the blocked
//! count-min sketch and the SSD write budget with the θ feedback threshold.
//! No IO, no allocation after construction; shared by the server and the simulator.

use crate::hash::H;

// ---------------------------------------------------------------- M ring

/// FIFO ring of entry handles (CLOCK reinsertion is pop + push).
pub struct MRing {
    buf: Box<[u32]>,
    mask: u64,
    head: u64,
    tail: u64,
}

impl MRing {
    pub fn new(cap_pow2: u64) -> Self {
        assert!(cap_pow2.is_power_of_two());
        MRing { buf: vec![0; cap_pow2 as usize].into_boxed_slice(), mask: cap_pow2 - 1, head: 0, tail: 0 }
    }
    #[inline]
    pub fn len(&self) -> u64 {
        self.tail - self.head
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tail == self.head
    }
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() == self.mask + 1
    }
    #[inline]
    pub fn push(&mut self, eh: u32) {
        debug_assert!(!self.is_full());
        self.buf[(self.tail & self.mask) as usize] = eh;
        self.tail += 1;
    }
    #[inline]
    pub fn pop(&mut self) -> Option<u32> {
        if self.is_empty() {
            return None;
        }
        let eh = self.buf[(self.head & self.mask) as usize];
        self.head += 1;
        Some(eh)
    }
    pub fn capacity(&self) -> u64 {
        self.mask + 1
    }
}

// ---------------------------------------------------------------- ghost

/// Bucketed fingerprint ghost. An entry is live while `vts ≥ n_ins − cap`, so the ghost
/// behaves like a FIFO of the last `cap` insertions without per-entry eviction work.
pub struct Ghost {
    b: Box<[[(u32, u32); 8]]>,
    nb: u64,
    cap: u64,
    n_ins: u64,
}

impl Ghost {
    pub fn new(buckets: u64) -> Self {
        Ghost { b: vec![[(0u32, 0u32); 8]; buckets as usize].into_boxed_slice(), nb: buckets, cap: buckets * 8, n_ins: 0 }
    }

    #[inline]
    fn live(&self, vts: u32) -> bool {
        // vts is n_ins truncated to 32 bits; compare in modular arithmetic.
        let age = (self.n_ins as u32).wrapping_sub(vts) as u64;
        age < self.cap
    }

    pub fn insert(&mut self, h: &H) {
        let fp = h.ghost_fp();
        self.n_ins += 1;
        let vts = self.n_ins as u32;
        let nb = self.nb;
        let bi = h.ghost_bucket(nb) as usize;
        // Replace: same fp, else an empty/expired way, else the oldest.
        let mut victim = 0;
        let mut oldest_age = 0u32;
        for w in 0..8 {
            let (f, v) = self.b[bi][w];
            if f == fp {
                victim = w;
                break;
            }
            let age = if f == 0 { u32::MAX } else { vts.wrapping_sub(v) };
            if age >= oldest_age {
                oldest_age = age;
                victim = w;
            }
        }
        self.b[bi][victim] = (fp, vts);
    }

    /// Consume the ghost entry for `h` if present and live.
    pub fn take(&mut self, h: &H) -> bool {
        let fp = h.ghost_fp();
        let bi = h.ghost_bucket(self.nb) as usize;
        for w in 0..8 {
            let (f, v) = self.b[bi][w];
            if f == fp {
                self.b[bi][w] = (0, 0);
                return self.live(v);
            }
        }
        false
    }
}

// ---------------------------------------------------------------- sketch

/// Blocked count-min sketch: 4 × 4-bit counters per key, all in one 64 B line.
/// Halving ("aging") is incremental: `age_step` halves a bounded number of lines per tick.
pub struct Sketch {
    lines: Box<[[u64; 8]]>,
    nlines: u64,
    incs: u64,
    reset_at: u64,
    aging_cursor: Option<u64>,
}

impl Sketch {
    pub fn new(lines: u64, reset_at: u64) -> Self {
        Sketch { lines: vec![[0u64; 8]; lines as usize].into_boxed_slice(), nlines: lines, incs: 0, reset_at, aging_cursor: None }
    }

    #[inline]
    fn pos(&self, h: &H) -> (usize, [u32; 4]) {
        let m = h.sketch_mix();
        let line = crate::hash::fast_range32((m >> 32) as u32, self.nlines) as usize;
        // 128 counters per line → 7 bits each; take 4 positions from m[27:0], one per word pair.
        let p = [
            (m & 0x1f) as u32,
            32 + ((m >> 5) & 0x1f) as u32,
            64 + ((m >> 10) & 0x1f) as u32,
            96 + ((m >> 15) & 0x1f) as u32,
        ];
        (line, p)
    }

    #[inline]
    fn get(line: &[u64; 8], c: u32) -> u8 {
        ((line[(c / 16) as usize] >> ((c % 16) * 4)) & 0xf) as u8
    }

    #[inline]
    fn set(line: &mut [u64; 8], c: u32, v: u8) {
        let w = &mut line[(c / 16) as usize];
        let sh = (c % 16) * 4;
        *w = (*w & !(0xf << sh)) | ((v as u64) << sh);
    }

    /// Conservative update: only the minimum counters are incremented.
    pub fn inc(&mut self, h: &H) {
        let (li, p) = self.pos(h);
        let line = &mut self.lines[li];
        let min = p.iter().map(|&c| Self::get(line, c)).min().unwrap_or(0);
        if min < 15 {
            for &c in &p {
                if Self::get(line, c) == min {
                    Self::set(line, c, min + 1);
                }
            }
        }
        self.incs += 1;
        if self.incs >= self.reset_at && self.aging_cursor.is_none() {
            self.aging_cursor = Some(0);
            self.incs = 0;
        }
    }

    pub fn est(&self, h: &H) -> u8 {
        let (li, p) = self.pos(h);
        let line = &self.lines[li];
        p.iter().map(|&c| Self::get(line, c)).min().unwrap_or(0)
    }

    /// Halve up to `max_lines` lines of a pending aging pass.
    pub fn age_step(&mut self, max_lines: u64) {
        let Some(cur) = self.aging_cursor else { return };
        let end = (cur + max_lines).min(self.nlines);
        for li in cur..end {
            for w in self.lines[li as usize].iter_mut() {
                *w = (*w >> 1) & 0x7777_7777_7777_7777;
            }
        }
        self.aging_cursor = if end == self.nlines { None } else { Some(end) };
    }
}

// ---------------------------------------------------------------- write budget

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Deny {
    Theta,
    NoTokens,
}

/// Per-shard token bucket over SSD bytes, plus the θ feedback threshold (design §4.5).
pub struct Budget {
    /// Bytes per second.
    pub rate: f64,
    pub burst: f64,
    pub tokens: f64,
    pub cost: f64,
    last_ns: u64,
    pub theta: u8,
    pub use_sketch: bool,
    interval_ns: u64,
    next_adjust_ns: u64,
    dry: u32,
    overflowed: bool,
    /// Demand: candidates seen this interval (for rebalancing).
    pub demand: u64,
}

impl Budget {
    pub fn new(rate: f64, burst_s: f64, cost: u64, use_sketch: bool) -> Self {
        let burst = (rate * burst_s).max(cost as f64);
        Budget {
            rate,
            burst,
            tokens: burst,
            cost: cost as f64,
            last_ns: 0,
            theta: 0,
            use_sketch,
            interval_ns: 1_000_000_000,
            next_adjust_ns: 1_000_000_000,
            dry: 0,
            overflowed: false,
            demand: 0,
        }
    }

    pub fn set_rate(&mut self, rate: f64, burst_s: f64) {
        self.rate = rate;
        self.burst = (rate * burst_s).max(self.cost);
        self.tokens = self.tokens.min(self.burst);
    }

    pub fn refill(&mut self, now_ns: u64) {
        if now_ns > self.last_ns {
            let dt = (now_ns - self.last_ns) as f64 * 1e-9;
            self.tokens += self.rate * dt;
            if self.tokens >= self.burst {
                self.tokens = self.burst;
                self.overflowed = true;
            }
            self.last_ns = now_ns;
        }
        if now_ns >= self.next_adjust_ns {
            if self.use_sketch {
                if self.dry > 0 {
                    self.theta = (self.theta + 1).min(15);
                } else if self.overflowed && self.theta > 0 {
                    self.theta -= 1;
                }
            }
            self.dry = 0;
            self.overflowed = false;
            self.next_adjust_ns = now_ns + self.interval_ns;
        }
    }

    /// Admission check for one demotion candidate with sketch estimate `est`.
    pub fn admit(&mut self, est: u8, gadmit: bool) -> Result<(), Deny> {
        self.demand += 1;
        if self.use_sketch {
            let th = if gadmit { self.theta.saturating_sub(1) } else { self.theta };
            if est < th {
                return Err(Deny::Theta);
            }
        }
        if self.tokens < self.cost {
            self.dry += 1;
            return Err(Deny::NoTokens);
        }
        self.tokens -= self.cost;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: u64) -> H {
        crate::hash::Hasher::new(1).hash(&{
            let mut k = [0u8; 16];
            k[..8].copy_from_slice(&i.to_le_bytes());
            k
        })
    }

    #[test]
    fn ghost_fifo_window() {
        let mut g = Ghost::new(1024);
        for i in 0..100 {
            g.insert(&h(i));
        }
        assert!(g.take(&h(5)));
        assert!(!g.take(&h(5)));
        assert!(!g.take(&h(1000)));
        // Push far past capacity: old entries expire.
        for i in 1000..1000 + 8 * 1024 * 2 {
            g.insert(&h(i));
        }
        let survivors = (0..100).filter(|&i| g.take(&h(i))).count();
        assert_eq!(survivors, 0);
    }

    #[test]
    fn sketch_counts_and_ages() {
        let mut s = Sketch::new(64, 1 << 40);
        for _ in 0..5 {
            s.inc(&h(1));
        }
        s.inc(&h(2));
        assert!(s.est(&h(1)) >= 5);
        assert!(s.est(&h(2)) >= 1);
        s.aging_cursor = Some(0);
        s.age_step(1000);
        assert!(s.est(&h(1)) >= 2 && s.est(&h(1)) <= 3);
    }

    #[test]
    fn budget_rate() {
        let mut b = Budget::new(1000.0, 1.0, 100, true);
        let mut ok = 0;
        for t in 0..10_000u64 {
            b.refill(t * 1_000_000); // 10 s in 1 ms steps
            if b.admit(15, false).is_ok() {
                ok += 1;
            }
        }
        // 1 s burst (10) + 10 s × 10/s
        assert!((105..=112).contains(&ok), "{ok}");
        assert!(b.theta > 0);
    }

    #[test]
    fn mring() {
        let mut r = MRing::new(4);
        for i in 0..4 {
            r.push(i);
        }
        assert!(r.is_full());
        assert_eq!(r.pop(), Some(0));
        r.push(9);
        assert_eq!((r.pop(), r.pop(), r.pop(), r.pop(), r.pop()), (Some(1), Some(2), Some(3), Some(9), None));
    }
}
