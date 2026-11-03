//! Key hashing and the bit map of design §2.2. No field derived here overlaps a field it
//! must be independent of.

use crate::proto::Key;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct H {
    pub hi: u64,
    pub lo: u64,
}

#[derive(Copy, Clone, Debug)]
pub struct Hasher {
    seed: u64,
}

impl Hasher {
    pub fn new(seed: u64) -> Self {
        Hasher { seed }
    }
    #[inline]
    pub fn hash(&self, key: &Key) -> H {
        let h = xxhash_rust::xxh3::xxh3_128_with_seed(key, self.seed);
        H { hi: (h >> 64) as u64, lo: h as u64 }
    }
}

#[inline]
pub fn fast_range32(x: u32, n: u64) -> u64 {
    ((x as u64) * n) >> 32
}

impl H {
    /// Owner shard: `hi[63:32]`.
    #[inline]
    pub fn shard(&self, n: u16) -> u16 {
        fast_range32((self.hi >> 32) as u32, n as u64) as u16
    }
    /// 16-bit non-zero index tag: `hi[15:0]`.
    #[inline]
    pub fn tag(&self) -> u16 {
        let t = self.hi as u16;
        if t == 0 { 1 } else { t }
    }
    /// First index bucket: `lo[31:0]`.
    #[inline]
    pub fn bucket1(&self, nbuckets: u64) -> u64 {
        fast_range32(self.lo as u32, nbuckets)
    }
    /// Ghost bucket: `hi[31:0]`.
    #[inline]
    pub fn ghost_bucket(&self, nb: u64) -> u64 {
        fast_range32(self.hi as u32, nb)
    }
    /// Ghost fingerprint: `lo[63:32]`, non-zero.
    #[inline]
    pub fn ghost_fp(&self) -> u32 {
        let f = (self.lo >> 32) as u32;
        if f == 0 { 1 } else { f }
    }
    /// Sketch remix.
    #[inline]
    pub fn sketch_mix(&self) -> u64 {
        (self.lo ^ self.hi.rotate_left(29)).wrapping_mul(0x9E37_79B9_7F4A_7C15)
    }
}

/// The alternate cuckoo bucket: `(f(tag) − b) mod n`, an involution for any n.
#[inline]
pub fn alt_bucket(tag: u16, b: u64, n: u64) -> u64 {
    let f = ((tag as u64).wrapping_mul(0x5bd1_e995)) % n;
    (f + n - b) % n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_is_involution() {
        for n in [1u64, 2, 3, 7, 1000, 1 << 20, 8_783_000] {
            for tag in [1u16, 2, 77, 65535] {
                for b in [0, n / 2, n - 1] {
                    let a = alt_bucket(tag, b, n);
                    assert!(a < n);
                    assert_eq!(alt_bucket(tag, a, n), b);
                }
            }
        }
    }

    #[test]
    fn shard_spread() {
        let h = Hasher::new(7);
        let mut counts = [0u32; 16];
        for i in 0u64..160_000 {
            let mut k = [0u8; 16];
            k[..8].copy_from_slice(&i.to_le_bytes());
            counts[h.hash(&k).shard(16) as usize] += 1;
        }
        for c in counts {
            assert!((9000..11000).contains(&c), "{counts:?}");
        }
    }
}
