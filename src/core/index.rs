//! Entry slab and per-shard bucketized cuckoo index (design §3.3).
//! Single writer (the owner shard); no atomics.

use super::NONE;
use crate::hash::{H, alt_bucket};
use crate::proto::Key;

// meta: q:1 | freq:2 | hit:1 | gadmit:1 | dead:1 | reading:1 | writing:1 | lap:8 | rsv:16
const Q: u32 = 1 << 0;
const FREQ_SHIFT: u32 = 1;
const FREQ_MASK: u32 = 0b11 << FREQ_SHIFT;
const HIT: u32 = 1 << 3;
const GADMIT: u32 = 1 << 4;
const DEAD: u32 = 1 << 5;
const READING: u32 = 1 << 6;
const WRITING: u32 = 1 << 7;
const LAP_SHIFT: u32 = 8;
const LAP_MASK: u32 = 0xff << LAP_SHIFT;
/// In-use marker for slab bookkeeping (free handles have it clear).
const ALLOCATED: u32 = 1 << 31;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Entry {
    pub key: Key,
    pub mem: u32,
    pub ssd: u32,
    pub ver: u32,
    meta: u32,
}

const _: () = assert!(std::mem::size_of::<Entry>() == 32);

impl Entry {
    #[inline]
    pub fn in_m(&self) -> bool {
        self.meta & Q != 0
    }
    #[inline]
    pub fn set_in_m(&mut self, v: bool) {
        if v { self.meta |= Q } else { self.meta &= !Q }
    }
    #[inline]
    pub fn freq(&self) -> u8 {
        ((self.meta & FREQ_MASK) >> FREQ_SHIFT) as u8
    }
    #[inline]
    pub fn set_freq(&mut self, f: u8) {
        self.meta = (self.meta & !FREQ_MASK) | (((f.min(3)) as u32) << FREQ_SHIFT);
    }
    #[inline]
    pub fn bump_freq(&mut self) {
        let f = self.freq();
        if f < 3 {
            self.set_freq(f + 1)
        }
    }
    #[inline]
    pub fn hit(&self) -> bool {
        self.meta & HIT != 0
    }
    #[inline]
    pub fn set_hit(&mut self) {
        self.meta |= HIT
    }
    #[inline]
    pub fn gadmit(&self) -> bool {
        self.meta & GADMIT != 0
    }
    #[inline]
    pub fn set_gadmit(&mut self, v: bool) {
        if v { self.meta |= GADMIT } else { self.meta &= !GADMIT }
    }
    #[inline]
    pub fn dead(&self) -> bool {
        self.meta & DEAD != 0
    }
    #[inline]
    pub fn set_dead(&mut self) {
        self.meta |= DEAD
    }
    #[inline]
    pub fn reading(&self) -> bool {
        self.meta & READING != 0
    }
    #[inline]
    pub fn set_reading(&mut self, v: bool) {
        if v { self.meta |= READING } else { self.meta &= !READING }
    }
    #[inline]
    pub fn writing(&self) -> bool {
        self.meta & WRITING != 0
    }
    #[inline]
    pub fn set_writing(&mut self, v: bool) {
        if v { self.meta |= WRITING } else { self.meta &= !WRITING }
    }
    #[inline]
    pub fn lap(&self) -> u8 {
        ((self.meta & LAP_MASK) >> LAP_SHIFT) as u8
    }
    #[inline]
    pub fn set_lap(&mut self, l: u8) {
        self.meta = (self.meta & !LAP_MASK) | ((l as u32) << LAP_SHIFT);
    }
    /// A handle can be reused only when nothing refers to it (design §3.3).
    #[inline]
    pub fn unreferenced(&self) -> bool {
        !self.in_m() && !self.reading() && !self.writing()
    }
}

pub struct Slab {
    ents: Box<[Entry]>,
    free: Box<[u32]>,
    n_free: u32,
}

impl Slab {
    pub fn new(cap: u32) -> Self {
        let ents = vec![Entry { key: [0; 16], mem: NONE, ssd: NONE, ver: 0, meta: 0 }; cap as usize];
        let free: Vec<u32> = (0..cap).rev().collect();
        Slab { ents: ents.into_boxed_slice(), free: free.into_boxed_slice(), n_free: cap }
    }
    pub fn alloc(&mut self, key: &Key) -> Option<u32> {
        if self.n_free == 0 {
            return None;
        }
        self.n_free -= 1;
        let eh = self.free[self.n_free as usize];
        let e = &mut self.ents[eh as usize];
        debug_assert_eq!(e.meta & ALLOCATED, 0);
        // `ver` is never reset on reuse (ABA guard for back-map and IO completions).
        e.key = *key;
        e.mem = NONE;
        e.ssd = NONE;
        e.ver = e.ver.wrapping_add(1);
        e.meta = ALLOCATED;
        Some(eh)
    }
    pub fn free(&mut self, eh: u32) {
        let e = &mut self.ents[eh as usize];
        debug_assert!(e.meta & ALLOCATED != 0);
        debug_assert!(e.unreferenced());
        e.meta = 0;
        e.ver = e.ver.wrapping_add(1);
        e.mem = NONE;
        e.ssd = NONE;
        self.free[self.n_free as usize] = eh;
        self.n_free += 1;
    }
    pub fn is_allocated(&self, eh: u32) -> bool {
        self.ents[eh as usize].meta & ALLOCATED != 0
    }
    pub fn in_use(&self) -> u32 {
        self.ents.len() as u32 - self.n_free
    }
    pub fn capacity(&self) -> u32 {
        self.ents.len() as u32
    }
}

impl std::ops::Index<u32> for Slab {
    type Output = Entry;
    #[inline]
    fn index(&self, eh: u32) -> &Entry {
        &self.ents[eh as usize]
    }
}
impl std::ops::IndexMut<u32> for Slab {
    #[inline]
    fn index_mut(&mut self, eh: u32) -> &mut Entry {
        &mut self.ents[eh as usize]
    }
}

#[repr(C, align(64))]
#[derive(Copy, Clone)]
struct Bucket {
    tags: [u16; 8],
    eh: [u32; 8],
    _pad: [u8; 16],
}

const _: () = assert!(std::mem::size_of::<Bucket>() == 64);

const STASH: usize = 64;
const MAX_KICKS: u32 = 128;

pub struct Index {
    buckets: Box<[Bucket]>,
    n: u64,
    stash: [(u16, u32); STASH],
    n_stash: usize,
    kick: u32,
    pub len: u64,
}

impl Index {
    pub fn new(nbuckets: u64) -> Self {
        let b = Bucket { tags: [0; 8], eh: [NONE; 8], _pad: [0; 16] };
        Index {
            buckets: vec![b; nbuckets as usize].into_boxed_slice(),
            n: nbuckets,
            stash: [(0, NONE); STASH],
            n_stash: 0,
            kick: 0,
            len: 0,
        }
    }

    #[inline]
    fn probe(&self, b: u64, tag: u16, key: &Key, slab: &Slab) -> Option<(u64, usize)> {
        let bk = &self.buckets[b as usize];
        for w in 0..8 {
            if bk.tags[w] == tag && slab[bk.eh[w]].key == *key {
                return Some((b, w));
            }
        }
        None
    }

    pub fn find(&self, h: &H, key: &Key, slab: &Slab) -> Option<u32> {
        let tag = h.tag();
        let b1 = h.bucket1(self.n);
        if let Some((b, w)) = self.probe(b1, tag, key, slab) {
            return Some(self.buckets[b as usize].eh[w]);
        }
        let b2 = alt_bucket(tag, b1, self.n);
        if let Some((b, w)) = self.probe(b2, tag, key, slab) {
            return Some(self.buckets[b as usize].eh[w]);
        }
        self.stash[..self.n_stash].iter().find(|&&(t, eh)| t == tag && slab[eh].key == *key).map(|&(_, eh)| eh)
    }

    /// Insert a handle whose key is not present. On `Err(victim)` the index was too full
    /// (stash overflow, far above the 0.85 design point): `victim` (possibly a different
    /// handle than `eh`, displaced by the cuckoo walk) is no longer indexed and the caller
    /// must drop it.
    pub fn insert(&mut self, h: &H, eh: u32) -> Result<(), u32> {
        let tag = h.tag();
        let b1 = h.bucket1(self.n);
        let b2 = alt_bucket(tag, b1, self.n);
        for b in [b1, b2] {
            let bk = &mut self.buckets[b as usize];
            if let Some(w) = bk.tags.iter().position(|&t| t == 0) {
                bk.tags[w] = tag;
                bk.eh[w] = eh;
                self.len += 1;
                return Ok(());
            }
        }
        // Random-walk cuckoo displacement, bounded.
        let (mut tag, mut eh, mut b) = (tag, eh, b1);
        for _ in 0..MAX_KICKS {
            self.kick = self.kick.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let w = ((self.kick >> 16) & 7) as usize;
            let bk = &mut self.buckets[b as usize];
            std::mem::swap(&mut bk.tags[w], &mut tag);
            std::mem::swap(&mut bk.eh[w], &mut eh);
            b = alt_bucket(tag, b, self.n);
            let bk = &mut self.buckets[b as usize];
            if let Some(w) = bk.tags.iter().position(|&t| t == 0) {
                bk.tags[w] = tag;
                bk.eh[w] = eh;
                self.len += 1;
                return Ok(());
            }
        }
        if self.n_stash < STASH {
            self.stash[self.n_stash] = (tag, eh);
            self.n_stash += 1;
            self.len += 1;
            return Ok(());
        }
        Err(eh)
    }

    /// Remove `key`. Returns its handle.
    pub fn remove(&mut self, h: &H, key: &Key, slab: &Slab) -> Option<u32> {
        let tag = h.tag();
        let b1 = h.bucket1(self.n);
        let b2 = alt_bucket(tag, b1, self.n);
        for b in [b1, b2] {
            if let Some((b, w)) = self.probe(b, tag, key, slab) {
                let bk = &mut self.buckets[b as usize];
                let eh = bk.eh[w];
                bk.tags[w] = 0;
                bk.eh[w] = NONE;
                self.len -= 1;
                return Some(eh);
            }
        }
        if let Some(i) = self.stash[..self.n_stash].iter().position(|&(t, eh)| t == tag && slab[eh].key == *key) {
            let eh = self.stash[i].1;
            self.n_stash -= 1;
            self.stash[i] = self.stash[self.n_stash];
            self.len -= 1;
            return Some(eh);
        }
        None
    }

    pub fn stash_len(&self) -> usize {
        self.n_stash
    }
}
