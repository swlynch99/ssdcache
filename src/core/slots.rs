//! Per-shard slot pools (design §3.2, §4.4, §5.1). Two pools share one partition of the
//! arena: the **cache pool** (M objects, Filling slots, zombies, slots pinned by demotion
//! writes) and the **staging pool** (SSD read buffers only; never indexed or cached).
//!
//! Slot ids are global (dense over the whole arena) so a `Hit{slot}` names memory any
//! worker can send from. Only the owner shard touches the metadata.

use super::NONE;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlotState {
    Free = 0,
    Filling = 1,
    Live = 2,
    Zombie = 3,
    Staging = 4,
    StagingRetired = 5,
    StagingFree = 6,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SlotMeta {
    pub pins: u16,
    pub state: SlotState,
    pub sgen: u32,
}

pub struct SlotPool {
    base: u32,
    cache_n: u32,
    staging_n: u32,
    meta: Box<[SlotMeta]>,
    free_cache: Box<[u32]>,
    n_free_cache: u32,
    free_staging: Box<[u32]>,
    n_free_staging: u32,
    // accounting
    pub zombies: u32,
    pub filling: u32,
    pub staging_held: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GenErr {
    Stale,
}

impl SlotPool {
    /// `base`: global id of this shard's first slot. Layout: `[cache_n | staging_n]`.
    pub fn new(base: u32, cache_n: u32, staging_n: u32) -> Self {
        let total = (cache_n + staging_n) as usize;
        let mut meta = Vec::with_capacity(total);
        for i in 0..total {
            let st = if (i as u32) < cache_n { SlotState::Free } else { SlotState::StagingFree };
            meta.push(SlotMeta { pins: 0, state: st, sgen: 0 });
        }
        // LIFO free lists; pop from the end, so push in reverse to hand out low ids first.
        let free_cache: Vec<u32> = (0..cache_n).rev().map(|i| base + i).collect();
        let free_staging: Vec<u32> = (0..staging_n).rev().map(|i| base + cache_n + i).collect();
        SlotPool {
            base,
            cache_n,
            staging_n,
            meta: meta.into_boxed_slice(),
            free_cache: free_cache.into_boxed_slice(),
            n_free_cache: cache_n,
            free_staging: free_staging.into_boxed_slice(),
            n_free_staging: staging_n,
            zombies: 0,
            filling: 0,
            staging_held: 0,
        }
    }

    #[inline]
    fn m(&self, slot: u32) -> &SlotMeta {
        &self.meta[(slot - self.base) as usize]
    }
    #[inline]
    fn mm(&mut self, slot: u32) -> &mut SlotMeta {
        &mut self.meta[(slot - self.base) as usize]
    }

    pub fn owns(&self, slot: u32) -> bool {
        slot >= self.base && slot < self.base + self.cache_n + self.staging_n
    }
    pub fn is_staging(&self, slot: u32) -> bool {
        slot >= self.base + self.cache_n
    }
    #[inline]
    pub fn free_slots(&self) -> u32 {
        self.n_free_cache
    }
    pub fn free_staging(&self) -> u32 {
        self.n_free_staging
    }
    pub fn cache_n(&self) -> u32 {
        self.cache_n
    }
    pub fn staging_n(&self) -> u32 {
        self.staging_n
    }
    pub fn state(&self, slot: u32) -> SlotState {
        self.m(slot).state
    }
    pub fn slot_gen(&self, slot: u32) -> u32 {
        self.m(slot).sgen
    }
    pub fn pins(&self, slot: u32) -> u16 {
        self.m(slot).pins
    }

    // ---- cache pool ----

    pub fn alloc_filling(&mut self) -> Option<(u32, u32)> {
        if self.n_free_cache == 0 {
            return None;
        }
        self.n_free_cache -= 1;
        let slot = self.free_cache[self.n_free_cache as usize];
        let m = self.mm(slot);
        debug_assert_eq!(m.state, SlotState::Free);
        m.state = SlotState::Filling;
        let g = m.sgen;
        self.filling += 1;
        Some((slot, g))
    }

    /// Validate a (slot, gen) pair that names a Filling slot.
    pub fn check_filling(&self, slot: u32, g: u32) -> Result<(), GenErr> {
        if !self.owns(slot) || self.is_staging(slot) {
            return Err(GenErr::Stale);
        }
        let m = self.m(slot);
        if m.sgen != g || m.state != SlotState::Filling { Err(GenErr::Stale) } else { Ok(()) }
    }

    pub fn mark_live(&mut self, slot: u32) {
        let m = self.mm(slot);
        debug_assert_eq!(m.state, SlotState::Filling);
        m.state = SlotState::Live;
        self.filling -= 1;
    }

    /// Abort / not-stored: Filling → Free.
    pub fn free_filling(&mut self, slot: u32) {
        debug_assert_eq!(self.m(slot).state, SlotState::Filling);
        self.filling -= 1;
        self.release(slot);
    }

    fn release(&mut self, slot: u32) {
        let m = self.mm(slot);
        m.state = SlotState::Free;
        m.pins = 0;
        m.sgen = m.sgen.wrapping_add(1);
        self.free_cache[self.n_free_cache as usize] = slot;
        self.n_free_cache += 1;
    }

    /// Pin a Live cache slot or a Staging buffer. Returns the gen to carry in `Hit`.
    #[inline]
    pub fn pin(&mut self, slot: u32) -> u32 {
        let m = self.mm(slot);
        debug_assert!(matches!(m.state, SlotState::Live | SlotState::Staging), "{:?}", m.state);
        m.pins += 1;
        m.sgen
    }

    /// Logical eviction of a Live cache slot: free now if unpinned, else Zombie.
    pub fn retire(&mut self, slot: u32) {
        let m = self.mm(slot);
        debug_assert_eq!(m.state, SlotState::Live);
        if m.pins == 0 {
            self.release(slot);
        } else {
            m.state = SlotState::Zombie;
            self.zombies += 1;
        }
    }

    /// Release one pin (send done / write done). Returns true if the slot was freed.
    pub fn unpin(&mut self, slot: u32, g: u32) -> Result<bool, GenErr> {
        if !self.owns(slot) {
            return Err(GenErr::Stale);
        }
        let m = self.mm(slot);
        if m.sgen != g || m.pins == 0 {
            return Err(GenErr::Stale);
        }
        m.pins -= 1;
        if m.pins > 0 {
            return Ok(false);
        }
        match m.state {
            SlotState::Zombie => {
                self.zombies -= 1;
                self.release(slot);
                Ok(true)
            }
            SlotState::StagingRetired => {
                self.release_staging(slot);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    // ---- staging pool ----

    pub fn alloc_staging(&mut self) -> Option<u32> {
        if self.n_free_staging == 0 {
            return None;
        }
        self.n_free_staging -= 1;
        let slot = self.free_staging[self.n_free_staging as usize];
        let m = self.mm(slot);
        debug_assert_eq!(m.state, SlotState::StagingFree);
        m.state = SlotState::Staging;
        self.staging_held += 1;
        Some(slot)
    }

    /// Done handing out pins on a staging buffer: it returns to the pool at the last unpin.
    pub fn retire_staging(&mut self, slot: u32) {
        let m = self.mm(slot);
        debug_assert_eq!(m.state, SlotState::Staging);
        if m.pins == 0 {
            self.release_staging(slot);
        } else {
            m.state = SlotState::StagingRetired;
        }
    }

    fn release_staging(&mut self, slot: u32) {
        let m = self.mm(slot);
        m.state = SlotState::StagingFree;
        m.pins = 0;
        m.sgen = m.sgen.wrapping_add(1);
        self.free_staging[self.n_free_staging as usize] = slot;
        self.n_free_staging += 1;
        self.staging_held -= 1;
    }

    /// Debug: check the pool's accounting invariants. O(pool).
    pub fn check(&self) -> Result<(), String> {
        let mut free = 0;
        let mut zombies = 0;
        let mut filling = 0;
        let mut sfree = 0;
        for (i, m) in self.meta.iter().enumerate() {
            let staging = (i as u32) >= self.cache_n;
            match m.state {
                SlotState::Free => free += 1,
                SlotState::Zombie => {
                    zombies += 1;
                    if m.pins == 0 {
                        return Err(format!("zombie {} without pins", self.base + i as u32));
                    }
                }
                SlotState::Filling => filling += 1,
                SlotState::StagingFree => sfree += 1,
                SlotState::StagingRetired if m.pins == 0 => {
                    return Err("retired staging without pins".into());
                }
                _ => {}
            }
            if staging != matches!(m.state, SlotState::Staging | SlotState::StagingRetired | SlotState::StagingFree) {
                return Err(format!("slot {} in wrong pool: {:?}", self.base + i as u32, m.state));
            }
        }
        if free != self.n_free_cache || zombies != self.zombies || filling != self.filling || sfree != self.n_free_staging {
            return Err(format!(
                "slot accounting: free {free}/{} zombies {zombies}/{} filling {filling}/{} sfree {sfree}/{}",
                self.n_free_cache, self.zombies, self.filling, self.n_free_staging
            ));
        }
        Ok(())
    }
}

impl Default for SlotMeta {
    fn default() -> Self {
        SlotMeta { pins: 0, state: SlotState::Free, sgen: 0 }
    }
}

#[allow(dead_code)]
const _: () = assert!(NONE == u32::MAX);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zombie_lifecycle() {
        let mut p = SlotPool::new(100, 4, 2);
        let (s, g) = p.alloc_filling().unwrap();
        p.mark_live(s);
        let g2 = p.pin(s);
        assert_eq!(g, g2);
        p.retire(s);
        assert_eq!(p.state(s), SlotState::Zombie);
        assert_eq!(p.free_slots(), 3);
        assert_eq!(p.unpin(s, g), Ok(true));
        assert_eq!(p.free_slots(), 4);
        assert_eq!(p.unpin(s, g), Err(GenErr::Stale));
        p.check().unwrap();
    }

    #[test]
    fn staging_lifecycle() {
        let mut p = SlotPool::new(0, 2, 2);
        let b = p.alloc_staging().unwrap();
        assert!(p.is_staging(b));
        let g = p.pin(b);
        p.pin(b);
        p.retire_staging(b);
        assert_eq!(p.free_staging(), 1);
        assert_eq!(p.unpin(b, g), Ok(false));
        assert_eq!(p.unpin(b, g), Ok(true));
        assert_eq!(p.free_staging(), 2);
        p.check().unwrap();
    }
}
