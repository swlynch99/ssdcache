//! Cross-shard messaging (design §2.4): one SPSC ring per ordered worker pair, a small
//! region-control ring per pair, and the fenced sleeping-flag doorbell over MSG_RING.

use crate::core::shard::{RegionMsg, Reply, ReqToken};
use crate::proto::{Key, SetMode};
use crossbeam_utils::CachePadded;
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering::*, fence};

/// Lock-free single-producer single-consumer ring. Producer and consumer each cache the
/// other side's index to avoid touching the shared line on every operation.
pub struct Spsc<T: Copy> {
    buf: Box<[UnsafeCell<MaybeUninit<T>>]>,
    mask: u32,
    head: CachePadded<AtomicU32>, // consumer position
    tail: CachePadded<AtomicU32>, // producer position
    cached_head: CachePadded<UnsafeCell<u32>>, // producer-private
    cached_tail: CachePadded<UnsafeCell<u32>>, // consumer-private
}

// Safety: exactly one producer thread calls `push` and one consumer thread calls `pop`
// (enforced by the mesh layout: ring (a, b) is pushed only by worker a, popped only by b).
unsafe impl<T: Copy + Send> Sync for Spsc<T> {}
unsafe impl<T: Copy + Send> Send for Spsc<T> {}

impl<T: Copy> Spsc<T> {
    pub fn new(cap: u32) -> Self {
        let cap = cap.next_power_of_two();
        Spsc {
            buf: (0..cap).map(|_| UnsafeCell::new(MaybeUninit::uninit())).collect(),
            mask: cap - 1,
            head: CachePadded::new(AtomicU32::new(0)),
            tail: CachePadded::new(AtomicU32::new(0)),
            cached_head: CachePadded::new(UnsafeCell::new(0)),
            cached_tail: CachePadded::new(UnsafeCell::new(0)),
        }
    }

    /// Producer only.
    #[inline]
    pub fn push(&self, v: T) -> Result<(), T> {
        let tail = self.tail.load(Relaxed);
        let ch = unsafe { &mut *self.cached_head.get() };
        if tail.wrapping_sub(*ch) > self.mask {
            *ch = self.head.load(Acquire);
            if tail.wrapping_sub(*ch) > self.mask {
                return Err(v);
            }
        }
        unsafe { (*self.buf[(tail & self.mask) as usize].get()).write(v) };
        self.tail.store(tail.wrapping_add(1), Release);
        Ok(())
    }

    /// Consumer only.
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let head = self.head.load(Relaxed);
        let ct = unsafe { &mut *self.cached_tail.get() };
        if head == *ct {
            *ct = self.tail.load(Acquire);
            if head == *ct {
                return None;
            }
        }
        let v = unsafe { (*self.buf[(head & self.mask) as usize].get()).assume_init() };
        self.head.store(head.wrapping_add(1), Release);
        Some(v)
    }

    /// Either side: is anything queued (Acquire on tail)?
    #[inline]
    pub fn is_empty_acquire(&self) -> bool {
        self.head.load(Relaxed) == self.tail.load(Acquire)
    }
}

/// One cache line per message.
#[derive(Copy, Clone, Debug)]
pub enum Msg {
    // A -> B (B = owner)
    Lookup { hi: u64, lo: u64, key: Key, req: ReqToken, exists: bool },
    Reserve { req: ReqToken },
    Commit { hi: u64, lo: u64, key: Key, slot: u32, sgen: u32, mode: SetMode, req: ReqToken },
    Abort { slot: u32, sgen: u32 },
    Delete { hi: u64, lo: u64, key: Key, req: ReqToken },
    Unpin { n: u8, slots: [(u32, u32); 5] },
    // B -> A
    Reply { req: ReqToken, r: Reply },
    Grant { slot: u32, sgen: u32 },
}

#[repr(C, align(64))]
#[derive(Copy, Clone, Debug)]
pub struct Line(pub Msg);
const _: () = assert!(std::mem::size_of::<Line>() == 64);

pub struct Mesh {
    pub n: u16,
    rings: Box<[Spsc<Line>]>,
    region: Box<[Spsc<RegionMsg>]>,
    pub sleeping: Box<[CachePadded<AtomicBool>]>,
    pub ring_fd: Box<[AtomicI32]>,
}

impl Mesh {
    pub fn new(n: u16, cap: u32) -> Self {
        let nn = n as usize * n as usize;
        Mesh {
            n,
            rings: (0..nn).map(|_| Spsc::new(cap)).collect(),
            region: (0..nn).map(|_| Spsc::new(64)).collect(),
            sleeping: (0..n).map(|_| CachePadded::new(AtomicBool::new(false))).collect(),
            ring_fd: (0..n).map(|_| AtomicI32::new(-1)).collect(),
        }
    }
    #[inline]
    pub fn ring(&self, from: u16, to: u16) -> &Spsc<Line> {
        &self.rings[from as usize * self.n as usize + to as usize]
    }
    #[inline]
    pub fn region_ring(&self, from: u16, to: u16) -> &Spsc<RegionMsg> {
        &self.region[from as usize * self.n as usize + to as usize]
    }

    /// Consumer side of the doorbell: anything inbound for `me`?
    pub fn has_inbound(&self, me: u16) -> bool {
        (0..self.n).any(|a| a != me && (!self.ring(a, me).is_empty_acquire() || !self.region_ring(a, me).is_empty_acquire()))
    }

    /// Producer side, after publishing pushes for `target`: returns true if the target was
    /// asleep and needs a MSG_RING wakeup (the swap removes duplicate doorbells).
    #[inline]
    pub fn needs_doorbell(&self, target: u16) -> bool {
        fence(SeqCst);
        self.sleeping[target as usize].load(Relaxed) && self.sleeping[target as usize].swap(false, AcqRel)
    }

    /// Consumer: announce sleep. Returns false (and clears the flag) if work arrived.
    pub fn try_sleep(&self, me: u16, extra_pending: impl Fn() -> bool) -> bool {
        self.sleeping[me as usize].store(true, Relaxed);
        fence(SeqCst);
        if self.has_inbound(me) || extra_pending() {
            self.sleeping[me as usize].store(false, Relaxed);
            return false;
        }
        true
    }

    pub fn woke(&self, me: u16) {
        self.sleeping[me as usize].store(false, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn spsc_threads() {
        let q = Arc::new(Spsc::<u64>::new(64));
        let p = q.clone();
        let t = std::thread::spawn(move || {
            for i in 0..1_000_000u64 {
                while p.push(i).is_err() {
                    std::hint::spin_loop();
                }
            }
        });
        let mut expect = 0;
        while expect < 1_000_000 {
            if let Some(v) = q.pop() {
                assert_eq!(v, expect);
                expect += 1;
            }
        }
        t.join().unwrap();
        assert!(q.pop().is_none());
    }
}
