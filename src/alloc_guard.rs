//! Allocation guard (design §8): a global allocator wrapper that counts heap allocations
//! made by a worker thread while it is inside its event loop. The count is exported in
//! `/stats` as `worker_allocs` and must stay 0. (The design's debug build panics; counting
//! is safer inside an allocator and works in release builds too.)

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub struct GuardedAlloc;

pub static WORKER_ALLOCS: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static GUARDED: Cell<bool> = const { Cell::new(false) };
}

/// Mark the current thread as a guarded request thread (or not).
pub fn set_guarded(on: bool) {
    GUARDED.with(|g| g.set(on));
}

#[inline]
fn note() {
    if GUARDED.try_with(|g| g.get()).unwrap_or(false) {
        WORKER_ALLOCS.fetch_add(1, Relaxed);
        if std::env::var_os("SSDCACHE_ALLOC_PANIC").is_some() {
            // Unguard first so the panic machinery can allocate.
            set_guarded(false);
            panic!("heap allocation on a worker thread inside the event loop");
        }
    }
}

unsafe impl GlobalAlloc for GuardedAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        note();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        note();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        note();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}

#[cfg(test)]
#[global_allocator]
static TEST_ALLOC: GuardedAlloc = GuardedAlloc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_guarded_allocations_only() {
        let before = WORKER_ALLOCS.load(Relaxed);
        let v: Vec<u8> = Vec::with_capacity(64); // unguarded
        drop(v);
        set_guarded(true);
        let v: Vec<u8> = Vec::with_capacity(64); // guarded: counted
        set_guarded(false);
        drop(v);
        // Other test threads never set the flag, so exactly one allocation was counted here.
        assert_eq!(WORKER_ALLOCS.load(Relaxed) - before, 1);
    }
}
