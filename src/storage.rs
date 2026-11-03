//! Startup-time memory and device setup: the slot arena (design §3.2) and the SSD devices
//! with their superblock (design §3.4). Everything here runs before workers start.

use crate::sizing::{Geometry, SUPERBLOCK_BYTES};
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub struct Arena {
    pub base: *mut u8,
    pub len: usize,
    pub hugetlb: bool,
}

unsafe impl Send for Arena {}
unsafe impl Sync for Arena {}

impl Arena {
    pub fn new(bytes: u64, try_hugetlb: bool) -> io::Result<Arena> {
        let len = crate::sizing::round_up(bytes.max(4096), 2 << 20) as usize;
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
        if try_hugetlb {
            let p = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags | libc::MAP_HUGETLB, -1, 0) };
            if p != libc::MAP_FAILED {
                return Ok(Arena { base: p as *mut u8, len, hugetlb: true });
            }
        }
        let p = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags, -1, 0) };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        unsafe { libc::madvise(p, len, libc::MADV_HUGEPAGE) };
        Ok(Arena { base: p as *mut u8, len, hugetlb: false })
    }

    /// First-touch a byte range (called by the owning worker so pages land on its node).
    pub fn prefault(&self, off: u64, len: u64) {
        let end = (off + len).min(self.len as u64);
        let mut o = off;
        while o < end {
            unsafe { std::ptr::write_volatile(self.base.add(o as usize), 0) };
            o += 4096;
        }
        // Best effort: lock it (needs RLIMIT_MEMLOCK / CAP_IPC_LOCK).
        unsafe { libc::mlock(self.base.add(off as usize) as *const libc::c_void, (end - off) as usize) };
    }

    /// iovecs for io_uring buffer registration: one per 1 GiB chunk.
    pub fn chunk_iovecs(&self, geo: &Geometry) -> Vec<libc::iovec> {
        let chunks = geo.arena_slots.div_ceil(geo.slots_per_chunk);
        (0..chunks)
            .map(|c| {
                let off = c * crate::sizing::CHUNK;
                let len = (geo.arena_bytes - off).min(crate::sizing::CHUNK);
                libc::iovec { iov_base: unsafe { self.base.add(off as usize) } as *mut _, iov_len: len as usize }
            })
            .collect()
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base as *mut _, self.len) };
    }
}

pub struct Device {
    pub fd: OwnedFd,
    pub bytes: u64,
}

impl Device {
    pub fn raw(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

/// Open (creating regular files as needed) every configured device with O_DIRECT.
pub fn open_devices(paths: &[std::path::PathBuf], want_bytes: Option<u64>, direct: bool) -> io::Result<Vec<Device>> {
    let mut out = Vec::new();
    for p in paths {
        out.push(open_device(p, want_bytes, direct)?);
    }
    let first = out[0].bytes;
    if out.iter().any(|d| d.bytes != first) {
        return Err(io::Error::other("all devices must have the same size"));
    }
    Ok(out)
}

fn open_device(p: &Path, want_bytes: Option<u64>, direct: bool) -> io::Result<Device> {
    let meta = std::fs::metadata(p).ok();
    let is_blk = meta.as_ref().map(|m| std::os::unix::fs::FileTypeExt::is_block_device(&m.file_type())).unwrap_or(false);
    let mut oo = OpenOptions::new();
    oo.read(true).write(true);
    if !is_blk {
        oo.create(true);
    }
    if direct {
        oo.custom_flags(libc::O_DIRECT);
    }
    let f = oo.open(p).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.display())))?;
    let bytes = if is_blk {
        let mut sz: u64 = 0;
        // BLKGETSIZE64
        let r = unsafe { libc::ioctl(f.as_raw_fd(), 0x8008_1272, &mut sz) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        want_bytes.map(|w| w.min(sz)).unwrap_or(sz)
    } else {
        let want = want_bytes.ok_or_else(|| io::Error::other(format!("{}: device_bytes is required for regular files", p.display())))?;
        if f.metadata()?.len() < want {
            f.set_len(want)?;
        }
        want
    };
    Ok(Device { fd: f.into(), bytes })
}

/// Write a fresh superblock (cold start: every region is Clean). Warm restart (design §9.4)
/// is a phase-6 feature; the superblock records the geometry so a mismatch is detectable.
pub fn format(devs: &[Device], geo: &Geometry, instance: u64) -> io::Result<()> {
    let layout = std::alloc::Layout::from_size_align(4096, 4096).unwrap();
    let buf = unsafe { std::alloc::alloc_zeroed(layout) };
    let sb = unsafe { std::slice::from_raw_parts_mut(buf, 4096) };
    sb[..8].copy_from_slice(b"SSDCACHE");
    sb[8..12].copy_from_slice(&1u32.to_le_bytes());
    sb[16..24].copy_from_slice(&instance.to_le_bytes());
    sb[24..28].copy_from_slice(&geo.v.to_le_bytes());
    sb[28..36].copy_from_slice(&geo.s.to_le_bytes());
    sb[36..44].copy_from_slice(&geo.region_bytes.to_le_bytes());
    sb[44..52].copy_from_slice(&geo.regions.to_le_bytes());
    sb[52..60].copy_from_slice(&geo.slots_per_region.to_le_bytes());
    sb[60] = 0; // clean-shutdown flag
    let crc = crate::crc::crc32c(&sb[..4092]);
    sb[4092..4096].copy_from_slice(&crc.to_le_bytes());
    let mut res = Ok(());
    for (i, d) in devs.iter().enumerate() {
        sb[64..66].copy_from_slice(&(i as u16).to_le_bytes());
        let crc = crate::crc::crc32c(&sb[..4092]);
        sb[4092..4096].copy_from_slice(&crc.to_le_bytes());
        for copy in [0u64, 4096] {
            let n = unsafe { libc::pwrite(d.raw(), buf as *const _, 4096, copy as i64) };
            if n != 4096 {
                res = Err(io::Error::last_os_error());
            }
        }
        debug_assert!(SUPERBLOCK_BYTES >= 8192);
    }
    unsafe { std::alloc::dealloc(buf, layout) };
    res
}
