//! Startup (design §9.1): geometry, devices, arena, shards, workers, control plane.

use crate::config::Config;
use crate::control::{self, Control};
use crate::core::shard::{Shard, ShardParams};
use crate::flash::Flash;
use crate::sizing::Geometry;
use crate::stats::WorkerStats;
use crate::storage::{self, Arena};
use crate::worker::{Worker, WorkerShared};
use crate::xshard::Mesh;
use crossbeam_queue::ArrayQueue;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::*};
use std::sync::{Arc, Barrier};

pub struct Running {
    pub addrs: Vec<std::net::SocketAddr>,
    pub stop: Arc<AtomicBool>,
    pub stats: Arc<Vec<WorkerStats>>,
    pub geo: Geometry,
    workers: Vec<std::thread::JoinHandle<()>>,
    _arena: Arc<Arena>,
    _devs: Arc<Vec<storage::Device>>,
}

impl Running {
    pub fn shutdown(mut self) {
        self.stop.store(true, SeqCst);
        // Wake sleeping workers: their timed wait expires within 10 ms anyway.
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
    pub fn wait(mut self) {
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}

fn rand_seed() -> u64 {
    let mut b = [0u8; 8];
    unsafe { libc::getrandom(b.as_mut_ptr() as *mut _, 8, 0) };
    u64::from_le_bytes(b) | 1
}

pub fn start(cfg: &Config, quiet: bool) -> Result<Running, String> {
    cfg.validate()?;
    let devs = storage::open_devices(&cfg.devices, cfg.device_bytes, cfg.o_direct).map_err(|e| e.to_string())?;
    let geo = Geometry::compute(cfg, devs[0].bytes)?;
    if !quiet {
        eprintln!("{}", geo.report());
    }
    storage::format(&devs, &geo, rand_seed()).map_err(|e| format!("format: {e}"))?;
    let arena = Arc::new(Arena::new(geo.arena_bytes, cfg.hugepages).map_err(|e| format!("arena: {e}"))?);
    if !quiet {
        eprintln!("arena: {} MiB, hugetlb={}", arena.len >> 20, arena.hugetlb);
    }
    let flash = Arc::new(Flash::new(&geo));
    let n = cfg.workers;
    let mesh = Arc::new(Mesh::new(n, 256));
    let handoff: Arc<Vec<ArrayQueue<_>>> = Arc::new((0..n).map(|_| ArrayQueue::new(1024)).collect());
    let stop = Arc::new(AtomicBool::new(false));
    let stats: Arc<Vec<WorkerStats>> = Arc::new((0..n).map(|_| WorkerStats::default()).collect());
    let devs = Arc::new(devs);
    let seed = if cfg.hash_seed != 0 { cfg.hash_seed } else { rand_seed() };
    let host_rate = cfg.wear.write_rate_bytes.map(|r| r as f64).unwrap_or_else(|| {
        let cap = geo.device_bytes as f64 * geo.devices as f64;
        cfg.wear.rated_dwpd * cap / 86_400.0 * cfg.wear.safety * cfg.wear.seq_endurance_factor
    });
    let max_conns = (cfg.max_conns / n as u32).max(16) + 16;
    let ready = Arc::new(Barrier::new(n as usize + 1));
    let errors: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let mut workers = Vec::new();
    for id in 0..n {
        let cfg = cfg.clone();
        let geo = geo.clone();
        let flash = flash.clone();
        let arena = arena.clone();
        let devs = devs.clone();
        let sh = WorkerShared { mesh: mesh.clone(), handoff: handoff.clone(), stop: stop.clone(), stats: stats.clone() };
        let ready = ready.clone();
        let errors = errors.clone();
        let t = std::thread::Builder::new()
            .name(format!("worker-{id}"))
            .spawn(move || {
                if let Some(&cpu) = cfg.cpu_list.get(id as usize) {
                    unsafe {
                        let mut set: libc::cpu_set_t = std::mem::zeroed();
                        libc::CPU_SET(cpu, &mut set);
                        libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set);
                    }
                }
                // First touch of this shard's partition.
                let base = geo.slot_offset((id as u64 * geo.shard_slots) as u32);
                let end = if id + 1 == geo.n { geo.arena_bytes } else { geo.slot_offset(((id as u64 + 1) * geo.shard_slots) as u32) };
                arena.prefault(base, end - base);
                let shard = Shard::new(
                    ShardParams {
                        id,
                        n: geo.n,
                        policy: cfg.policy.clone(),
                        credits: cfg.credits.clone(),
                        write_rate: host_rate / geo.n as f64,
                        burst_s: cfg.wear.burst_s,
                        hash_seed: seed,
                        verify_crc: cfg.verify_crc,
                        arena: arena.base,
                    },
                    &geo,
                    flash,
                );
                let dev_fds = devs.iter().map(|d| d.raw()).collect();
                let mut w = match Worker::new(id, &cfg, &geo, shard, arena.base, dev_fds, sh, max_conns) {
                    Ok(w) => w,
                    Err(e) => {
                        errors.lock().unwrap().push(format!("worker {id}: {e}"));
                        ready.wait();
                        return;
                    }
                };
                if cfg.register_buffers {
                    if let Err(e) = w.register_arena(&arena.chunk_iovecs(&geo)) {
                        if id == 0 {
                            eprintln!("note: fixed buffers unavailable ({e}); using plain READ/WRITE");
                        }
                    }
                }
                w.shared_mesh().ring_fd[id as usize].store(w.ring_fd(), Release);
                ready.wait();
                w.run();
            })
            .map_err(|e| e.to_string())?;
        workers.push(t);
    }
    ready.wait();
    if let Some(e) = errors.lock().unwrap().first() {
        stop.store(true, SeqCst);
        return Err(e.clone());
    }
    let ctl = Arc::new(Control { mesh, handoff, stop: stop.clone(), stats: stats.clone(), next: AtomicUsize::new(0) });
    let addrs = control::start(cfg, ctl).map_err(|e| format!("listen: {e}"))?;
    Ok(Running { addrs, stop, stats, geo, workers, _arena: arena, _devs: devs })
}
