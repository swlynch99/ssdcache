//! Phase-0 simulator (design §10.4): replays a trace through the real `Shard` code with a
//! fake SSD whose completions arrive after randomized delays (out of order), and with
//! sends that hold pins for a while. Checks the shard invariants as it goes and reports
//! miss ratio, DRAM/SSD hit split, SSD bytes written per request, and drop reasons.
//!
//! Traces: synthetic Zipf (default), a text file with one integer key per line, or
//! libCacheSim's `oracleGeneral` binary format (24-byte records).

use clap::Parser;
use ssdcache::config::{Config, CreditCfg, PolicyCfg};
use ssdcache::core::shard::{IoKind, Out, Reply, ReqToken, Shard, ShardParams};
use ssdcache::flash::Flash;
use ssdcache::proto::{Key, SetMode};
use ssdcache::sizing::Geometry;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{BufRead, Read};
use std::sync::Arc;

#[derive(Parser, Debug, Clone)]
#[command(about = "ssdcache policy simulator")]
struct Args {
    /// Value size V.
    #[arg(long, default_value_t = 65536)]
    value_size: u32,
    /// DRAM cache objects (all shards; M capacity).
    #[arg(long, default_value_t = 20_000)]
    mem_objects: u64,
    /// SSD objects (D capacity, approx.).
    #[arg(long, default_value_t = 400_000)]
    ssd_objects: u64,
    #[arg(long, default_value_t = 4)]
    workers: u16,
    #[arg(long, default_value_t = 5_000_000)]
    requests: u64,
    /// Zipf exponent for the synthetic trace.
    #[arg(long, default_value_t = 0.9)]
    zipf: f64,
    /// Synthetic key universe.
    #[arg(long, default_value_t = 2_000_000)]
    universe: u64,
    /// Fraction of synthetic requests that are one-hit wonders (fresh keys).
    #[arg(long, default_value_t = 0.2)]
    one_hit: f64,
    /// Request rate (virtual time), GETs per second.
    #[arg(long, default_value_t = 50_000.0)]
    rate: f64,
    /// SSD write budget, demotions per second (all shards).
    #[arg(long, default_value_t = 500.0)]
    write_rate: f64,
    /// Plain FIFO M (paper's S) instead of CLOCK.
    #[arg(long)]
    fifo: bool,
    /// Admit every M evictee (no hit/ghost requirement).
    #[arg(long)]
    admit_all: bool,
    /// Disable the count-min threshold.
    #[arg(long)]
    no_sketch: bool,
    /// Ghost size factor (× |M|+|D|).
    #[arg(long, default_value_t = 1.0)]
    ghost: f64,
    /// Text trace (one integer key per line) or oracleGeneral binary (`.oracleGeneral` suffix).
    #[arg(long)]
    trace: Option<std::path::PathBuf>,
    /// Run `Shard::check` every N requests (0 = only at the end).
    #[arg(long, default_value_t = 200_000)]
    check_every: u64,
    /// Max IO latency in µs (completions are uniformly random up to this, so they reorder).
    #[arg(long, default_value_t = 400)]
    io_lat_us: u64,
    /// Max send time in µs (pins are held this long).
    #[arg(long, default_value_t = 200)]
    send_us: u64,
    /// Fraction of SSD reads that fail (fault injection).
    #[arg(long, default_value_t = 0.0)]
    read_err: f64,
    #[arg(long, default_value_t = 1)]
    seed: u64,
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// Zipf sampler by inverse CDF over a precomputed table (fine for ≤ 10^7 keys).
struct Zipf {
    cdf: Vec<f64>,
}
impl Zipf {
    fn new(n: u64, s: f64) -> Self {
        let mut cdf = Vec::with_capacity(n as usize);
        let mut acc = 0.0;
        for i in 1..=n {
            acc += 1.0 / (i as f64).powf(s);
            cdf.push(acc);
        }
        for c in cdf.iter_mut() {
            *c /= acc;
        }
        Zipf { cdf }
    }
    fn sample(&self, u: f64) -> u64 {
        self.cdf.partition_point(|&c| c < u) as u64
    }
}

enum Trace {
    Synth { z: Zipf, rng: Rng, one_hit: f64, next_fresh: u64, universe: u64 },
    Text(std::io::BufReader<std::fs::File>),
    Oracle(std::io::BufReader<std::fs::File>),
}

impl Trace {
    fn next(&mut self) -> Option<u64> {
        match self {
            Trace::Synth { z, rng, one_hit, next_fresh, universe } => {
                if rng.f64() < *one_hit {
                    *next_fresh += 1;
                    Some(*universe + *next_fresh)
                } else {
                    let r = z.sample(rng.f64());
                    // Scatter ranks over the key space.
                    Some(r.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 8)
                }
            }
            Trace::Text(r) => {
                let mut line = String::new();
                loop {
                    line.clear();
                    if r.read_line(&mut line).ok()? == 0 {
                        return None;
                    }
                    let t = line.trim();
                    if let Ok(k) = t.split([',', ' ']).next().unwrap_or("").parse::<u64>() {
                        return Some(k);
                    }
                }
            }
            Trace::Oracle(r) => {
                let mut rec = [0u8; 24];
                r.read_exact(&mut rec).ok()?;
                Some(u64::from_le_bytes(rec[4..12].try_into().unwrap()))
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ev {
    Io { shard: u16, op: u32, opgen: u32, res: i32 },
    Unpin { shard: u16, slot: u32, sgen: u32 },
}

fn key_of(k: u64) -> Key {
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&k.to_le_bytes());
    key[8..].copy_from_slice(&(!k).to_le_bytes());
    key
}

fn main() {
    let a = Args::parse();
    let n = a.workers as u64;
    let v = a.value_size;
    let s = ssdcache::sizing::round_up(v as u64, 4096);
    let credits = CreditCfg::default();
    let h = n * credits.p as u64 + n * credits.f as u64 + credits.w as u64;
    let staging = credits.qd as u64 + n * credits.p as u64;
    let per_shard = a.mem_objects.div_ceil(n) + h + staging;
    let spc = (1u64 << 30) / s;
    let total_slots = per_shard * n;
    let memory_bytes = (total_slots / spc) * (1 << 30) + (total_slots % spc) * s;
    let region_bytes: u64 = 64 << 20;
    let spr_guess = region_bytes / s;
    let regions = a.ssd_objects.div_ceil(spr_guess).max(4 * n + 140);
    let device_bytes = (1 << 20) + regions * region_bytes;
    let policy = PolicyCfg {
        m_clock: !a.fifo,
        admit_requires_hit: !a.admit_all,
        ghost_factor: a.ghost,
        sketch: !a.no_sketch,
        ..PolicyCfg::default()
    };
    let cfg_text = format!(
        "value_size = {v}\nmemory_bytes = {memory_bytes}\nworkers = {n}\ndevices = [\"/dev/null\"]\nhost_op = 0.0\n[[listeners]]\naddr = \"127.0.0.1:0\"\nproto = \"memcache\"\n"
    );
    let mut cfg: Config = toml::from_str(&cfg_text).unwrap();
    cfg.policy = policy.clone();
    let geo = Geometry::compute(&cfg, device_bytes).expect("geometry");
    eprintln!("{}", geo.report());
    let flash = Arc::new(Flash::new(&geo));
    let mut shards: Vec<Shard> = (0..n as u16)
        .map(|id| {
            Shard::new(
                ShardParams {
                    id,
                    n: n as u16,
                    policy: policy.clone(),
                    credits: credits.clone(),
                    write_rate: a.write_rate * geo.demote_cost() as f64 / n as f64,
                    burst_s: 2.0,
                    hash_seed: 42,
                    verify_crc: false,
                    arena: std::ptr::null_mut(),
                },
                &geo,
                flash.clone(),
            )
        })
        .collect();

    let mut trace = match &a.trace {
        None => Trace::Synth {
            z: Zipf::new(a.universe, a.zipf),
            rng: Rng(a.seed),
            one_hit: a.one_hit,
            next_fresh: 0,
            universe: 1 << 62,
        },
        Some(p) if p.to_string_lossy().ends_with("oracleGeneral") => {
            Trace::Oracle(std::io::BufReader::new(std::fs::File::open(p).expect("trace")))
        }
        Some(p) => Trace::Text(std::io::BufReader::new(std::fs::File::open(p).expect("trace"))),
    };

    let hasher = *shards[0].hasher();
    let mut rng = Rng(a.seed ^ 0xdead_beef);
    let mut events: BinaryHeap<Reverse<(u64, u64, Ev)>> = BinaryHeap::new();
    let mut ev_seq = 0u64;
    let dt_ns = (1e9 / a.rate) as u64;
    let mut now = 0u64;
    // Pending GETs: token.conn = request id; on reply we decide hit/miss and maybe SET.
    let mut pending_get_keys: std::collections::HashMap<u32, u64> = Default::default();
    let mut reqs = 0u64;
    let (mut hits_m, mut hits_d, mut misses, mut errors) = (0u64, 0u64, 0u64, 0u64);
    let mut sets_waiting: std::collections::HashMap<u32, u64> = Default::default();
    let mut reserve_pending: std::collections::HashMap<u32, u64> = Default::default();
    let mut next_req_id = 1u32;
    let mut done = false;

    macro_rules! drain {
        ($shards:expr, $sid:expr) => {{
            let sid: u16 = $sid;
            loop {
                let mut progressed = false;
                while let Some(io) = $shards[sid as usize].io_out.pop() {
                    progressed = true;
                    let lat = 20_000 + rng.below(a.io_lat_us * 1000);
                    let res = if io.kind == IoKind::Read && rng.f64() < a.read_err { -5 } else { io.len as i32 };
                    ev_seq += 1;
                    events.push(Reverse((now + lat, ev_seq, Ev::Io { shard: sid, op: io.op, opgen: io.opgen, res })));
                }
                while let Some((target, msg)) = $shards[sid as usize].region_out.pop() {
                    progressed = true;
                    $shards[target as usize].region_msg(msg);
                }
                while let Some(o) = $shards[sid as usize].out.pop() {
                    progressed = true;
                    match o {
                        Out::Reply(tok, Reply::Hit { slot, sgen }) => {
                            pending_get_keys.remove(&tok.conn);
                            hits_d += 1;
                            ev_seq += 1;
                            events.push(Reverse((now + rng.below(a.send_us * 1000), ev_seq, Ev::Unpin { shard: sid, slot, sgen })));
                        }
                        Out::Reply(tok, Reply::Miss) => {
                            misses += 1;
                            if let Some(k) = pending_get_keys.remove(&tok.conn) {
                                sets_waiting.insert(tok.conn, k);
                            }
                        }
                        Out::Reply(tok, Reply::ServerErr) => {
                            errors += 1;
                            pending_get_keys.remove(&tok.conn);
                        }
                        Out::Reply(tok, Reply::Reserved { slot, sgen }) => {
                            let k = reserve_pending.remove(&tok.conn).expect("reserve token");
                            let key = key_of(k);
                            let h = hasher.hash(&key);
                            $shards[sid as usize].commit(sid, &h, &key, slot, sgen, SetMode::Set);
                        }
                        Out::Reply(_, r) => panic!("unexpected reply {r:?}"),
                        Out::Grant { worker, slot, sgen } => {
                            // The simulator has no stashes: give it back.
                            $shards[sid as usize].abort(worker, slot, sgen);
                        }
                    }
                }
                if !progressed {
                    break;
                }
            }
        }};
    }

    let t0 = std::time::Instant::now();
    while !done || !events.is_empty() {
        // Deliver events due before the next request.
        let next_req_at = now + dt_ns;
        while let Some(Reverse((t, _, _))) = events.peek() {
            if *t > next_req_at && !done {
                break;
            }
            let Reverse((t, _, ev)) = events.pop().unwrap();
            now = now.max(t);
            match ev {
                Ev::Io { shard, op, opgen, res } => {
                    shards[shard as usize].io_done(op, opgen, res);
                    drain!(shards, shard);
                }
                Ev::Unpin { shard, slot, sgen } => {
                    shards[shard as usize].unpin(slot, sgen);
                }
            }
        }
        if done {
            continue;
        }
        now = next_req_at;
        // Ticks.
        if reqs % 64 == 0 {
            for sid in 0..n as u16 {
                shards[sid as usize].tick(now);
                drain!(shards, sid);
            }
        }
        // Process any SETs from earlier misses (fill after miss).
        let fills: Vec<(u32, u64)> = sets_waiting.iter().map(|(a, b)| (*a, *b)).collect();
        for (id, k) in fills {
            let key = key_of(k);
            let h = hasher.hash(&key);
            let sid = h.shard(n as u16);
            let tok = ReqToken { worker: sid, cgen: 0, conn: id, resp: 0 };
            match shards[sid as usize].reserve(sid, tok) {
                Some(Reply::Reserved { slot, sgen }) => {
                    sets_waiting.remove(&id);
                    shards[sid as usize].commit(sid, &h, &key, slot, sgen, SetMode::Set);
                }
                None => {
                    // Waits in the owner's list; the Reserved reply arrives via `out`.
                    sets_waiting.remove(&id);
                    reserve_pending.insert(id, k);
                }
                Some(r) => panic!("reserve: {r:?}"),
            }
            drain!(shards, sid);
        }
        // Next request: GET, fill on miss.
        let Some(k) = trace.next() else {
            done = true;
            continue;
        };
        reqs += 1;
        if reqs >= a.requests {
            done = true;
        }
        let key = key_of(k);
        let h = hasher.hash(&key);
        let sid = h.shard(n as u16);
        let id = next_req_id;
        next_req_id = next_req_id.wrapping_add(1).max(1);
        let tok = ReqToken { worker: sid, cgen: 0, conn: id, resp: 0 };
        match shards[sid as usize].lookup(&h, &key, tok, false) {
            Some(Reply::Hit { slot, sgen }) => {
                hits_m += 1;
                ev_seq += 1;
                events.push(Reverse((now + rng.below(a.send_us * 1000), ev_seq, Ev::Unpin { shard: sid, slot, sgen })));
            }
            Some(Reply::Miss) => {
                misses += 1;
                sets_waiting.insert(id, k);
            }
            Some(r) => {
                errors += 1;
                let _ = r;
            }
            None => {
                pending_get_keys.insert(id, k);
            }
        }
        drain!(shards, sid);
        if a.check_every > 0 && reqs % a.check_every == 0 {
            for (i, sh) in shards.iter().enumerate() {
                if let Err(e) = sh.check() {
                    panic!("shard {i} invariant violated at request {reqs}: {e}");
                }
            }
            let tot = (hits_m + hits_d + misses).max(1) as f64;
            eprintln!(
                "  {reqs:>10} reqs  miss {:.4}  hit_M {:.4}  hit_D {:.4}  ({:.1}s)",
                misses as f64 / tot,
                hits_m as f64 / tot,
                hits_d as f64 / tot,
                t0.elapsed().as_secs_f64()
            );
        }
    }
    // Drain: final ticks so waiters finish.
    for _ in 0..4 {
        for sid in 0..n as u16 {
            shards[sid as usize].tick(now);
            drain!(shards, sid);
        }
        while let Some(Reverse((t, _, ev))) = events.pop() {
            now = now.max(t);
            match ev {
                Ev::Io { shard, op, opgen, res } => {
                    shards[shard as usize].io_done(op, opgen, res);
                    drain!(shards, shard);
                }
                Ev::Unpin { shard, slot, sgen } => shards[shard as usize].unpin(slot, sgen),
            }
        }
    }
    for (i, sh) in shards.iter().enumerate() {
        sh.check().unwrap_or_else(|e| panic!("shard {i} final check: {e}"));
        assert_eq!(sh.slots.zombies, 0, "zombies left after drain");
        assert_eq!(sh.slots.staging_held, 0, "staging buffers left after drain");
        assert_eq!(sh.demote_inflight, 0);
    }

    let mut st = ssdcache::core::shard::ShardStats::default();
    macro_rules! sum {
        ($($f:ident),*) => { for sh in &shards { $( st.$f += sh.stats.$f; )* } };
    }
    sum!(
        gets, hits_m, hits_d, misses, sets, ghost_hits, m_evictions, m_reinsertions, clean_evictions, demotions,
        demotions_gadmit, demote_rescued_hot, drop_no_hit, drop_theta, drop_no_tokens, drop_forced, drop_no_region,
        drop_w_full, ssd_bytes_written, ssd_reads, ssd_read_err, lap_mismatch, region_opens, region_wait,
        early_seals, reclaims, d_evictions, slot_waits, stale_msgs
    );
    let tot = (hits_m + hits_d + misses + errors).max(1) as f64;
    let secs = now as f64 / 1e9;
    println!("requests            {reqs}  (virtual {secs:.1} s, wall {:.1} s)", t0.elapsed().as_secs_f64());
    println!(
        "policy              m_clock={} admit_requires_hit={} sketch={} ghost={}",
        policy.m_clock, policy.admit_requires_hit, policy.sketch, policy.ghost_factor
    );
    println!("miss ratio          {:.4}", misses as f64 / tot);
    println!("hit DRAM (h_M)      {:.4}", hits_m as f64 / tot);
    println!("hit SSD  (h_D)      {:.4}", hits_d as f64 / tot);
    println!("errors              {errors}");
    println!(
        "SSD writes          {} demotions ({} ghost-admitted, {} rescued hot) = {:.3} KiB/request, {:.1}/s",
        st.demotions,
        st.demotions_gadmit,
        st.demote_rescued_hot,
        st.ssd_bytes_written as f64 / 1024.0 / tot,
        st.demotions as f64 / secs.max(1e-9)
    );
    println!(
        "M evictions         {} (clean {}, reinsertions {})",
        st.m_evictions, st.clean_evictions, st.m_reinsertions
    );
    println!(
        "drops to G          no_hit {} theta {} no_tokens {} forced {} no_region {} w_full {}",
        st.drop_no_hit, st.drop_theta, st.drop_no_tokens, st.drop_forced, st.drop_no_region, st.drop_w_full
    );
    println!(
        "ghost hits          {}   D evictions {}   reclaims {}   regions opened {} (waits {}, early seals {})",
        st.ghost_hits, st.d_evictions, st.reclaims, st.region_opens, st.region_wait, st.early_seals
    );
    println!(
        "ssd reads           {}  (read errors {}, lap mismatches {}, slot waits {}, stale msgs {})",
        st.ssd_reads, st.ssd_read_err, st.lap_mismatch, st.slot_waits, st.stale_msgs
    );
    let thetas: Vec<u8> = shards.iter().map(|s| s.budget.theta).collect();
    println!("theta per shard     {thetas:?}");
    let states = flash.count_states();
    println!(
        "regions             clean {} open {} sealed {} reclaiming {} draining {}",
        states[0], states[1], states[2], states[3], states[4]
    );
}
