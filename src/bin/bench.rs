//! Closed-loop memcached-text load generator: C connections, each with a pipeline depth
//! of D requests, GET/SET mix over a key range. Reports throughput and latency percentiles.
use clap::Parser;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::*};
use std::time::{Duration, Instant};

#[derive(Parser, Clone)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:11311")]
    addr: String,
    #[arg(long, default_value_t = 65536)]
    value_size: usize,
    #[arg(long, default_value_t = 16)]
    conns: usize,
    #[arg(long, default_value_t = 1)]
    depth: usize,
    #[arg(long, default_value_t = 2000)]
    keys: u64,
    /// Fraction of requests that are SETs.
    #[arg(long, default_value_t = 0.1)]
    set_ratio: f64,
    #[arg(long, default_value_t = 10)]
    seconds: u64,
    /// Preload all keys first.
    #[arg(long)]
    preload: bool,
}

fn key(i: u64) -> String {
    format!("{:08x}-0000-4000-8000-{:012x}", i, i.wrapping_mul(2654435761) % (1 << 48))
}

fn read_reply(s: &mut TcpStream, buf: &mut Vec<u8>, v: usize, is_set: bool) -> std::io::Result<bool> {
    // Returns hit for GET. Uses a simple buffered parser.
    let need_line = |buf: &Vec<u8>| buf.windows(2).position(|w| w == b"\r\n");
    let mut tmp = [0u8; 1 << 16];
    loop {
        if let Some(p) = need_line(buf) {
            let line = buf[..p].to_vec();
            if is_set {
                buf.drain(..p + 2);
                return Ok(line == b"STORED");
            }
            if line == b"END" {
                buf.drain(..p + 2);
                return Ok(false);
            }
            // VALUE line: need value + \r\n + END\r\n
            let total = p + 2 + v + 2 + 5;
            while buf.len() < total {
                let n = s.read(&mut tmp)?;
                if n == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            buf.drain(..total);
            return Ok(true);
        }
        let n = s.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn main() {
    let a = Args::parse();
    let value = vec![b'v'; a.value_size];
    if a.preload {
        let mut s = TcpStream::connect(&a.addr).unwrap();
        let mut buf = Vec::new();
        for i in 0..a.keys {
            let mut req = format!("set {} 0 0 {}\r\n", key(i), a.value_size).into_bytes();
            req.extend_from_slice(&value);
            req.extend_from_slice(b"\r\n");
            s.write_all(&req).unwrap();
            read_reply(&mut s, &mut buf, a.value_size, true).unwrap();
        }
        eprintln!("preloaded {} keys", a.keys);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));
    let hits = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for c in 0..a.conns {
        let a = a.clone();
        let stop = stop.clone();
        let ops = ops.clone();
        let hits = hits.clone();
        let value = value.clone();
        handles.push(std::thread::spawn(move || {
            let mut s = TcpStream::connect(&a.addr).unwrap();
            s.set_nodelay(true).unwrap();
            let mut buf = Vec::new();
            let mut lat: Vec<u32> = Vec::with_capacity(1 << 20);
            let mut rng = 0x9E3779B97F4A7C15u64 ^ (c as u64 * 7919);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            while !stop.load(Relaxed) {
                let mut kinds = Vec::with_capacity(a.depth);
                let mut req = Vec::new();
                for _ in 0..a.depth {
                    let k = key(next() % a.keys);
                    let set = (next() % 10_000) as f64 / 10_000.0 < a.set_ratio;
                    if set {
                        req.extend_from_slice(format!("set {k} 0 0 {}\r\n", a.value_size).as_bytes());
                        req.extend_from_slice(&value);
                        req.extend_from_slice(b"\r\n");
                    } else {
                        req.extend_from_slice(format!("get {k}\r\n").as_bytes());
                    }
                    kinds.push(set);
                }
                let t0 = Instant::now();
                s.write_all(&req).unwrap();
                for set in kinds {
                    let hit = read_reply(&mut s, &mut buf, a.value_size, set).unwrap();
                    lat.push(t0.elapsed().as_micros() as u32);
                    if !set && hit {
                        hits.fetch_add(1, Relaxed);
                    }
                    ops.fetch_add(1, Relaxed);
                }
            }
            lat
        }));
    }
    let t = Instant::now();
    std::thread::sleep(Duration::from_secs(a.seconds));
    stop.store(true, Relaxed);
    let mut all: Vec<u32> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let el = t.elapsed().as_secs_f64();
    all.sort_unstable();
    let p = |q: f64| all[((all.len() as f64 * q) as usize).min(all.len() - 1)];
    let n = ops.load(Relaxed);
    println!(
        "ops {n}  {:.0} ops/s  {:.2} GB/s payload  get-hit {:.3}  latency µs p50 {} p99 {} p99.9 {} p99.99 {} max {}",
        n as f64 / el,
        n as f64 * a.value_size as f64 / el / 1e9,
        hits.load(Relaxed) as f64 / (n as f64 * (1.0 - a.set_ratio)).max(1.0),
        p(0.5),
        p(0.99),
        p(0.999),
        p(0.9999),
        all[all.len() - 1]
    );
}
