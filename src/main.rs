use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering::*};

#[derive(Parser)]
#[command(about = "ssdcache: tiered S3-FIFO cache server (DRAM probation → SSD main) over io_uring + kTLS")]
struct Args {
    /// Path to the TOML config.
    #[arg(short, long)]
    config: std::path::PathBuf,
}

#[global_allocator]
static ALLOC: ssdcache::alloc_guard::GuardedAlloc = ssdcache::alloc_guard::GuardedAlloc;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, SeqCst);
}

fn main() {
    let args = Args::parse();
    let cfg = match ssdcache::config::Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            std::process::exit(2);
        }
    };
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let run = match ssdcache::server::start(&cfg, false) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("startup: {e}");
            std::process::exit(1);
        }
    };
    for a in &run.addrs {
        eprintln!("listening on {a}");
    }
    while !STOP.load(SeqCst) && !run.stop.load(SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    eprintln!("shutting down");
    run.shutdown();
}
