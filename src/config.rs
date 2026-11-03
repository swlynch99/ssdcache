//! Configuration (design §9.1). Loaded once at startup on the main thread.

use crate::proto::ProtoKind;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// V: value size in bytes on the wire (20,000 ..= 102,400 typical; any > 0 allowed).
    pub value_size: u32,
    /// DRAM arena size in bytes (cache pools + headroom + staging pools, all shards).
    pub memory_bytes: u64,
    /// N worker threads (= shards).
    pub workers: u16,
    /// Optional CPU ids to pin workers to (len ≥ workers). Control thread is left unpinned
    /// unless `control_cpu` is set.
    #[serde(default)]
    pub cpu_list: Vec<usize>,
    #[serde(default)]
    pub control_cpu: Option<usize>,
    /// SSD devices: raw block devices or regular files (files are created/extended to
    /// `device_bytes`). All devices must be the same size.
    pub devices: Vec<PathBuf>,
    /// Size of each device. Required for regular files; for block devices the real size is
    /// used if this is omitted.
    #[serde(default)]
    pub device_bytes: Option<u64>,
    /// Use O_DIRECT for device IO (default true). Turn off only for tmpfs-backed tests.
    #[serde(default = "yes")]
    pub o_direct: bool,
    #[serde(default = "default_region_bytes")]
    pub region_bytes: u64,
    /// Host over-provisioning fraction left unused at the end of each device.
    #[serde(default = "default_host_op")]
    pub host_op: f64,
    #[serde(default = "default_max_conns")]
    pub max_conns: u32,
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub tls: Option<TlsCfg>,
    #[serde(default)]
    pub admin_addr: Option<String>,
    #[serde(default)]
    pub policy: PolicyCfg,
    #[serde(default)]
    pub wear: WearCfg,
    #[serde(default)]
    pub credits: CreditCfg,
    #[serde(default = "default_spin_us")]
    pub spin_us: u32,
    #[serde(default = "default_body_timeout_ms")]
    pub body_timeout_ms: u32,
    #[serde(default = "default_pin_stall_ms")]
    pub pin_stall_ms: u32,
    /// Try to register the arena as io_uring fixed buffers (needs RLIMIT_MEMLOCK).
    /// Falls back to plain READ/WRITE if registration fails.
    #[serde(default = "yes")]
    pub register_buffers: bool,
    /// Try MAP_HUGETLB for the arena (falls back to THP-advised anonymous memory).
    #[serde(default = "yes")]
    pub hugepages: bool,
    /// Verify crc32c of SSD reads against the CRC recorded at demotion.
    #[serde(default = "yes")]
    pub verify_crc: bool,
    /// Random hash seed if 0.
    #[serde(default)]
    pub hash_seed: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub addr: String,
    pub proto: ProtoKind,
    #[serde(default)]
    pub tls: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsCfg {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// Extra handshake threads (besides the acceptor).
    #[serde(default = "default_tls_threads")]
    pub handshake_threads: u16,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u32,
}

/// Eviction policy knobs (design §4.3).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyCfg {
    /// CLOCK reinsertion in M (true) or the paper's plain FIFO (false).
    pub m_clock: bool,
    /// Consecutive CLOCK reinsertions before the tail is force-evicted.
    pub m_max_spins: u16,
    /// Same bound under slot pressure.
    pub m_max_spins_forced: u16,
    /// An M evictee needs `hit || gadmit` to be an SSD candidate.
    pub admit_requires_hit: bool,
    /// Ghost capacity as a multiple of |M|+|D|.
    pub ghost_factor: f64,
    /// Insert D evictees into the ghost.
    pub ghost_d_evictees: bool,
    /// Seal an open region after this many seconds.
    pub open_max_age_s: u32,
    /// Use the count-min threshold θ under budget pressure.
    pub sketch: bool,
}

impl Default for PolicyCfg {
    fn default() -> Self {
        PolicyCfg {
            m_clock: true,
            m_max_spins: 64,
            m_max_spins_forced: 4,
            admit_requires_hit: true,
            ghost_factor: 1.0,
            ghost_d_evictees: true,
            open_max_age_s: 600,
            sketch: true,
        }
    }
}

/// SSD write budget (design §4.5).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WearCfg {
    pub rated_dwpd: f64,
    pub safety: f64,
    pub seq_endurance_factor: f64,
    /// Explicit host write rate in bytes/s for all shards together. Overrides the DWPD formula.
    pub write_rate_bytes: Option<u64>,
    /// Token-bucket burst in seconds of rate.
    pub burst_s: f64,
}

impl Default for WearCfg {
    fn default() -> Self {
        WearCfg { rated_dwpd: 1.0, safety: 0.8, seq_endurance_factor: 1.0, write_rate_bytes: None, burst_s: 2.0 }
    }
}

/// Cross-shard budgets (design §2.4) and per-shard IO limits.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CreditCfg {
    /// Op credits per ordered pair.
    pub c: u16,
    /// Pin quota per ordered pair.
    pub p: u16,
    /// Pin quota per connection per owner.
    pub p_conn: u16,
    /// Fill quota per ordered pair (includes the stash).
    pub f: u16,
    /// Stash target per ordered pair.
    pub stash: u16,
    /// Max demotion writes in flight per shard.
    pub w: u16,
    /// Max SSD reads in flight per shard.
    pub qd: u16,
}

impl Default for CreditCfg {
    fn default() -> Self {
        CreditCfg { c: 32, p: 64, p_conn: 8, f: 8, stash: 4, w: 64, qd: 128 }
    }
}

fn yes() -> bool {
    true
}
fn default_region_bytes() -> u64 {
    64 << 20
}
fn default_host_op() -> f64 {
    0.07
}
fn default_max_conns() -> u32 {
    4096
}
fn default_spin_us() -> u32 {
    30
}
fn default_body_timeout_ms() -> u32 {
    2000
}
fn default_pin_stall_ms() -> u32 {
    100
}
fn default_tls_threads() -> u16 {
    1
}
fn default_handshake_timeout_ms() -> u32 {
    5000
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.value_size == 0 || self.value_size > (16 << 20) {
            return Err("value_size must be in 1..=16MiB".into());
        }
        if self.workers == 0 || self.workers > 256 {
            return Err("workers must be in 1..=256".into());
        }
        if self.devices.is_empty() {
            return Err("at least one device is required".into());
        }
        if self.listeners.is_empty() {
            return Err("at least one listener is required".into());
        }
        if self.listeners.iter().any(|l| l.tls) && self.tls.is_none() {
            return Err("a TLS listener needs a [tls] section".into());
        }
        if !self.cpu_list.is_empty() && self.cpu_list.len() < self.workers as usize {
            return Err("cpu_list must have at least `workers` entries".into());
        }
        let c = &self.credits;
        if c.p_conn == 0 || c.p_conn > c.p || c.stash > c.f || c.c == 0 || c.w == 0 || c.qd == 0 {
            return Err("invalid credits: need 0 < p_conn <= p, stash <= f, c/w/qd > 0".into());
        }
        if !(0.0..0.9).contains(&self.host_op) {
            return Err("host_op must be in [0, 0.9)".into());
        }
        Ok(())
    }
}
