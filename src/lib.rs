//! ssdcache: a tiered (DRAM probation → SSD main) S3-FIFO cache server over io_uring and kTLS.
//! See DESIGN.md.

pub mod alloc_guard;
pub mod config;
pub mod core;
pub mod crc;
pub mod flash;
pub mod hash;
pub mod proto;
pub mod tls;
pub mod sizing;
pub mod control;
pub mod server;
pub mod stats;
pub mod storage;
pub mod worker;
pub mod xshard;
