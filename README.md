# ssdcache

A cache server for fixed-size keys (UUIDs) and fixed-size values (20–100 KB, set at startup). It speaks memcached (text + meta), RESP2/3 and HTTP/1.1. It runs over io_uring with kernel TLS (rustls handshake, then kTLS), shard-per-core, with no locks and no heap allocation on request threads.

Eviction is S3-FIFO in its flash configuration. A DRAM CLOCK queue (M, about 5% of objects) acts as probation in front of an SSD region log (D, the main store), and a ghost (G) records recent evictions. An object is written to SSD only if it was hit in DRAM, or re-SET after a ghost hit, and only if a wear-rate token bucket allows the write. Nothing ever moves from SSD back to DRAM: an SSD hit is read into a staging buffer, sent and released.

The full design is in [DESIGN.md](DESIGN.md).

## Build and run

```sh
cargo build --release
./target/release/ssdcache -c config.toml
```

Minimal config. The device can be a raw block device or a regular file (O_DIRECT is used either way):

```toml
value_size = 65536
memory_bytes = 8589934592          # DRAM arena: cache + headroom + staging
workers = 4
devices = ["/dev/nvme1n1"]         # or a file path plus device_bytes
# device_bytes = 107374182400
admin_addr = "127.0.0.1:18080"     # GET /stats

[[listeners]]
addr = "0.0.0.0:11211"
proto = "memcache"                 # memcache | resp | http

[[listeners]]
addr = "0.0.0.0:11212"
proto = "memcache"
tls = true

[tls]
cert = "cert.pem"
key = "key.pem"

[wear]
rated_dwpd = 1.0                   # or write_rate_bytes = <bytes/s> for all shards
```

All other knobs and their defaults are in `src/config.rs`: policy, credits and quotas, spin, timeouts. The server prints its full derived geometry (`src/sizing.rs`) at startup.

## Tests

| What | How |
|---|---|
| Unit tests: core, policy, sizing (both §3.5 columns), SPSC, protocols (incl. fuzz-style), alloc guard | `cargo test` |
| Policy simulator: real shard code, fake SSD with reordered completions, invariant checks, fault injection | `./target/release/ssdcache-sim --help` |
| End to end: memcache text/meta, memcache over kTLS, RESP, HTTP | `python3 tests/e2e.py` against a running server |
| SSD tier: demotion, D hits, reclaim laps, byte-exact verification | `python3 tests/tiering.py --n 45000` |
| Slow clients: stalled SET bodies time out, slots return, others unaffected | `python3 tests/slowclient.py` |
| Load | `./target/release/ssdcache-bench --preload --keys 3000 --conns 16` |

The Python tests expect the listener ports in `examples/test.toml`: memcache 11311, TLS memcache 11312, RESP 16379, HTTP 18081, admin 18080.

`/stats` includes `worker_allocs`, the number of heap allocations made by worker threads inside their event loops. It must be 0, and it is 0 across all of the tests above. Set `SSDCACHE_ALLOC_PANIC=1` to make any such allocation panic.

## Status

Implemented (design phases 0–4, partly 5):
- **Policy and simulator (phase 0):**
  - M CLOCK queue (or plain FIFO via `m_clock = false`), ghost, blocked count-min sketch with θ feedback, and the per-shard token bucket.
  - The `admit_requires_hit` rule.
  - The simulator, with delayed and reordered IO, read-error injection and invariant checks.
- **Storage:**
  - Hugepage arena, falling back to THP.
  - Per-shard cache and staging pools with pins and zombies.
  - Cuckoo index with full keys.
  - A global region FIFO with K-ahead reclaim, sent to region owners over region-control rings.
  - Lap tags, Draining, a bounded open-region age, footers, and a superblock.
  - CRC verification of every SSD read before it is sent.
- **Threading:** shard-per-core workers, an SPSC message mesh with a fenced sleeping-flag doorbell over `MSG_RING`, op credits, pin quotas (per pair and per connection), fill quotas, and owner-granted slot stashes.
- **Network:**
  - Pipelined connections with in-order response rings.
  - Bodies received straight into slots.
  - `[header, value, trailer]` gathered into one `SENDMSG`.
  - Body-progress deadline.
- **TLS:** record-exact rustls handshake on control threads and kTLS TX/RX install with `RX_EXPECT_NO_PAD`. On alerts the server sends close_notify and closes. It also closes on KeyUpdate: kernels before 6.14 can't rekey kTLS.
- **Admin:** `/stats`, `/shutdown`. Allocation guard.

Not yet implemented (see DESIGN.md §10.4 for where each belongs):
- **Slow-client protection:** the pin-stall spill pool, the send deadline, and per-connection caps on pinned bytes. A client that stops reading currently holds its pins until it disconnects.
- **TLS:** kTLS rekey (6.14+) and the 90% AES-GCM record-limit rekey or close.
- **Write budget:** rebalancing write budgets between shards, the SMART/OCP wear controller and the TBW cap. The rate is static from config.
- **Policy options:** `d_rewrite_hits` (SSD→SSD rewrite) and `m_probation_frac`.
- **Simulator baselines:** the v1.1 four-queue design and TinyLFU admission.
- **io_uring features:**
  - Provided-buffer rings and fixed files. Header recv goes into each connection's own carry buffer instead.
  - Chunked send submission with owner passes between chunks.
  - IOPOLL, FDP and the other phase-6 items.
- **Operations:** live config (`POST /config`), Prometheus `/metrics`, graceful drain, warm restart, and format-time discard.
- **Verification:** loom models of the SPSC ring and doorbell, and cargo-fuzz targets.

Deviations from DESIGN.md:
- **Value CRCs** are kept in memory, 4 B per SSD slot, as well as in the footer. This lets each read be verified without reading the footer.
- **Header recv** uses the per-connection carry buffer, not provided buffers. Multi-key commands are parsed one key at a time, so no fallback pool is needed.
- **Fixed buffers** are registered when `RLIMIT_MEMLOCK` allows it. Otherwise the server uses plain READ/WRITE and logs a note.
