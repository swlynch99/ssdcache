# Cache Server Design: Tiered S3-FIFO Cache over io_uring and kTLS

**Status:** proposed architecture, v1.2 (v1.1 + one DRAM queue, no SSD→DRAM movement, D-hit send path; see §12) · **Target:** Rust (nightly allowed), Linux 6.14+ recommended, 6.1 hard floor · **Example deployment:** 64 KiB values (a 20 KB column is also shown), 256 GiB RAM, 4 TB NVMe, 16 worker cores (benchmark 8/16/32)

---

## 1. Executive summary

We build a **shard-per-core** cache server:
- One **control thread** accepts connections, runs the rustls handshake, installs kTLS, hands sockets off and serves the admin plane. It also derives keys for TLS rekeys, because that work allocates.
- **N pinned worker threads** each run one io_uring loop. Each worker is a *network thread* for the connections it was given. It is also the *single owner* of 1/N of the key space: index, memory slots, M/G queues and the SSD regions it wrote.
- When a key's owner is another worker, the request goes there as a 64-byte message on a lock-free SPSC ring. The owner replies with a **pinned reference** to a memory slot or, for an SSD hit, to a staging buffer. The connection's own thread then sends the value straight from that slot. kTLS encrypts during `sendmsg`, so the pin ends at the send CQE.

All policy, pin and eviction state has a single writer and uses plain integers. The request path takes no locks.

**Values are fixed size, so storage is simple:**
- Every memory object is one slot in a hugepage arena. The arena is registered with io_uring.
- Every SSD object is one slot in a 64 MiB region of a circular log.
- Region reclaim follows **one global FIFO order** across all shards. This keeps device write amplification (DLWA) near 1 without FDP. Open regions have a bounded age, and a region that is not Clean is retried, never skipped. Both rules protect the FIFO order.

**Eviction is S3-FIFO in its flash configuration: DRAM probation, SSD main** (M = DRAM, D = SSD main, G = ghost):
- The SSD log D is the main store (≈ 95% of objects). DRAM is one CLOCK queue M that every new object enters.
- An M-evictee goes to SSD only if it was hit while in DRAM, or its SET followed a ghost hit, **and** a wear-rate token bucket allows the write. One-hit wonders never reach flash.
- Nothing ever moves from SSD to DRAM. A D hit is read into a transient staging buffer, sent, and released. Demoting an object that still has a valid SSD copy costs nothing.
- D is a strict FIFO. Evicted D objects go to G, and a ghost hit on the next SET pre-admits the object.

**Everything is preallocated at startup from the fixed configuration.** The one exception is a capped fallback pool for oversized request headers, such as long multi-key lines. Every slot allocation on the owner can fail, and each caller has a bounded wait path for that case. Quotas (op credits, pin quotas, fill quotas) bound how many slots can be outside the cache at once. Headroom H is sized so that these waits are rare. Overload becomes TCP backpressure, never allocation.

### Key decisions

| # | Decision | Chosen | Rejected (why) |
|---|---|---|---|
| D1 | Threading | Shard-per-core: 1 control thread + N workers, each both network and storage owner. N sized to the NIC/kTLS need (example 16), not to the core count. | N-net + 1-storage (single FCFS queue, one stall hits all requests, caps scaling). Shared lock-free index (atomics on hot lines, epoch reclamation, CAS loops). |
| D2 | Cross-shard access | SPSC N×N message rings with an `IORING_OP_MSG_RING` doorbell. The owner pins; the connection thread sends from the owner's slot. Op credits are separate from pin and fill quotas. | Moving the connection to the owner (clients mix keys). Copying values between threads (wastes bandwidth). |
| D3 | Who issues SSD IO | The owner shard reads into a **staging buffer** from a per-shard pool that is separate from the cache pool. The buffer is never cached. | Connection thread reads (no coalescing, region pins become cross-thread). Reading into a cache slot (D hits would compete with SETs for slots). |
| D4 | Eviction | S3-FIFO, flash configuration: M (one DRAM CLOCK queue, 2-bit, ≈ 5% of M+D) → D (SSD region log, strict FIFO, main store) + G (fingerprint ghost, \|M\|+\|D\| entries). **No SSD→DRAM promotion or reinsertion.** | v1.1 4-queue S→M→D (S was only ≈ 0.5% of M+D, so admission degraded to second-miss). Promotion of D hits (displaces unproven M objects). SIEVE, W-TinyLFU, ARC, LIRS, LRB as the main policy (§4.7). |
| D5 | SSD admission | Only M-evictees with no valid SSD copy that were hit in DRAM or ghost-admitted, gated by a per-shard wear-rate token bucket and a count-min threshold under pressure | Write every DRAM eviction (≈7× the budget). Random admission (wastes budget on cold items). |
| D6 | SSD layout | Raw block device, O_DIRECT, 4 KiB LBA. 64 MiB regions of 1023 slots plus a 64 KiB footer. **One global region FIFO**, with bounded open-region age. Whole-namespace discard at format. | In-place slots (random overwrites, DLWA ≫ 1). Per-shard LBA partitions (lifetimes diverge, DLWA rises without FDP). |
| D7 | Overwrites | Never in place: a SET writes a new slot and retires the old one | In-place writes (tear in-flight sends and demotion writes) |
| D8 | In-flight safety | Logical eviction now, physical free on the last unpin (zombie). Pins are owner-local `u16`. Per-entry `ver`. Per-region `inflight_reads` with Draining state. Reclaim clears SSD pointers synchronously. SSD locations carry a region lap tag. | Epoch/QSBR (one slow client blocks all reclamation). Skipping pinned victims (distorts policy). |
| D9 | TLS | rustls 0.23 (≥0.23.27) unbuffered API on the control thread, `dangerous_into_kernel_connection()`, own kTLS module, TLS 1.3 only. TX/RX rekey on ≥6.14, with key derivation on the control thread. | `ktls` crate (Tokio-bound, no KeyUpdate). Userspace TLS on workers (copy plus CPU). |
| D10 | Send path | Plain `SENDMSG` gathering `[header, value slot or staging buffer, trailer]`, **without** `MSG_WAITALL`, so a short count reports exact progress. Payload is submitted in chunks of ≤ 128 KiB per `io_uring_enter`. Software kTLS encrypts straight from the user pages for full records, so the encryption is the only pass (§6.4.1). | `SEND_ZC` (EOPNOTSUPP on kTLS sockets). `splice` from the SSD (io-wq on every read, kernel page allocation, no CRC check before send, no pass saved with software kTLS; a phase-6 option for NIC offload only). |
| D11 | Recv path | Header phase: one-shot `RECV` with provided buffers. Body phase: one-shot `RECV` straight into the reserved slot. Control records and `-EKEYEXPIRED` are handled in both phases. | Multishot from day 1 (races with the body-phase switch). Deferred to phase 6. |
| D12 | io_uring crate | `io-uring` 0.7.x, hand-rolled completion loop | monoio, glommio, tokio-uring, compio (owned buffers, hidden SQE flags, allocate) |
| D13 | Index | Per-shard 8-way 2-choice bucketized cuckoo (64 B bucket lines) over a 32 B entry slab holding the **full key** | Tag-only index (false-positive 64 KiB SSD reads hurt the tail) |
| D14 | Warm restart | Optional (phase 6), **after a clean shutdown only**. A crash means a cold start. | Crash-consistent restart (needs persistent DEL/overwrite tombstones, which add wear) |
| D15 | Protocols | `Protocol` trait, enum dispatch (`AnyProto`), borrowed parse output, body as a separate outcome | `dyn` dispatch. Compose-into-buffer (copies values). |
| D16 | SET slot source | Per-(A,B) **stash** of 2–4 owner-granted Filling slots (v1), so the body recv starts at once and only Commit crosses shards | A Reserve hop before every body (one owner tick per SET, serializes pipelined SETs) |

---

## 2. Threading model

### 2.1 Threads

| Thread | Count | Pinned | Responsibilities | Allocation allowed |
|---|---|---|---|---|
| Control (acceptor + admin) | 1 (+ optional `tls_threads` extra handshake threads) | Yes, on a non-worker core | Multishot accept, rustls handshake, kTLS install, worker selection, handoff, **rekey key derivation**, admin HTTP, stats aggregation, write-budget rebalancing, SMART/wear polling, shutdown orchestration | Yes |
| Worker | N (example N = 16; benchmark 8/16/32) | Yes; optionally `isolcpus`/`nohz_full` | io_uring loop. Connections it owns: recv, parse, send, kTLS control records, rekey state machine and `setsockopt`. **Shard it owns:** index, entry slab, cache and staging pools, M ring, ghost, sketch, write budget, regions it wrote, SSD IO. | No (except the capped fallback pool) |

The user's constraint is met: connection establishment and admin never run on request threads. If handshake CPU limits accept rate (churn above about 5–10k handshakes/s per core with ECDSA P-256), add handshake threads. They feed the same handoff queues.

**Sizing N.** The NIC sets the ceiling: about 190k GET/s at 64 KiB on 100 GbE (§3.5). At about 15–20 µs of kTLS plus TCP work per 64 KiB GET, that is 3–4 cores of crypto. More workers make H, the N² SPSC rings and the doorbell traffic larger and make each worker idler, so more hops find the owner asleep. The example uses N = 16. Phase 2 benchmarks N = 8/16/32 and picks the smallest N that meets p99.99 at peak.

### 2.2 Shard ownership and hash bit map

- `h = xxh3_128(seed, key16) = (hi: u64, lo: u64)`. The seed is random per process; UUIDv1/v7 keys are not uniform, so we always hash.
- **Bit map (no field overlaps any field it must be independent of):**

| Field | Bits | Derivation |
|---|---|---|
| Shard | `hi[63:32]` | `((hi >> 32) * N) >> 32` (fast range) |
| Index tag (16 bit, non-zero) | `hi[15:0]` | 0 is remapped to 1 |
| Ghost bucket | `hi[31:0]` | fast range over the ghost buckets (separate table; it may share bits with the tag) |
| Index bucket 1 | `lo[31:0]` | fast range over `nbuckets` (≈ 20–23 bits used) |
| Index bucket 2 | — | `(f(tag) − bucket1) mod nbuckets` (an involution, valid for any `nbuckets`) |
| Ghost fingerprint (32 bit, non-zero) | `lo[63:32]` | independent of the shard, tag and index-bucket bits |
| Sketch line and counters | remix | `m = (lo ^ hi.rotate_left(29)).wrapping_mul(K)`; line = fast range of `m >> 32`, counter positions from `m[15:0]` |

- Worker *i* is the only thread that ever **mutates** shard *i*'s state. Other workers may **read** slot *bytes* (to send them) under a pin the owner granted. They never read or write shard metadata.

### 2.3 Connection handoff (control → worker)

1. The control ring has multishot `ACCEPT`. Handshake I/O runs on the same ring with record-exact reads (§6.2).
2. The control thread picks a worker: fewest connections, from per-worker `CachePadded<AtomicU32>` counters. Ties go to a worker on the NIC's NUMA node.
3. It pushes `Handoff { fd: RawFd, proto: ProtoKind, tls: Option<Box<TlsState>>, peer }` into that worker's **handoff SPSC** (capacity 1024). `TlsState` holds the `KernelConnection`, the cipher and the record counters. It comes from a control-thread pool. On close the worker returns it through a **return SPSC**, so the worker never frees heap memory.
4. Doorbell: `MsgRingData` to the worker's ring fd with `user_data = HANDOFF`. The control thread has its own ring, so this works on 6.1. On 6.13+ `IORING_REGISTER_SEND_MSG_RING` also works.
5. The worker drains the queue. It installs the fd into its sparse fixed-file table with the **synchronous** `register_files_update` call, before it prepares the first RECV. That call is uncontended, because the worker is the single issuer of its own ring. (An async `FilesUpdate` SQE submitted with the RECV has no guaranteed order if it is punted, and the RECV can fail with `-EBADF`. If the async form is ever used, link it to the RECV with `IOSQE_IO_LINK`.) The worker **keeps the raw fd** for rekey `setsockopt`.

We do not use `IORING_MSG_SEND_FD`. We need the SPSC anyway to carry `TlsState` and protocol metadata. (Its locking cost depends on the kernel: older kernels take the target's `uring_lock`, and newer kernels post to single-issuer or DEFER_TASKRUN targets through task_work. That cost is not the reason for this choice.)

### 2.4 Cross-shard messaging

- **Topology:** one SPSC ring per ordered pair (A→B), including A→A for uniform accounting. Local calls bypass the ring. A second, small **region-control** SPSC per ordered pair (64 entries) carries `RegionMsg` (§3.4). It is not credit-based: a sender that finds it full retries the action on the next tick.
- **Ring size:** 256 entries × 64 B. Total N²·16 KiB = **4 MiB** at N = 16 (plus 1 MiB of region-control rings).
- **Messages** are `#[repr(C, align(64))]`, one cache line:

```rust
enum ShardMsg {
    // A -> B (B = owner)
    Lookup  { h: u128, key: Key, req: ReqToken },                    // op credit + 1 pin-quota unit
    Reserve { h: u128, key: Key, req: ReqToken },                    // SET when A's stash for B is empty
    Commit  { h: u128, key: Key, slot: u32, slot_gen: u32, mode: SetMode, req: ReqToken },
    Abort   { slot: u32, slot_gen: u32 },                            // only after the body RECV CQE is reaped
    Delete  { h: u128, key: Key, req: ReqToken },
    Unpin   { n: u8, slots: [(u32 /*slot*/, u32 /*slot_gen*/); 7] }, // batched by sender per loop tick
    // B -> A
    Hit     { req: ReqToken, slot: u32, slot_gen: u32 },             // A sends from B's slot memory
    Miss    { req: ReqToken },
    Reserved{ req: ReqToken, slot: u32, slot_gen: u32 },
    Grant   { slot: u32, slot_gen: u32 },                            // unsolicited stash refill
    Done    { req: ReqToken, status: Status },                       // Stored/NotStored/Deleted/NotFound/Err
    // control -> worker (separate ring)
    Config(..), Drain, Stats, RekeyDone { conn_idx: u32, conn_gen: u16, dir: Dir, info: CryptoInfoRef }
}
enum RegionMsg { Reclaim { r: u32, seq: u64 }, Sealed { r: u32 } }   // region-control ring
struct ReqToken { conn_idx: u32, conn_gen: u16, resp_idx: u16 }
```

- **Three separate budgets per ordered pair (A,B).** An op credit is not tied to a pin's lifetime, so one slow client cannot hold other connections' credits.

| Budget | Size (default) | Taken | Returned | Bounds |
|---|---|---|---|---|
| Op credit | **C = 32** (≈ BDP: ~185 ops/s per pair × ≤ 150 µs, with a large margin for bursts) | `Lookup`/`Reserve`/`Delete` sent | reply **received** at A (`Hit`/`Miss`/`Reserved`/`Done`) | ring occupancy, owner work queue |
| Pin quota | **P = 64** per pair; **p_conn = 8** per connection per owner | with `Lookup` (reserved before dispatch) | `Miss` received, or `Unpin` sent | zombies and pinned staging slots at B |
| Fill quota | **F = 8** per pair (includes a stash of up to 4) | `Reserve` sent or `Grant` received | `Commit`/`Abort` sent | Filling slots at B |

  - When A lacks any of these for B, the *connection* parks. Its recv is not re-armed, and TCP pushes back on the client. Other connections on A continue. Per-connection quotas mean one connection can never hold more than 1/8 of a pair's pin quota.
  - A→B ring occupancy ≤ C + F + ⌈P/7⌉ < 256. B→A ≤ C + F.
- **Ordering.** All requests from one connection for one key travel A→B on one FIFO ring, so B applies them in arrival order. A pipelined `SET k; GET k` on a connection is read-your-writes: the GET is parsed only after the SET body is complete, so `Commit` is pushed before `Lookup`.
- **Doorbell protocol** (no lost wakeups; this is the Dekker pattern, so both sides need a SeqCst fence):
  - Consumer: `sleeping.store(true, Relaxed); fence(SeqCst);` re-scan inbound ring tails (Acquire), and if any is non-empty, `sleeping.store(false, Relaxed)` and continue. Else `submit_and_wait(1)`. On wake, `sleeping.store(false, Relaxed)`.
  - Producer: push with `Release`, `fence(SeqCst)`, then `if target.sleeping.swap(false, AcqRel) { MsgRingData(target_ring_fd, XSHARD) }`. The swap removes duplicate doorbells.
  - Both sides are modeled in loom with the fences exactly as written.
  - **Adaptive spin is on by default** (`spin_us = 30`, range 20–50) before sleeping. At realistic load a worker is mostly idle, so without the spin most hops would pay a `MSG_RING` wakeup. Worker cores also get a `cpu_latency_qos` limit (`/dev/cpu_dma_latency` held open with a value ≤ 10 µs) or C6 disabled in BIOS. C6 exit latency (about 50–130 µs) would otherwise go into p99.9.
- **Cost model** (estimate; measure):
  - **Hop = queueing behind the owner's current tick**, plus the wakeup when the owner sleeps (2–10 µs, rare with the spin). The loop in §2.5 bounds the inline crypto work between two owner passes to about one send chunk (≤ 128 KiB of payload, about 20–40 µs). So the owner response time is bounded by about 40 µs at p99.99, not by the length of a whole flush.
  - Owner work per op: about 0.3–1 µs (2–3 index misses + 1 sketch miss + bookkeeping).
  - Connection-side work per 64 KiB GET: kTLS AES-GCM at an estimated 3–6 GB/s/core is about 11–22 µs, plus TCP.
  - **Owner response latency** (time from `Lookup` enqueue to `Hit` enqueue) is a first-class histogram. It is a phase-2 exit criterion.

### 2.5 Worker event loop

```text
loop {
  1. reap CQEs (batch): recv/send/ssd/demote/handoff/doorbell → advance state machines
  2. OWNER PASS: drain inbound SPSC rings, ≤ 64 msgs per ring (fairness); owner ops + replies; publish tails
  3. drain handoff queue, rekey replies, region-control rings
  4. bounded background work: make_room(≤ 64 evictions), grant queued Reserves, reclaim(≤ 64 slots), seal/footer, timers
  5. flush dirty connections in CHUNKS: prepare SENDMSGs until ≥ send_chunk_bytes (128 KiB) of payload,
     submit(); OWNER PASS (step 2, owner ops only); repeat until the flush list or the tick budget is empty
  6. batch outbound Unpins; publish SPSC tails; doorbells
  7. spin up to spin_us on the inbound tails; then the sleeping-flag protocol; submit_and_wait(have_pending_work ? 0 : 1)
}
```

Sends run inline inside `io_uring_enter` (no SQPOLL), and each send includes the kTLS encryption. Chunked submission with an owner pass between chunks keeps a remote GET from waiting behind a whole tick of crypto.

### 2.6 Why this minimizes tail latency without locks

1. **No shared mutable metadata on the request path.** The only atomics a worker touches:
   - SPSC head/tail (acquire/release, uncontended pairs)
   - the `sleeping` flag
   - one `fetch_add` on the global region cursor per region allocation, and an atomic load of `RegionMeta.seq` per SSD read (lap check, a read-shared line)
   - relaxed stats stores

   There are no CAS retry loops, no epochs and no pin-count cache-line ping-pong. **One known cross-core shared write on the send path:** if kTLS uses its zero-copy-from-iov path (synchronous AEAD, full records), it takes folio references on the user pages. With 1 GiB hugetlb folios, all workers that send slots from the same GiB increment and decrement one refcount line. For this reason the default arena page size is 2 MiB (512× more folios). 1 GiB pages are enabled only if the phase-4 benchmark shows no refcount contention at p99.99 (§3.2, §6.2).
2. **Low service-time dispersion.** Fixed key and value sizes make per-core FCFS queues behave well (Shinjuku and RackSched find partitioned queues fail mainly under heavy-tailed service times). The heavy crypto work stays on the connection's core, so hot keys concentrate only the small owner work. A key with 10% of 190k req/s (19k ops/s) adds about 2% CPU to its owner.
3. **Blast radius.** A stall on one worker (preemption, IRQ storm, reclaim burst) delays 1/N of keys plus that worker's connections, not all traffic. In the 1-storage-thread model every request crosses one queue.
4. **All background work runs in bounded steps** (64 per tick). It is never synchronous with a request, except the bounded forced eviction in §4.4 (≤ 4 evictions, ≤ 20 ring pops).
5. **Design point:** ≤ 60–70% per-core utilization at peak. Pre-fault and mlock all memory. No page faults on the request path. Measure hop p99.99 with the production power settings, not only at saturation.

**NUMA:** on multi-socket hosts, run **one server instance per NUMA node**, each with its own NIC port and SSDs. Senders then never read remote memory.

---

## 3. Data layout

### 3.1 Value and slot geometry

- `V` = configured value size (bytes on the wire).
- Slot stride `S = round_up(V, 4096)`. Headers live **outside** the slot: memory metadata in `SlotMeta`, SSD metadata in the region footer. So 64 KiB = 16 pages exactly. 20,000 B pads to 20,480 (2.4%). 100 KB (102,400) has no padding.
- The wire length is always `V`. Padding is never sent.
- Every ring, table and id width is derived from V in `sizing.rs`. No size is hard-coded for 64 KiB. Unit tests check both ends of the 20–100 KB range.

### 3.2 Memory tier: slot arena

- One `mmap(MAP_HUGETLB)` arena of `mem_slots × S` bytes. **Default page size is 2 MiB**; `hugepage = "1G"` is a config option, enabled only after the phase-4 refcount benchmark (§2.6). It is pre-faulted and `mlock`ed.
- It is partitioned contiguously per shard. Each partition is first-touched by its owner thread (`mbind` to the local node).
- It is registered in **every** worker ring as 1 GiB chunks:
  - `slots_per_chunk = floor(2^30 / S)`. Slot ids are dense; a slot never straddles a chunk (the at most one slot per GiB that would straddle is simply not given an id).
  - **Coordinates:** `chunk = slot / slots_per_chunk`, `off = (slot % slots_per_chunk) × S`. `buf_index = chunk`; the address is `arena + chunk × 2^30 + off`. Plain pointers (send iovecs) use the same mapping.
  - 192 chunks for 192 GiB, far below the 16,384 limit.
  - Use `IORING_REGISTER_CLONE_BUFFERS` (6.12+) for rings 2..N, else register in each ring. Startup logs the kernel memory used by the registered-buffer tables (with 2 MiB pages, a kernel that does not coalesce folios needs more bvec entries).
  - Needs `CAP_IPC_LOCK` or a raised `RLIMIT_MEMLOCK`.

```rust
#[repr(C)]
struct SlotMeta {        // 16 B, dense array, owner-local (only owner shard touches)
    pins: u16,           // in-flight sends (any thread, via owner), SSD write, coalesced readers
    state: u8,           // Free | Filling | Live | Zombie | Staging
    _r: u8,
    gen: u32,            // bumped on every free; Unpin/Commit/Abort carry it (ABA guard)
    eh: u32,             // owning entry when Live (debug/consistency)
    _r2: u32,
}
```

Per-shard pool = `cache_slots + H`. H (headroom) is sized in §5.1. Allocation can fail, and every caller has a bounded wait path.

### 3.3 Index (per shard, single writer)

```rust
#[repr(C)]
struct Entry {           // 32 B, slab indexed by entry handle `eh: u32`
    key: [u8; 16],       // full key: no false-positive SSD reads
    mem: u32,            // memory slot or NONE
    ssd: u32,            // global SSD slot id (≤ 28 bits at 20 KB) or NONE (both set => "clean" copy)
    ver: u32,            // content version: bumped on SET/DEL/free; never reset on handle reuse
    meta: u32,           // q:1 {None,M} | freq:2 | hit:1 | gadmit:1 | dead:1 | reading:1 | writing:1 | lap:8 | rsv:16
}

#[repr(C, align(64))]
struct Bucket {          // 64 B: 8-way, probed with one SIMD compare on tags
    tags: [u16; 8],      // 0 = empty
    eh:   [u32; 8],
    _pad: [u8; 16],
}
// bucket2 = (f(tag) − bucket1) mod nbuckets (involution); bounded BFS cuckoo insert (depth 4) + 64-entry stash.
```

- **Lookup:** 1 bucket line, then the entry line on a tag match, then at most 1 more bucket. That is 2–3 cache misses.
- **Load factor:** ≤ 0.85. No resize ever.
- **SSD location = `(ssd, lap)`.** `lap = (RegionMeta[r].seq / R) as u8` at demotion time. Before an SSD read is issued, and again at its completion, the owner checks `lap == (RegionMeta[r].seq / R) as u8` (atomic load). A mismatch is a miss, never a hit. This is defense in depth behind the synchronous-reclaim rule (§4.4).
- **Entry handle lifecycle (tombstones):**
  - A deleted or evicted entry leaves the index immediately and sets `dead`.
  - Its handle is freed only when `q == None && !reading && !writing`.
  - So no ring element ever refers to a reused handle, and rings need no generation tag.
- **SSD back-map:** per SSD slot, `(eh: u32, ver: u32)` (8 B). It is written at demotion submit and used by reclaim. A slot is live iff `ent[eh].ver == ver && ent[eh].ssd == slot && !dead`.

### 3.4 SSD layout

```
raw NVMe namespace (4 KiB LBA format; statx(STATX_DIOALIGN) checked at startup)
├─ [0, 1 MiB)    superblock A/B (4 KiB each): magic, format ver, instance UUID, V, S, region size,
│                region count, slots/region, clean-shutdown flag, epoch
├─ region[0]     64 MiB = 1023 × 64 KiB slots + 64 KiB footer   (for S = 64 KiB)
├─ region[1] ...
└─ unused tail   host over-provisioning (default 7% without FDP; 0% with FDP)

footer (written once at seal; 32 KiB used of 64 KiB for S = 64 KiB):
  header 32 B {magic, instance UUID, region_seq u64, shard u16, V u32, fill u16, crc}
  per slot 32 B {key[16], ver u32, crc32c(value) u32, flags u32, rsv u32}
```

- **General rule:** `slots_per_region = floor((region_bytes - F) / S)`, where `F = round_up(32 + 32·slots, 4096)`. Default `region_bytes = 64 MiB`. With FDP, use a divisor of the reclaim-unit size; with ZNS, the zone capacity.
- **Format discards the whole namespace** (NVMe Deallocate, `blkdiscard`, or Format with secure erase). After a geometry change, the unused tail is discarded again. Without this, LBAs from earlier use stay valid to the FTL, the 7% host OP gives no real OP, and DLWA rises. The measured DLWA (§4.5) checks the result.
- **Global region FIFO (D6):**
  - `RegionMeta[r]` holds `{state: AtomicU8 (Clean|Open|Sealed|Reclaiming|Draining), owner: AtomicU16, seq: AtomicU64}` plus owner-exclusive fields `{fill: u16, inflight_reads: u16, inflight_writes: u16, opened_at: u32}`. Ownership passes through Release/Acquire on `state`.
  - **A shard needing a new open region:**
    1. If it holds a **pending seq** from an earlier attempt, reuse it. Else `seq = REGION_CURSOR.fetch_add(1)`. Then `r = seq % R`.
    2. Require `state == Clean`. If it is not Clean, keep `seq` as the pending seq and **retry on the next tick**. Never fetch another seq: skipping regions breaks the global FIFO that DLWA ≈ 1 depends on. While it waits, demotion candidates drop to G, and a counter (`region_wait`) increments.
    3. Set owner, `seq` and Open.
    4. Send `RegionMsg::Reclaim{(seq + K) % R}` to that region's owner on the region-control ring (local call if self). K = max(4N, 128) = 128 regions are kept clean ahead of the cursor.
  - **Bounded open-region age.** A shard seals its open region (writes the footer with `fill` < slots_per_region, leaves the remaining slots unwritten) when it has been Open longer than `open_max_age` (default 10 min), or when `REGION_CURSOR − seq > max(R/4, 2N)`. The 2N floor stops a small device from sealing every region nearly empty: one round of opens moves the cursor by N, so a limit at or below N marks every open region as lagging. Startup requires `R ≥ K + 4N + 4`. A shard with little demotion demand therefore never holds a region that the cursor laps. On 6.12+ the unwritten remainder is discarded asynchronously (block uring_cmd discard); on older kernels it is left as is (small FTL cost).
  - **Reclaim of a region that is still Open** (only possible if the age bound failed, for example after a long stall): the owner first closes it. It stops appends, waits for `inflight_writes == 0`, seals, and then reclaims. There is no direct Open → Reclaiming transition.
  - Within a region, slots are written in order. Each slot is its own `WRITE_FIXED` straight from the memory slot.
  - All shards allocate from one cursor and reclaim in cursor order. Every erase block therefore holds data from one narrow time window, and that data dies together, so DLWA ≈ 1.
  - Write budgets are rebalanced by demand (§4.5), so fill rates differ between shards. The age bound limits the effect: a slow shard's region is sealed early, and its lifetime stays inside the global window. At 1 DWPD and N = 16 a region fills in about 1023 / 35.3 ≈ 29 s.
- **Multiple SSDs:** region r lives on device `r % D`, at offset `(r / D) × region_bytes`. The global cursor stripes writes and reads across devices.
- **No TRIM in steady state.** Strict FIFO overwrite makes it unnecessary. TRIM is used only at format, after a geometry change, and optionally for the tail of an early-sealed region.
- **FDP (6.16+ `sqe->write_stream`):** stream 0 for data, stream 1 for the superblock. Phase 6.

### 3.5 Example sizing: 256 GiB RAM, 4 TB SSD, N = 16

All values below are computed by `sizing.rs`. The 20 KB column is the worst case for metadata.

| Item | Formula | V = 64 KiB | V = 20,000 B |
|---|---|---|---|
| Slot stride S | round_up(V, 4096) | 65,536 B | 20,480 B |
| Slots per 1 GiB chunk | floor(2³⁰ / S) | 16,384 | 52,428 |
| Memory arena (192 GiB) | 192 × slots_per_chunk | **3,145,728** (196,608/shard) | **10,066,176** (629,136/shard) |
| Headroom H per shard (cache pool) | N·P + N·F + W = 16·64 + 16·8 + 64 | 1,216 (total 19,456 = 1.19 GiB) | 1,216 (total 19,456 = 380 MiB) |
| Staging pool per shard (SSD reads) | QD + N·P = 128 + 1,024 | 1,152 (total 18,432 = 1.125 GiB) | 1,152 (total 18,432 = 360 MiB) |
| Cache slots = M capacity | per shard / total (192 GiB arena − H − staging) | 194,240 / **3,107,840** | 626,768 / **10,028,288** |
| M as a fraction of M+D | | 5.2% | 5.3% |
| SSD usable | 0.93 × 4.0e12 − 1 MiB | ≈ 3.72e12 B | ≈ 3.72e12 B |
| Regions R | floor(usable / 64 MiB) | **55,432** | **55,432** |
| Slots per region / footer | §3.4 rule | 1023 / 64 KiB | 3,271 / 104 KiB |
| SSD slots | R × slots/region | **56,706,936** (26-bit ids) | **181,318,072** (28-bit ids) |
| Effective D (minus K = 128 clean + 16 open) | (R − 144) × slots/region | 56,559,624 | 180,847,048 |
| Footer overhead | F / 64 MiB | 0.098% | 0.16% |
| Max live keys | M + D | 59,667,464 | 190,875,336 |
| M ring per shard | next_pow2(1.25 × M cap) | 262,144 (16 MiB total) | 1,048,576 (64 MiB total) |
| Entry slab | (max live + ring capacity + H) × 32 B | 64.95M → 2.08 GB | 211.9M → 6.78 GB |
| Index buckets | max live / (8 × 0.85) × 64 B | 0.56 GB | 1.80 GB |
| SSD back-map | SSD slots × 8 B | 0.45 GB | 1.45 GB |
| Ghost | (\|M\|+\|D\|) × 1.25 × 8 B | 59.37M → 0.59 GB | 189.9M → 1.90 GB |
| Count-min sketch (blocked) | per shard next_pow2(keys/shard) × 4 bit | 2²² × 4 bit = 2 MiB/shard, **32 MiB total** | 2²⁴ × 4 bit = 8 MiB/shard, **128 MiB total** |
| SlotMeta | arena slots × 16 B | 50 MB | 161 MB |
| Region meta | R × 64 B | 3.5 MB | 3.5 MB |
| Connections | 65,536 × 32 KiB | 2 GiB | 2 GiB |
| Provided recv buffers | 16 × 2048 × 16 KiB | 512 MiB | 512 MiB |
| SPSC rings (+ region-control) | 16² × 256 × 64 B (+ 16² × 64 × 64 B) | 5 MiB | 5 MiB |
| Send spill pool | 16 × 32 × S | 32 MiB | 10 MiB |
| **Total resident** | | **≈ 192 GiB + 6.1 GiB = 198.1 GiB** | **≈ 192 GiB + 14.0 GiB = 206 GiB** |
| Left for kernel and OS | 256 − total | ≈ 57.9 GiB | ≈ 50 GiB |

At 64 KiB, index plus back-map plus slab cost ≈ 51.8 B per cached object (61.7 B including ghost). The memory tier holds ≈ 5.2% of cached objects (3.11M of 59.7M). The staging pool comes out of the same 192 GiB arena, so the arena and total rows are unchanged. At 20 KB the metadata is about 3× larger. A deployment at the small end of the range can move some DRAM from the arena to metadata.

Socket buffers come out of the "left" row: `SO_SNDBUF` 512 KiB × 65,536 = 32 GiB worst case. `tcp_mem` is set explicitly (pressure ≈ 24 GiB, high ≈ 36 GiB at 64 KiB values), and memory-pressure events raise an alert (§6.4).

**Write budget (initial values, before wear measurements exist; §4.5):**

| Quantity | 1 DWPD | 3 DWPD |
|---|---|---|
| Safe host write rate (4.0e12 × DWPD / 86,400 × 0.8) | 37.0 MB/s | 111.1 MB/s |
| Slot writes per second (64 KiB / 20 KB) | 565 / 1,807 | 1,695 / 5,422 |
| Per shard, N = 16 (64 KiB / 20 KB) | 35.3/s / 113/s | 106/s / 339/s |
| D-tier turnover (effective D ÷ write rate) | **≈ 27.8 h** | ≈ 9.3 h |

Rated DWPD is specified with the JEDEC JESD219 enterprise workload (random small writes, device WAF ≈ 2.5–4). This design writes a sequential circular log with DLWA ≈ 1, so the NAND can probably take about 2–4× the rated host writes. The table is therefore a conservative start. The wear controller (§4.5) raises the rate when measured wear allows it. Lifetime host writes over 5 years at 1 DWPD: 4e12 × 365 × 5 = **7.3 PB** (relevant if the warranty is TBW-based; see §4.5 and Q3).

At 100k GET/s with a 5% miss rate there are 5,000 fills/s. Only about 11% of M-evictees can be written at the initial 1 DWPD rate (fewer are candidates in v1.2: only those with a DRAM hit or a ghost hit). Admission (§4.5) is the binding constraint, so every unused unit of real endurance costs hit ratio.

**Network and storage ceilings (one consistent target: 190k GET/s at 64 KiB):**
- 100 GbE ≈ 12.5 GB/s, which is about 190k GET/s of 64 KiB (about 12k/s per worker at N = 16), or about 625k GET/s of 20 KB.
- One Gen4 NVMe (about 6.5 GB/s of reads) serves about 100k 64 KiB SSD hits/s. **Drives needed = ⌈190k × h_D / 100k⌉**, where h_D is the fraction of GETs served from D. With the single 4 TB drive in this example, the NIC rate holds only while h_D ≤ ~50%. At 100% D hits, 2 drives are needed. SSD read bandwidth is a capacity-planning input, next to the write budget. v1.2 never promotes D hits, so an object that turns hot after it reached D keeps costing SSD reads; phase 0 reports h_D for this reason.

---

## 4. Eviction: DRAM probation over an SSD main queue (S3-FIFO, tiered)

### 4.1 Queues

v1.2 removes the separate S queue and all SSD→DRAM movement. Three structures remain:

| Queue | Medium | Structure | Capacity | Role |
|---|---|---|---|---|
| **M** (memory) | DRAM | FIFO-reinsertion (CLOCK) ring of `eh`, 2-bit freq | all DRAM cache slots (≈ 5% of M+D) | Every new object enters here. It is the observation window for SSD admission and it holds the hottest objects. |
| **D** (SSD main) | NVMe | Global circular log of 64 MiB regions, strict FIFO | all SSD slots (≈ 95% of M+D) | **The main store.** Objects never leave D for DRAM. A D hit is served from a transient staging buffer. |
| **G** (ghost) | DRAM | Bucketed `{fp: u32, vts: u32}`, expired if `vts < N_ins − \|G\|` | \|M\| + \|D\| entries | Keys dropped from M without admission, and keys evicted from D. A ghost hit on SET marks the new object as pre-admitted. |

**Why one DRAM queue.** D is the main store, so the right model is the S3-FIFO paper's flash configuration: **"S in DRAM, M on flash"**. The paper reports that configuration had the lowest miss ratio and the fewest flash writes, compared with probabilistic and Flashield admission. In v1.1, DRAM held a small S (≈ 0.5% of M+D) and an M in front of D. The S window was about 60 s, so most admission fell back to the ghost (second-miss admission). In v1.2 the whole DRAM tier is the probation queue for D:
- It is ≈ 5% of the logical cache. The paper's S is 10%, so this is close to the paper's configuration, not 20× smaller.
- An object has its whole DRAM residence to prove reuse before it costs a flash write. At 5k fills/s, that window is 3.12M slots / 5k/s ≈ 10 min, against ≈ 60 s for the v1.1 S.
- One ring, one eviction routine, one fewer queue state. The S/M split, `s_frac`, `s_promote_hits` and `s_to_m_keep_freq` are gone.

**What we give up.** A one-hit wonder now stays in DRAM for a full lap before it is dropped, not for 10% of a lap. That costs DRAM hit ratio, not flash writes, because one-hit wonders are still filtered at the M→D boundary. DRAM serves only ≈ 5% of the objects, so this cost is small. Phase 0 checks it against a small FIFO probation segment inside M (knob `m_probation_frac`, default 0).

**Why M is CLOCK and not FIFO.** The paper's S is a plain FIFO. We keep CLOCK reinsertion in M so that objects that stay hot remain in DRAM and never cost an SSD read. This matters because SSD read bandwidth limits throughput when most GETs hit D (§3.5). `m_clock = false` gives the paper's plain FIFO for the phase-0 comparison.

**Why nothing moves from D to DRAM.**
- A promotion displaces an M object. That object is new and has not yet proven reuse, so displacing it is wrong.
- It removes the clean-copy state and the promotion throttle (v1.1 §4.5 item 5 and §4.6), and the race rows that went with them.
- An SSD hit costs one read and one send from a staging buffer. The staging buffer goes back to the pool after the send, so D hits never use cache slots.
- **Cost:** an object that becomes hot after it reached D is served from SSD for the rest of its D residence. This is a capacity-planning input (drives needed for read bandwidth, §3.5), not a policy problem.

**D is a strict FIFO by default.** v1.1 used region-granular CLOCK reinsertion, where a hot victim was read back into M. That is a D→DRAM move, so v1.2 removes it. An evicted D object goes to G. If the client fills it again (SET after a miss), the ghost hit pre-admits it. The cost is one client-visible miss and one write: the same write a reinsertion costs, with one fewer SSD read. An optional SSD→SSD rewrite (`d_rewrite_hits`, off by default) reads a hot victim into a staging buffer and appends it at the log head. It never enters DRAM, and it pays from the same token bucket. Phase 0 decides whether it earns its write cost.

### 4.2 Frequency and admission bits

Each entry has a 2-bit `freq` and two admission bits: `hit` (sticky: set on any hit while the object is in M) and `gadmit` (set when the SET consumed a ghost entry).

| Event | Effect |
|---|---|
| Insert into M (SET of a new key) | `freq = 0`, `hit = 0`, `gadmit = ghost.take(fp)` |
| Hit in M | `freq = min(freq+1, 3)`, `hit = 1` (plain byte stores, no queue movement) |
| Hit in D | `freq = min(freq+1, 3)`, used only by the optional `d_rewrite_hits` and by stats |
| M reinsertion (CLOCK) | `freq − 1` |
| M eviction with `freq == 0` | **Admission candidate if `hit \|\| gadmit`**, then token bucket and θ (§4.5). Otherwise drop to G. |
| M → D demotion completes | If there were hits during the write: stay in M as a clean copy with `freq − 1`. Its next eviction is free. Otherwise: release the DRAM slot, D only. |
| SET overwrite | New slot in M. `freq` unchanged. `hit` and `gadmit` are kept (an overwritten key has proven reuse). The old SSD copy is dead. |

### 4.3 Policy parameters (config, all validated in the simulator)

```rust
struct PolicyCfg {
    m_clock: bool,            // true: CLOCK reinsertion in M; false: plain FIFO (paper S)
    m_probation_frac: f32,    // 0.0: optional FIFO probation segment inside M (phase-0 comparison)
    m_max_spins: u16,         // 64 consecutive CLOCK reinsertions → force-evict tail (tail-latency bound)
    m_max_spins_forced: u16,  // 4: under slot pressure each forced eviction pops at most 5 entries
    admit_requires_hit: bool, // true: an M evictee needs `hit || gadmit` to be a D candidate
    d_rewrite_hits: u8,       // 0 = off. ≥1: SSD→SSD rewrite of D victims with freq ≥ this, token-gated
    d_rewrite_max_frac: f32,  // 0.05 of a region's slots, when rewrite is on
    ghost_entries: u64,       // |M|+|D|
    ghost_d_evictees: bool,   // true
    open_max_age_s: u32,      // 600
    // wear (§4.5)
    service_life_days: u32,   // e.g. 1826 (5 y)
    rated_dwpd: f32,          // initial rate only
    seq_endurance_factor: f32,// per-drive config; 1.0 until wear is measured
    safety: f32,              // 0.8
    sketch: bool,             // true: admission threshold under budget pressure
}
```

### 4.4 Pseudocode (per shard; no allocation; all plain fields)

Two slot pools per shard:
- **Cache pool** (`slots`): M objects, Filling slots for SET bodies, zombies held by sends, slots pinned by demotion writes.
- **Staging pool** (`staging`): SSD read buffers only. A staging buffer is never indexed and never becomes a cache slot.

Accounting fields: `mem_used` (Live slots in M), `pending_free` (dirty demotions in flight; their slots are still in `mem_used`), `demote_inflight` (≤ W), `free_slots()` (cache-pool free list), `hard_low` (forced-eviction trigger).

```rust
// ---------- request-path owner ops ----------
fn lookup(sh: &mut Shard, h: u128, key: &Key, req: Req) -> Reply {
    sh.sketch.inc(h);                                 // blocked CMS: 1 cache line
    let Some(eh) = sh.idx.find(h, key) else { return Reply::Miss };
    let e = &mut sh.ent[eh];
    e.bump_freq();
    if e.mem != NONE { e.set_hit(); sh.slots.pin(e.mem); return Reply::Hit(Buf::Cache(e.mem)) }
    if !sh.lap_ok(e.ssd, e.lap()) { sh.drop_entry(eh); return Reply::Miss } // defense in depth
    let op = if e.reading() { sh.read_op_of(eh) }     // coalesce onto the in-flight read
             else { e.set_reading(true); sh.queue_read(eh, e.ver, e.ssd, e.lap()) };
    sh.waiters.push(op, req);                         // fixed table, ≤ N·P nodes
    Reply::Pending
}

// queue_read: takes an IoOp, increments the region's inflight_reads AT QUEUE TIME (so the region
// cannot drain to Clean while the read waits), and submits READ_FIXED into a staging buffer when
// SSD QD < 128 and a staging buffer is free. Otherwise it waits in the shard-local IoOp FIFO.

fn on_ssd_read(sh: &mut Shard, op: SsdRead, res: i32) {
    sh.region_read_done(op.ssd);                      // may move Draining → Clean
    let e = &mut sh.ent[op.eh]; e.set_reading(false);
    let lap_ok = sh.lap_ok(op.ssd, op.lap);           // re-check at completion
    if res != SLOT_BYTES || !lap_ok || !sh.footer_crc_ok(op) {
        if lap_ok { sh.fail_waiters(op) } else { sh.miss_waiters(op) }
        sh.staging.free(op.buf);
        if !e.dead() && e.ver == op.ver && e.mem == NONE { sh.drop_entry(op.eh) } // no SSD pointer survives a failed read
        sh.release_if_unref(op.eh); return;
    }
    for w in sh.waiters.take(op) { sh.staging.pin(op.buf); sh.reply(w, Reply::Hit(Buf::Staging(op.buf))) }
    sh.staging.retire(op.buf);                        // back to the staging pool at the last unpin; never cached
    if op.rewrite { sh.rewrite_from_staging(op) }     // optional d_rewrite_hits path: SSD → SSD, never DRAM
    sh.release_if_unref(op.eh);
}

fn reserve(sh: &mut Shard, from: Worker, req: Req) -> Option<(u32, u32)> {
    if sh.free_slots() > sh.hard_low { return Some(sh.slots.alloc_filling()) }
    sh.reserve_waiters.push(from, req);               // fixed list, ≤ N·F; granted by the tick (below)
    sh.want_room = true; None
}

fn commit(sh: &mut Shard, h: u128, key: &Key, slot: u32, slot_gen: u32, mode: SetMode) -> Status {
    debug_assert!(sh.slots.gen(slot) == slot_gen && sh.slots.state(slot) == Filling);
    sh.sketch.inc(h);
    let found = sh.idx.find(h, key);
    if !mode.allows(found.is_some()) { sh.slots.free(slot); return Status::NotStored }  // add/replace/NX/XX
    sh.slots.mark_live(slot);
    match found {
        Some(eh) => {                                     // overwrite: never in place
            let e = &mut sh.ent[eh];
            e.ver = e.ver.wrapping_add(1);
            if e.mem != NONE { sh.slots.retire(e.mem); sh.mem_used -= 1 } // zombie if pinned (sends / demote write)
            e.ssd = NONE;                                 // old SSD copy dead via back-map ver mismatch
            e.mem = slot; sh.mem_used += 1;
            if e.q() == None { e.set_q(M); sh.m_push(eh) } // was D-only or mid-demotion
        }
        None => {
            let eh = sh.ent.alloc();
            let gadmit = sh.ghost.take(fp(h));
            sh.ent[eh].init(key, slot, gadmit);           // q = M, freq = 0, hit = 0
            sh.m_push(eh); sh.idx.insert(h, eh); sh.mem_used += 1;
        }
    }
    if sh.mem_used > sh.cache_cap || sh.free_slots() < sh.hard_low { sh.make_room(FORCED, true) }
    Status::Stored
}

fn delete(sh: &mut Shard, h: u128, key: &Key) -> Status {
    let Some(eh) = sh.idx.remove(h, key) else { return Status::NotFound };
    let e = &mut sh.ent[eh];
    e.ver = e.ver.wrapping_add(1); e.set_dead();
    if e.mem != NONE { sh.slots.retire(e.mem); e.mem = NONE; sh.mem_used -= 1; sh.m_len -= 1 }
    e.ssd = NONE;                                         // SSD bytes become dead space
    sh.release_if_unref(eh);                              // stays as a tombstone while q != None / IO in flight
    Status::Deleted
}

// ---------- background (bounded steps per loop tick) ----------
// FORCED = 4 evictions; each forced eviction pops ≤ m_max_spins_forced + 1 entries.
fn make_room(sh: &mut Shard, mut evictions: u32, forced: bool) {
    loop {
        let pressure = sh.free_slots() < sh.hard_low || sh.mem_used > sh.cache_cap;
        let want = sh.mem_used - sh.pending_free + sh.low_wm > sh.cache_cap || sh.want_room;
        if evictions == 0 || !(want || pressure) { break }
        if !pressure && sh.demote_inflight >= W { break } // wait for write CQEs instead of dropping candidates
        evictions -= 1;
        step_m(sh, forced || pressure);
    }
    sh.want_room = !sh.reserve_waiters.is_empty() && sh.free_slots() <= sh.hard_low;
}

fn step_m(sh: &mut Shard, forced: bool) {
    let max_spins = if forced { sh.cfg.m_max_spins_forced } else { sh.cfg.m_max_spins };
    let eh = loop {
        let eh = sh.m_ring.pop();
        let e = &mut sh.ent[eh];
        if e.dead() { e.set_q(None); sh.release_if_unref(eh); continue }   // tombstones are free to skip
        if sh.cfg.m_clock && (e.freq() > 0 || e.writing()) && sh.m_spins < max_spins {
            if e.freq() > 0 { e.set_freq(e.freq() - 1) }
            sh.m_ring.push(eh); sh.m_spins += 1; continue;               // CLOCK second chance
        }
        break eh;
    };
    let e = &mut sh.ent[eh];
    sh.m_spins = 0; sh.m_len -= 1; e.set_q(None);
    if e.ssd != NONE {                                                    // clean copy: zero writes, frees now
        sh.slots.retire(e.mem); e.mem = NONE; sh.mem_used -= 1; e.set_freq(0); return;
    }
    let worthy = !sh.cfg.admit_requires_hit || e.hit() || e.gadmit();   // proved reuse in DRAM, or ghost re-admit
    if worthy && !forced && !e.writing() && sh.demote_inflight < W
        && sh.budget.admit(sh.sketch.est(e.h()), e.gadmit()) && let Some((dst, lap)) = sh.log.next_slot() {
        e.set_writing(true); sh.slots.pin(e.mem);                         // still Live & readable from DRAM
        sh.demote_inflight += 1; sh.pending_free += 1;
        sh.log.backmap[dst] = (eh, e.ver);
        sh.submit_write_fixed(e.mem, lba(dst), IoOp::Demote { eh, ver: e.ver, mem: e.mem, dst, lap });
    } else {
        sh.ghost.insert(fp_of(e)); sh.drop_entry(eh);                     // one-hit wonder, forced, or no tokens → G
    }
}

fn on_demote(sh: &mut Shard, op: Demote, res: i32) {
    sh.slots.unpin(op.mem);
    sh.region_write_done(op.dst);
    sh.demote_inflight -= 1; sh.pending_free -= 1;
    let e = &mut sh.ent[op.eh]; e.set_writing(false);
    if res == SLOT_BYTES && !e.dead() && e.ver == op.ver && e.q() == None && e.mem == op.mem {
        e.ssd = op.dst; e.set_lap(op.lap);
        if e.freq() > 0 {                                         // hit during the write: the DRAM copy never left
            e.set_freq(e.freq() - 1); e.set_q(M); sh.m_push(op.eh); // stays in M as a clean copy; next eviction is free
        } else {
            e.set_freq(0); sh.slots.retire(e.mem); e.mem = NONE; sh.mem_used -= 1;   // now D only, for good
        }
    } else {
        if res != SLOT_BYTES { sh.log.backmap[op.dst] = INVALID; sh.stats.ssd_write_err += 1 }
        if res != SLOT_BYTES && !e.dead() && e.q() == None && e.ver == op.ver {
            sh.ghost.insert(fp_of(e)); sh.drop_entry(op.eh);      // failed write: drop
        }
    }
    sh.release_if_unref(op.eh);
}

// ---------- D eviction: reclaim region r (triggered K regions ahead of the global cursor) ----------
// Precondition: r is Sealed (an Open region is first closed: stop appends, inflight_writes == 0, seal).
fn reclaim_batch(sh: &mut Shard, r: u32, cursor: &mut u16) {     // ≤ 64 slots per tick
    for slot in region_slots(r).skip(*cursor as usize).take(64) {
        *cursor += 1;
        let (eh, ver) = sh.log.backmap[slot];
        if eh == INVALID { continue }
        let e = &mut sh.ent[eh];
        if e.dead() || e.ver != ver || e.ssd != slot { continue }  // stale
        e.ssd = NONE;                                              // SYNCHRONOUS: no SSD pointer into r survives this visit
        if e.mem != NONE { continue }                              // clean DRAM copy → now dirty in M
        if sh.cfg.d_rewrite_hits > 0 && sh.rewrite_ok(e) {         // optional, off by default
            sh.queue_rewrite(eh, ver, slot, e.lap());              // staging read → append at log head; never DRAM
            continue;                                              // region stays Draining until the read completes
        }
        if sh.cfg.ghost_d_evictees { sh.ghost.insert(fp_of(e)) }
        sh.drop_entry(eh);                                         // idx remove; waiters of an in-flight read still served
    }
    if *cursor as usize == SLOTS_PER_REGION {
        sh.region_set(r, if sh.region(r).inflight_reads == 0 && sh.region(r).inflight_writes == 0 { Clean } else { Draining });
    }
}
```

Notes:
- **`m_push` on a full ring** first runs one `step_m`. Ring capacity is derived from V (§3.5) and exceeds live entries plus expected tombstones, so this happens only under heavy DEL churn.
- **Forced eviction** runs in `commit` when `mem_used > cache_cap` or `free_slots() < hard_low`. Forced steps choose only victims that free memory at once: clean M objects, and M drops to G with no write. Each forced eviction is O(1): at most `m_max_spins_forced + 1` ring pops. A victim that is pinned becomes a zombie and does not free at once. The pin quota bounds zombies, and H covers them (§5.1).
- **Grants.** The tick serves `reserve_waiters` (FIFO) and refills stashes (`Grant`) only while `free_slots() > hard_low`. While waiters exist, `want_room` keeps `make_room` running until a slot actually frees.
- **SSD reads never touch the cache pool.** A burst of D hits cannot evict M objects or delay SET grants. It can only fill the staging pool, and then reads wait in the IoOp FIFO.
- **Write sources.** The M→D demotion is the only SSD write source, plus the optional rewrite. Both draw from the same token bucket, so the wear budget is one choke point.

### 4.5 SSD admission and write-rate control (wear)

1. **Structural filters, free:**
   - Only M-evictees with `hit || gadmit` are candidates. One-hit wonders never reach flash.
   - Clean M-evictees cost 0 writes. Objects that get hits during their demotion write stay in M as clean copies.
2. **Per-shard token bucket:**
   - `refill = host_rate / N` B/s, capped at 2 s of burst. Each demotion costs `S + S·F/region_bytes` (slot plus footer share). The burst is not a concurrency limit: `demote_inflight < W` is enforced separately in `step_m`.
   - Every 10 s the control thread rebalances weights by per-shard demand (published `AtomicU32` weights). The global total stays fixed. The open-region age bound (§3.4) protects the global FIFO from unequal fill rates.
3. **Feedback threshold θ (blocked count-min sketch, 4-bit, halved every 10×(\|M\|+\|D\|) increments):**
   - Admit only if `sketch(key) ≥ θ`. A `gadmit` candidate is checked against `θ − 1`: a ghost hit is already a second request.
   - θ rises when the bucket ran dry in the last interval and falls when tokens overflowed. This uses the scarce budget on the most-requested candidates, not on the earliest ones.
4. **Wear-rate controller (sets `host_rate`).** The budget is set from measured wear, not from rated host bytes:
   - Initial value, before measurements exist: `host_rate = rated_dwpd × capacity / 86,400 × safety × seq_endurance_factor` (factor 1.0 by default; set per drive model in config when a sequential-endurance rating is known).
   - Every 60 s the control thread reads the NVMe **Percentage Used** and the **NAND/physical bytes written** counter (OCP SMART log C0h "Physical Media Units Written", or the vendor log), together with host "Data Units Written".
   - It controls the rate so that Percentage Used reaches `100% × safety` at `service_life_days`: `nand_rate = remaining_wear_nand_bytes / remaining_life`, with `remaining_wear_nand_bytes` from NAND bytes written per percent used. `host_rate = nand_rate / measured_DLWA`. The DLWA division happens **once**, against a NAND-byte budget. It is never applied on top of a rated host-write figure, which already contains the JEDEC workload's write amplification.
   - The rate changes slowly (at most ±10% per hour) and never above a configured hard cap.
   - **Warranty note:** if the vendor warranty is TBW-based (host bytes), not Percentage-Used-based, then the TBW limit is a separate business constraint. A config cap `max_host_bytes_per_day` enforces it, and it may bind before wear does (Q3).

### 4.6 SSD hits (no promotion)

- A D hit reads the slot into a staging buffer, sends it, and returns the buffer to the staging pool at the last unpin. The object stays in D only.
- Coalescing still applies: concurrent GETs for one D object share one read and one staging buffer.
- The optional `d_rewrite_hits` path is the only way a hot D object survives its region's reclaim without a client miss. It is SSD→SSD through a staging buffer and is token-gated.
- The send path for staging buffers, and why it is not `splice`, is in §6.4.

### 4.7 Literature comparison and why S3-FIFO

| Design | Verdict for this system |
|---|---|
| **S3-FIFO** (SOSP'23) | **Chosen, in the paper's flash configuration:** the probation queue is DRAM, the main queue is flash. No queue work on hits, so hit-path cost is a byte store and owner work stays tiny. Ring buffers, no CAS. The DRAM tier is ≈ 5% of the logical cache (paper S: 10%). Our deviations: CLOCK instead of FIFO in DRAM (keeps hot objects off the SSD read path; `m_clock = false` gives the paper's FIFO), and admission needs a hit **or** a ghost hit, plus a wear token. |
| **SIEVE** (NSDI'24) | Its lazy promotion is what our CLOCK M does. It needs middle removal (a linked list); a ring does the same work for us. |
| **W-TinyLFU** (ToS 2017) | Its frequency-based admission filter is a real competitor at the M→D boundary: phase 0 measures **TinyLFU admission** as a baseline. **We already borrow its count-min sketch** as the SSD admission threshold under budget pressure. |
| ARC, LIRS, CLOCK-Pro, 2Q | They need LRU updates on hits or complex stacks. S3-FIFO matches or beats them in the paper's evaluation. The ARC B2 idea (ghosting main-queue evictees) motivates `ghost_d_evictees`. |
| **CacheLib Navy BlockCache** (OSDI'20) | **Our D tier is its design:** region log, FIFO regions, write-budget admission (DynamicRandomAP), clean-region pool. Navy's hits-based reinsertion is our optional `d_rewrite_hits`. We drop BigHash, which is for small objects. |
| **Flashield** (NSDI'19) | Same principle as our admission rule: an object must prove reuse ("flashiness") in DRAM before it is written to flash. Flashield uses an SVM; we use the hit bit, the ghost and the sketch. |
| **Kangaroo / FairyWREN** (SOSP'21, OSDI'24) | Built for objects under 1 KB (per-object DRAM cost, set-associative pages). Not applicable to 20–100 KB objects. The lessons we keep: ALWA × DLWA multiply, and eviction should equal erase (region FIFO aligned to erase or reclaim units). |
| Baleen, CacheSack | They confirm the framing: maximize hit value under a flash write budget. ML admission can sit behind the `admit()` trait later. |
| LRB, GL-Cache | Inference on the request path conflicts with no-alloc and tail goals. GL-Cache-style region selection is future work, and only with FDP (out-of-order reclaim breaks DLWA ≈ 1). |
| RIPQ | Optional phase 6, only if `d_rewrite_hits` proves useful: two write heads (new admits vs. rewritten-hot). |

---

## 5. In-flight operation safety

### 5.1 Mechanisms

1. **Slot pins (owner-local `u16`).**
   - Taken by: the owner for each `Hit` reply (local or remote send, on a cache slot or a staging buffer), and each demotion write.
   - Released by: the owner processing `Unpin` (sent by A after the send CQE that covers the value, or after a spill copy), the write CQE, or the waiter's unpin.
   - Remote threads never touch `pins`.
2. **Logical eviction is immediate; physical free is deferred.** `retire(slot)`:
   - If `pins == 0`, the slot goes to the free list.
   - Otherwise it becomes `Zombie`, and the last unpin frees it.
   - The policy never skips a pinned victim. A hot object being sent has `freq > 0` anyway.
3. **Content version `ver` and lap tag per entry.** Every IO completion re-validates `(ver, ssd/mem location, dead, q)` before installing anything. A late completion can never install a stale location. SSD reads also check the region lap tag before issue and at completion (§3.3).
4. **Region pins and synchronous reclaim.**
   - `inflight_reads` (counted from queue time) and `inflight_writes` per region are owner-exclusive. Reclaim evicts logically at once, then moves the region to Draining. The region goes to Clean, and becomes allocatable, only when both counters are 0.
   - **When reclaim visits a live slot, it sets `e.ssd = NONE` at once**, whatever it decides next. The entry is dropped to G (or, with the optional `d_rewrite_hits`, queued for an SSD→SSD rewrite that appends a new location or drops it). No entry ever points into a region after reclaim visited it.
   - An Open region is closed (no appends, `inflight_writes == 0`, sealed) before reclaim. Open-region age is bounded (§3.4).
5. **Slot accounting (why the request path never fails on allocation).** Allocation is **fallible, with admission control**; it is not proven infallible. Slots outside `mem_used` and outside the free list are bounded by quota:

   | Holder | Bound per shard (as owner) | Example (N = 16) |
   |---|---|---|
   | Zombies and retired staging held by pins | N·P (pin quota) | 1,024 |
   | Filling slots (bodies in flight + stashes) | N·F (fill quota) | 128 |
   | Retired slots pinned by demotion writes | W (`demote_inflight < W` enforced) | 64 |

   `H = N·P + N·F + W` = 1,216 cache slots per shard. SSD reads use the separate staging pool, `QD + N·P` = 1,152 buffers per shard: at most QD reads in flight, plus buffers held by sends, which the pin quota bounds. On top of this:
   - **Reserve/Grant** is granted only while `free_slots() > hard_low`. Otherwise it waits in a fixed owner-side list (≤ N·F), and `make_room` runs until a slot actually frees.
   - **SSD reads** wait in the IoOp FIFO when no staging buffer is free. They never take cache slots.
   - `mem_used` may exceed `cache_cap` briefly (a commit during a write-latency window). Forced eviction then frees only immediately-freeing victims, and `pending_free` keeps `make_room` from counting writes in flight as relief or from over-evicting.
   - The simulator, with delayed-CQE fault injection, asserts that free-list waits stay bounded and rare. Production counts them (`slot_waits`).
6. **Slow-client bound.**
   - A pin lives until the send CQE that covers the value. With kTLS, `sendmsg` copies and encrypts synchronously into socket memory. Sends do not use `MSG_WAITALL`, so the CQE arrives as soon as the socket accepts any bytes, and a short count reports exact progress.
   - **Pin quotas:** ≤ p_conn = 8 pins per connection per owner and ≤ P = 64 per (A,B) pair. Op credits are returned when the reply arrives, so slow sends never hold credits.
   - **Pin-stall spill:** if a connection's send makes no progress for `pin_stall_ms` (default 100 ms), A cancels the send. After the CQE (`-ECANCELED` or a short count), A copies the unsent remainder of each pinned value into the worker's preallocated **spill pool** (32 × S per worker), sends `Unpin`, and continues from the spill copies. If the spill pool is empty, A closes the connection. Other clients never depend on the 10 s deadline.
   - **Body-progress deadline:** if a SET body does not complete within `body_timeout_ms` (default 2 s), A cancels the body RECV, waits for its CQE, sends `Abort{slot, slot_gen}` and closes the connection.
   - `TCP_NOTSENT_LOWAT` (128 KiB) and a per-connection send deadline (10 s, for idle-but-open sockets) remain as a last resort: `ASYNC_CANCEL` the send, `shutdown(SHUT_RDWR)`, unpin at the CQE, and close.
   - A per-connection cap on in-flight responses (64) and on pinned bytes (4 MiB) also applies.
7. **Connection generation.** `user_data` carries `conn_gen`. CQEs and replies for a dead connection are recognized: a stale `Hit` is unpinned at once. A stale `Reserved` goes into A's stash for B if there is room, else A sends `Abort{slot, slot_gen}` at once.
8. **Abort ordering rule.** `Abort` is sent only **after the CQE of the body RECV into that slot has been reaped** (including `-ECANCELED` or a short count). `ASYNC_CANCEL` is asynchronous, and a RECV that is already running can still write bytes. `Commit` and `Abort` carry `slot_gen`, and the owner checks it as it does for `Unpin`.

### 5.2 Race table

| # | Situation | Outcome |
|---|---|---|
| 1 | M eviction selects an object whose send is in flight | Index and policy state change now. The slot becomes a Zombie and is freed at the last `Unpin`. The client gets intact bytes. |
| 2 | SET overwrites a key with sends in flight | The new value is received into a **new** slot. On Commit the old slot is retired (Zombie). Old readers finish with the old bytes; there is no tearing. |
| 3 | DEL with sends in flight | Same as 2. The entry becomes a tombstone until its ring element is popped. |
| 4 | GET during a demotion write (M→D) | The entry still has `mem`, so it is served from DRAM. The write pin and the send pin coexist. The hit raises `freq`, so on completion the object stays in M as a clean copy. The DRAM copy never left, so this is not a D→DRAM move. |
| 5 | SET during a demotion write | `ver++`, the old slot is retired (the write pin keeps it). The entry gets a new `mem` and goes back into M. The write CQE sees the `ver` mismatch and installs nothing. The SSD slot is dead through the back-map `ver`. |
| 6 | DEL during a demotion write | The entry becomes `dead`. The CQE installs nothing. The handle is freed after the CQE (`writing` bit). |
| 7 | Second GET while an SSD read is in flight | It joins the waiter list. One read serves everyone; each waiter takes a pin on the staging buffer. |
| 8 | SET during an SSD read | Waiters, all of whose requests arrived before the SET, get the old bytes from the staging buffer. New GETs hit the new DRAM slot. |
| 9 | DEL during an SSD read | Waiters get the old bytes (linearized before the DEL). The entry is freed after the CQE (`reading` bit). |
| 10 | Region reclaim while a GET read targets it | Reclaim sets `e.ssd = NONE` synchronously and drops the entry to G (later GETs miss). The in-flight waiters are still served from the staging buffer. The region stays Draining until `inflight_reads == 0` (counted from queue time) and is never reallocated before that. A failed read drops the entry. The lap tag turns any remaining mismatch into a miss. With `d_rewrite_hits` on, the entry is instead queued for a rewrite, which shares the GET's read if one is in flight. |
| 11 | Region chosen for reclaim is still Open or has a write in flight | Open-region age is bounded (sealed after `open_max_age` or a lag of R/4 behind the cursor), so this should not occur. If it does, the owner closes the region first (stop appends, wait for `inflight_writes == 0`, seal), then reclaims. A region that is not Clean when the cursor reaches it is retried with the same seq, never skipped. |
| 12 | Two connections SET the same key at once | Both bodies go into separate Filling slots. B applies Commits in arrival order, and the last commit wins. The loser's slot is retired normally. |
| 13 | Connection dies mid-body | A cancels the body RECV and waits for its CQE. Only then does it send `Abort{slot, slot_gen}`. B frees the Filling slot; A returns the fill-quota unit. |
| 14 | A `Hit` arrives at A after the connection closed | A sends `Unpin` at once. |
| 15 | Stale or duplicated `Unpin`/`Commit`/`Abort` (a bug) | `slot_gen` mismatch triggers a debug panic and a release-build counter. It is never applied. |
| 16 | SSD write error | The back-map slot is invalidated and the object is dropped to G. Read error: waiters get a server error, the entry is dropped, and a counter increments. |
| 17 | A slow client holds a staging buffer | The buffer is pinned like a cache slot. The pin-stall spill (§5.1(6)) applies. The pin quota bounds held buffers, and the staging pool is sized for it (`QD + N·P`). |
| 18 | `Reserved` arrives after the connection closed | Put the slot in A's stash for B if there is room, else send `Abort{slot, slot_gen}` at once. The credit is returned at receipt. |
| 19 | Client stops reading with pinned values | After `pin_stall_ms`, cancel the send, copy the unsent remainder into the spill pool, `Unpin`. Close if the spill pool is empty. |
| 20 | Control record (alert, KeyUpdate) arrives mid-body | kTLS returns the bytes so far, then `-EIO`. The body sub-state keeps `filled`, handles the record (§6.2), then re-arms the body RECV at `slot + filled`. `-EKEYEXPIRED` after a KeyUpdate waits for the new RX key in the same way. |
| 21 | Slot pool near empty during a SET burst | Reserves wait in the owner's waiter list (the connection parks; TCP pushes back). Forced eviction frees immediately-freeable victims until a grant is possible. No panic, no allocation. |

**Visibility.** Slot bytes are written by kernel recv on A (SET) or by DMA observed through B's CQE (SSD). They are published by an SPSC push (Release) and consumed by a pop (Acquire) before any other thread issues a send that reads them. That gives a transitive happens-before chain: A's recv CQE → `Commit` (Release) → B → `Hit` (Release) → C's sendmsg.

---

## 6. IO path

### 6.1 Ring setup (per worker)

```rust
let ring = IoUring::builder()
    .setup_single_issuer()          // 6.0
    .setup_defer_taskrun()          // 6.1; task_work only in our enter → no IPIs, deterministic batching
    .setup_taskrun_flag()
    .setup_no_sqarray()             // 6.6 (skipped if probe fails)
    .setup_cqsize(16384)
    .build(4096)?;
sub.register_ring_fd()?;
sub.register_files_sparse(max_conns_per_worker)?;
sub.register_buffers(&arena_1gib_chunks)?;     // or REGISTER_CLONE_BUFFERS from worker 0 on 6.12+
sub.register_buffers_update(..footer + control buffers + spill pool..)?;
register_pbuf_ring(bgid = 0, 2048 entries × 16 KiB)?;   // own mmap'd BufRingEntry ring
sub.register_iowq_max_workers(&mut [4, 4])?;   // cap io-wq punts
```

- **No SQPOLL.** It cannot be combined with DEFER_TASKRUN and it burns a core. Sends therefore run inline in `io_uring_enter`, which is why sends are submitted in chunks (§2.5).
- **No IOPOLL in v1.** NVMe completions use interrupts on the same ring. Phase 6 adds a second per-worker IOPOLL ring (`HYBRID_IOPOLL` on 6.13+) if p99.99 measurements justify `nvme.poll_queues`.
- **SSD queue depth:** ≤ 128 in flight per shard (plus the footer write). Excess reads queue in a shard-local intrusive FIFO in the IoOp table. At startup, for each device, the server reads the per-hardware-queue depth (`/sys/block/<dev>/mq/*/nr_tags`) and checks that it is ≥ 129, and checks that the worker CPUs map to distinct hardware queues (`/sys/block/<dev>/mq/*/cpu_list`). It warns (it does not fail) when workers share a hardware queue, and then requires that queue's depth to cover the sum of their QDs.
- Startup probes every opcode and flag and logs the feature set. Required features fail fast if missing.

**`user_data` encoding (64 bits):**

```
kind:6 | conn ops:    conn_idx:20 | conn_gen:12 | aux:26   (resp ring idx / phase)
       | storage ops: op_idx:26   | op_gen:32              (IoOp table: eh, ver, buf, slot/dst, lap, rewrite)
```

### 6.2 kTLS via rustls

- **Config:**
  - `ServerConfig` with TLS 1.3 only, aws-lc-rs provider, suites AES-128-GCM > AES-256-GCM > ChaCha20-Poly1305 (ChaCha first on CPUs without AES-NI).
  - `enable_secret_extraction = true`, `send_tls13_tickets = 0`, no 0-RTT. ECDSA P-256 or Ed25519 certs.
- **Handshake (control thread):**
  - Use `UnbufferedServerConnection` with fixed buffers. Socket reads are **record-exact**: `RECV(5, MSG_WAITALL)` for the header, then `RECV(len, MSG_WAITALL)`.
  - We therefore never read past the client Finished. Pipelined application data stays in the kernel queue for kTLS RX at `rec_seq = 0`, so there are no leftover-plaintext handoffs.
  - Drive the connection to `WriteTraffic`, then `dangerous_into_kernel_connection()` → `(ExtractedSecrets, KernelConnection)`.
- **Install:**
  - `setsockopt(TCP_ULP, "tls")`, then `TLS_TX` and `TLS_RX` with `tls12_crypto_info_*`, `version = 0x0304`, and `rec_seq` = big-endian seq.
  - For GCM: salt = `iv[0..4]`, iv = `iv[4..12]`. For ChaCha: iv = 12 bytes.
  - **`TLS_RX_EXPECT_NO_PAD` is on by default** (6.0+). Without it, TLS 1.3 RX cannot decrypt straight into the slot, and SET bodies are decrypted and then copied. If a peer does pad, the kernel detects it, falls back to the copy path for that record, and counts it. A config flag turns the option off for peers that pad. Kernel crypto must be AES-NI/VAES-backed. WSL2 is functional-only (162 MB/s measured).
- **Control records (worker), a sub-state reachable from both Header and Body phases:**
  - A `RECV` returning `-EIO` means a non-data record is pending. In Body phase, the bytes received before it were already returned and added to `filled`. Post one `RECVMSG` with a per-connection preallocated `msghdr`, a 256 B buffer and `CMSG_SPACE(1)`.
  - **Type 21 (alert):** close_notify or fatal → send close_notify (`SENDMSG` with a `TLS_SET_RECORD_TYPE=21` cmsg), then close. In Body phase the close follows the Abort rule (§5.1(8)).
  - **Type 22 / KeyUpdate (24):** the RX side is paused (on ≥6.14, every RECV returns `-EKEYEXPIRED` until `TLS_RX` is reinstalled; `-EKEYEXPIRED` enters this same sub-state).
    1. Move the connection to `RxRekey`. Push `RekeyReq { conn, dir: Rx, tls: Box<TlsState> }` to the control thread on the return SPSC. **Key derivation runs on the control thread**, because rustls's TLS 1.3 key schedule heap-allocates (`Box<dyn HkdfExpander>`). The control thread replies with `RekeyDone { crypto_info }` on the handoff SPSC, with a doorbell.
    2. The worker calls `setsockopt(TLS_RX)` (a rare synchronous syscall on one connection).
    3. If `request_update == 1`, run the TX rekey sequence below.
    4. Re-arm recv: in Header phase, a normal header RECV; in Body phase, the body RECV at `slot + filled` for `V − filled` bytes.
  - **TX rekey sequence** (`TxRekey` state; used for a peer request and for the 90% confidentiality limit):
    1. **Drain:** stop gathering new data sends and wait until no data `SENDMSG` is in flight.
    2. Send the hand-encoded 5-byte KeyUpdate handshake message `[0x18, 0x00, 0x00, 0x01, update_requested]` (`update_requested = 0` when answering a peer) as one `SENDMSG` with a `TLS_SET_RECORD_TYPE=22` cmsg. It is the last record under the old key. rustls does not build these bytes for us.
    3. Reap its CQE.
    4. `setsockopt(TLS_TX)` with the new TX key (derived on the control thread, as above).
    5. Resume data sends.
  - Below 6.14 (no kTLS rekey), close the connection.
- **AES-GCM confidentiality limit:**
  - Count `records += ceil(bytes/16384) + 1` per send.
  - A 64 KiB GET is 5 records, so the 2²⁴-record limit allows about 3.3M GETs per connection.
  - At 90%: on 6.14+, run the TX rekey sequence. Otherwise flush and close (HTTP adds `Connection: close`).
- **Zero-copy:** `SEND_ZC` and `MSG_ZEROCOPY` on kTLS return `EOPNOTSUPP` (flag checks in mainline `tls_sw_sendmsg` and `tls_device_sendmsg`). The kTLS copy is the encryption pass itself. §6.4.1 compares this with `splice` for SSD hits.
- **Which TX path runs is measured, not assumed.** `tls_sw_sendmsg` uses its zero-copy-from-iov path (encrypt straight from the user pages, taking folio references) only for full records when the AEAD is synchronous. If the AES-GCM implementation is registered as async (some x86 SIMD wrappers), kTLS first copies the plaintext into kernel pages, which is one more pass over memory. The phase-4 benchmark identifies the path with perf/ftrace. The memory-bandwidth budget assumes the worse case: about 5× the payload (NIC DMA, plaintext read, copy write, ciphertext write, and read), not 3×. The folio-refcount issue (§2.6) applies only to the zero-copy path.
- **Optional NIC kTLS offload (`tls_device`, phase 6):** for NICs such as ConnectX-6 Dx/7. It removes the 3–6 GB/s/core crypto cost. It has no rekey support, so the GCM record limit means a graceful close. The CQE-time pin release must be checked again in this mode, because the NIC may read user pages after `sendmsg` returns. Until that is verified, it copies.

### 6.3 Recv

- **Header phase:** single-shot `RECV` with `IOSQE_BUFFER_SELECT` (bgid 0, 16 KiB buffers, so one full TLS record decrypts directly into it). Only connections with data consume buffers.
  - After parsing, any unconsumed tail is copied into the connection's `carry` buffer (24 KiB: it can hold a full 16 KiB record tail plus a partial 8 KiB header), and **the provided buffer is returned immediately, in all cases**. This includes the transition to Body: the body prefix waits in `carry`, so a connection parked on a credit, quota or `Reserved` never holds a provided buffer.
  - `-ENOBUFS` means refill and re-arm, and a counter increments. It does not happen in a healthy configuration.
- **Body phase:**
  1. Get a Filling slot for owner B: from A's stash for B (no hop), or by `Reserve` (one hop; the connection waits with recv not armed).
  2. Copy the body prefix from `carry` into the slot (≤ 16 KiB).
  3. Post `RECV(slot_addr + filled, V − filled, MSG_WAITALL)` with no buffer select. kTLS decrypts straight into the slot (with `EXPECT_NO_PAD`). Loop on short reads. `-EIO` and `-EKEYEXPIRED` enter the control-record sub-state (§6.2) and keep `filled`.
  4. The body-progress deadline applies (§5.1(6)).
  5. Then return to the header phase and `finish_body` (trailer or remaining RESP arguments).
- Phase 6: multishot recv with `IOU_PBUF_RING_INC` (6.12+), with cancel-and-drain on body entry.

### 6.4 Send

- Each connection has at most one send in flight. `try_flush` gathers the ready prefix of the response ring into `iov[196]` (3 per entry × 64 entries, + 1 for a header span that wraps the FIFO `HdrArena`, rounded up), `[hdr span(s) | value slot (V bytes) | trailer]` per entry. It stops gathering when fewer than 4 iovecs are left. It issues one `SENDMSG(MSG_NOSIGNAL)` **without `MSG_WAITALL`**.
- Header and value travel in one call, so kTLS fills 16 KiB records and never emits a tiny header record.
- Byte budget per send: **256 KiB**. Sends are submitted in chunks of ≤ 128 KiB of total payload per `io_uring_enter`, with an owner pass between chunks (§2.5). Short sends advance `iov_cursor`; entries fully covered are released (Unpin batched).
- **Pin release:** at the send CQE that covers the value (TLS, or plaintext with plain SENDMSG), or after a spill copy (§5.1(6)). With optional plaintext `SENDMSG_ZC` (phase 6), release happens at the `IORING_CQE_F_NOTIF` CQE, and header arena spans are held until then.
- Socket options: `SO_SNDBUF` **512 KiB** (≈ per-connection BDP; 1 MiB for known long-RTT listeners), `TCP_NOTSENT_LOWAT` 128 KiB (writability), `TCP_NODELAY`, `TCP_USER_TIMEOUT` 30 s. Startup sets `net.ipv4.tcp_mem` explicitly from the memory left after the arena (§3.5). The control thread alerts on TCP memory-pressure events (`TcpMemoryPressures` in `/proc/net/netstat`), because global pressure throttles `sendmsg` on all sockets.

#### 6.4.1 Sending D hits: read + `SENDMSG`, not `splice`

The question is how to send a value that lives on the SSD through a kTLS socket with the fewest passes over memory. Three paths were checked against mainline source (`net/tls/tls_sw.c`, `net/tls/tls_device.c`, `fs/splice.c`, `io_uring/splice.c`):

| Path | CPU passes over the payload, software kTLS | With NIC kTLS offload | io_uring behaviour | Verdict |
|---|---|---|---|---|
| **A. `READ_FIXED` into a staging buffer, then `SENDMSG [hdr, staging, trailer]`** | **1** (the encryption). NVMe DMA fills the buffer. For full 16 KiB records with a synchronous AEAD, `tls_sw_sendmsg` takes references on the user pages (`sk_msg_zerocopy_from_iter`) and encrypts from them directly. | 1 copy (`tls_push_data` copies user data into its page frags; the NIC encrypts) | Both ops are native async: no io-wq, no extra threads | **Default** |
| **B. `SPLICE` block device (O_DIRECT) → pipe → `SPLICE` pipe → socket** | **1** (the encryption). `copy_splice_read` DIOs into freshly allocated kernel pages; kTLS takes the pipe pages as `MSG_SPLICE_PAGES` without a copy. **No gain over A.** | **0** with `TLS_TX_ZEROCOPY_RO`: pages go straight to the NIC, which encrypts | `IORING_OP_SPLICE` sets `REQ_F_FORCE_ASYNC`: **every splice runs on an io-wq kernel thread** as a blocking call | Rejected for software kTLS. Phase-6 option for NIC offload only, behind a benchmark. |
| **C. `READ` + `SEND_ZC` / `MSG_ZEROCOPY`** | n/a | n/a | Software and device kTLS reject `MSG_ZEROCOPY` (`-EOPNOTSUPP` from the flag check in `tls_sw_sendmsg` / `tls_device_sendmsg`) | Not available. Path A already gives what ZC would: no copy before encryption. |

So with software kTLS, kTLS already gives zero-copy on the D-hit path. The encryption pass reads the staging buffer once and writes ciphertext into socket memory. No extra copy can be removed, and splice only adds costs:
- **Tail latency.** Every D hit becomes a blocking call on an io-wq worker. The read is synchronous on that thread, which adds a context switch, and requests queue behind the `iowq_max_workers` cap. Path A uses the NVMe interrupt-driven async path.
- **Kernel allocation per request.** `copy_splice_read` allocates pages for every read. The pipe needs `F_SETPIPE_SZ ≥ S`, and every in-flight read needs its own pipe (2 fds).
- **No check before the send.** User space never sees the bytes, so the footer CRC (§3.4) cannot be checked before the value reaches the client. Path A checks it in `on_ssd_read`, and a mismatch is a miss, not corrupt data.
- **Ordering.** Header, value and trailer would be three linked ops through the pipe. Path A sends them in one `SENDMSG`, so kTLS fills 16 KiB records.

**Conditions for the single pass, checked in phase 4:**
- The AEAD must be synchronous. In mainline the TX `async_capable` flag becomes 1 only after the cipher returns `-EINPROGRESS`, and the x86 AES-GCM `aead_alg` is registered without `CRYPTO_ALG_ASYNC`. Older kernels wrapped AES-NI GCM in an async SIMD helper, which forces the copy path. The phase-4 benchmark confirms the path with ftrace on `sk_msg_zerocopy_from_iter` on the target kernel (Q4).
- Only full records (or `MSG_EOR`) use the zero-copy path. A gathered `[hdr, value, trailer]` send fills full records except the last one, which is ≤ 16 KiB and is copied.
- With the zero-copy path the pages are referenced only during the synchronous encryption, so releasing the staging pin at the send CQE stays correct (§5.1(1)).

**NIC offload (phase 6).** With `tls_device` and `TLS_TX_ZEROCOPY_RO`, path B is the only path with zero CPU passes. If the target NIC has kTLS offload, phase 6 benchmarks B against A at p99.9. The io-wq cost is then traded against one copy per byte. The `ValueSource` enum (`Cache(slot) | Staging(buf) | Splice(pipe)`) in the send gatherer keeps this change local to `io/send.rs` and `shard/ssd.rs`.

### 6.5 SSD IO

- `O_DIRECT` on the raw namespace or partition (never a filesystem). `READ_FIXED` into a staging buffer and `WRITE_FIXED` from a cache slot, with `(buf_index, offset)` derived from the buffer id (§3.2 mapping; the staging pool is a reserved range of the same arena). Length = S. LBA = region base + slot-in-region × S.
- **Footer:** at seal (normal or early), one `WRITE_FIXED` from a per-shard registered footer buffer, built incrementally as slots are written.
- **Superblock:** written only at format and at clean shutdown.
- **Discard:** whole namespace at format; unused tail after a geometry change; optionally the unwritten tail of an early-sealed region (6.12+ async block discard).
- Phase 6: `sqe->write_stream` (6.16+) for FDP. NVMe passthrough (`/dev/ngXnY`, `UringCmd80`) only if FDP is needed before 6.16.

### 6.6 Lifecycles (A = connection thread, B = owner; when A == B the hops are function calls)

**GET, memory hit**
1. A: recv CQE → `parse` → `Complete{Get}` → push a `Pending` response entry. Take an op credit and a pin-quota unit (pair and connection) for B, send `Lookup`.
2. B: index find → `freq++` → `pins[slot]++` → `Hit{slot, slot_gen}`.
3. A: return the op credit. `encode` header into the arena → entry Ready → `try_flush` → `SENDMSG [hdr, &arena[slot], trailer]`.
4. A: send CQE covers the value → `Unpin` to B (batched) → pin-quota unit returned, entry freed.

**Typical latency:** parse about 0.3 µs, hop (queueing behind B's current chunk) about 0.3–40 µs, owner about 0.5 µs, kTLS about 15 µs. Wire time dominates.

**GET, SSD hit**
1–2. As above, until B finds `mem == NONE`. B checks the lap tag, queues the read (`inflight_reads++`), allocates a staging slot when QD allows (from the staging reserve), submits `READ_FIXED`, and records the waiter.
3. B: read CQE (about 80–150 µs on TLC NVMe) → lap and footer-CRC check → `Hit{staging}` to all waiters (each pinned) → retire the buffer (it returns to the staging pool at the last `Unpin`). No promotion: the object stays in D only.
4. A: same as memory-hit steps 3–4.

**GET, miss**
1. B replies `Miss`. A returns the op credit and the pin-quota unit, encodes `EN` / `END` / `$-1` / `_` / `404`, and flushes in order.

There is no read-through. The client fills with SET. A ghost entry, if present, is consumed at that SET.

**SET**
1. A: `parse` → `Body{hdr}`. Validate `body_len == V`, else `Reject{discard_body}` and drain into a per-worker 64 KiB scratch buffer. Copy the body prefix into `carry`; return the provided buffer.
2. A: push a Pending response entry. Take a slot from the stash for B (common case, no hop). If the stash is empty, take an op credit and a fill-quota unit and send `Reserve`; B replies `Reserved{slot, slot_gen}` when a slot is free (it may wait in B's waiter list).
3. A: copy the prefix into the slot, post the body `RECV` into the slot.
4. A: body complete → `finish_body` → `Commit{slot, slot_gen, mode}`.
5. B: index insert or overwrite into M (§4.4), consuming a ghost entry if present (sets `gadmit`), bounded forced eviction → `Done{Stored|NotStored}`. If free slots allow, B also sends `Grant` to refill A's stash.
6. A: encode `HD`/`STORED`/`+OK`/`204` (or suppress for `noreply`/`q`) → flush.

Pipelined SETs on one connection therefore cost no owner round trip before each body, as long as the stash has slots. Only `Commit` crosses shards.

---

## 7. Protocol abstraction

### 7.1 Core vocabulary

```rust
pub type Key = [u8; 16];
#[derive(Copy, Clone)] pub enum KeyRepr { Raw16, Hex32, Uuid36 { upper: bool }, Base64 }
#[derive(Copy, Clone, Default)] pub struct Opaque { len: u8, bytes: [u8; 32] }   // meta `O`
#[derive(Copy, Clone, Default)] pub struct ReqFlags(u16);  // QUIET, NOREPLY, RETURN_KEY, HEAD_ONLY, CLOSE_AFTER...
pub enum SetMode { Set, Add, Replace }                     // memcache add/replace, RESP NX/XX

pub enum Request<'a> {
    Get      { key: Key, ctx: ReqCtx },
    GetMulti { keys: KeyIter<'a>, ctx: ReqCtx },           // resumable cursor over the recv buffer
    Delete   { key: Key, ctx: ReqCtx },
    DeleteMulti { keys: KeyIter<'a>, ctx: ReqCtx },        // RESP DEL k1 k2 → one aggregated `:n`
    Noop     { ctx: ReqCtx },                               // meta mn, RESP PING
    Control  (Control<'a>),                                 // HELLO, SELECT 0, CLIENT, COMMAND, version, quit, stats
}
pub struct BodyHeader { pub mode: SetMode, pub key: Key, pub ctx: ReqCtx, pub body_len: u32, pub expect_continue: bool }

pub enum Parsed<'a> {
    Complete   { req: Request<'a>, consumed: usize },
    Body       { hdr: BodyHeader, consumed: usize },        // value is received into a slot by the conn machine
    Incomplete { min_more: usize },
    Reject     { err: ProtoErr, consumed: usize, discard_body: u32 },
    Fatal      { err: ProtoErr },                           // write error if possible, then close
}

pub enum Response { Hit { slot: u32 }, Miss, Stored, NotStored, Deleted, NotFound, Count(u32),
                    Noop, Pong, Ok, Continue, MultiEnd, Err(CoreErr) }

pub struct Frame { pub hdr: ArenaSpan, pub value: bool, pub trailer: &'static [u8], pub suppressed: bool, pub close_after: bool }

pub trait Protocol {
    type Conn: Default;                 // per-connection protocol state (RESP2/3, keep-alive, ...)
    const MAX_HEADER: usize;            // 512 memcache/RESP, 8192 HTTP
    fn parse<'a>(&self, st: &mut Self::Conn, buf: &'a [u8]) -> Parsed<'a>;
    fn finish_body(&self, st: &mut Self::Conn, hdr: &mut BodyHeader, buf: &[u8]) -> Result<usize, FinishErr>;
    fn encode(&self, st: &Self::Conn, ctx: &ReqCtx, r: &Response, v_len: u32, out: &mut HdrWriter<'_>) -> Result<Frame, ArenaFull>;
}

pub enum AnyProto { MemcText(MemcText), MemcMeta(MemcMeta), Resp(Resp), Http1(Http1) } // match dispatch, inlined
```

The core sees only `CoreOp { kind, key, h, mode }` and returns `Response`. The connection machine owns routing, credits, quotas, stashes, slots and ordering. **Adding a protocol** (memcached binary, a custom framed protocol, HTTP/2 later as a separate connection machine) means writing one `impl Protocol` plus one `AnyProto` arm and a listener config entry. Storage, eviction, IO and threading do not change.

### 7.2 Per-protocol rules

- **Keys:** accept 16 raw bytes, 32 hex characters or a 36-character UUID; anything else gets a protocol error. Odd keys are never hashed into 16 bytes (wrong-value risk). `KeyRepr` makes echoes byte-exact.
- **memcached text:** `get/gets k…` (multi → N entries + `END`), `set/add/replace`, `delete`, `version`, `quit`. `noreply` marks the entry suppressed.
  - `exptime` is accepted and ignored (counter `ttl_ignored`).
  - **Client `flags` must be 0** by default (`CLIENT_ERROR`). Silently dropping flags would corrupt clients that encode a serialization type there (open question Q2).
  - `cas` is unsupported.
- **memcached meta:** `mg/ms/md/mn` with `q`, `k`, `O`, `b`, `v`, `s`. `q` suppresses `EN`/`HD` but still takes a ring position. `mn` produces `MN`.
- **RESP2/3:** `GET`, `MGET`, `SET k v [NX|XX] [KEEPTTL]`, `DEL k…`, `EXISTS`, `PING`, `HELLO 2|3`, `SELECT 0`, `CLIENT SETNAME/SETINFO`, `COMMAND` (stub), `QUIT`, plus inline commands.
  - TTL options (`EX/PX/EXAT/PXAT`) are rejected. They are parsed after the body, so the slot is aborted (after the body RECV CQE) or returned to the stash.
  - A bulk length other than V is rejected. A length above `V + 64` is Fatal, which blocks memory-exhaustion attacks.
- **HTTP/1.1** (`httparse`, `[Header; 32]`): `GET/HEAD/PUT/DELETE /<key>`.
  - `Content-Length` must equal V. `Transfer-Encoding` gets 411, or 400 with CL+TE (anti-smuggling).
  - `Expect: 100-continue` produces an interim `Continue` entry before the body. Keep-alive rules follow 1.0 and 1.1.
  - Responses are always in request order (RFC 9112 §9.3.2).

### 7.3 Pipelining: out-of-order completion, in-order responses

```rust
struct Conn {
    fd: Fixed, raw_fd: RawFd, gen: u16, proto: AnyProtoConn,
    rx: RxState,                       // Header{carry_len, scan_from} | AwaitSlot | Body{slot, slot_gen, filled, hdr}
                                       // | Ctrl{resume: Header|Body} | RxRekey{resume} | Discard{left} | Parked
    tx: TxState,                       // Idle | Sending | Stalled{since} | TxRekey{step} | Spilled
    ring: RespRing<64>,                // head = oldest unsent, tail = next free
    arena: HdrArena<4096>,             // FIFO byte ring; spans freed in order
    carry: [u8; 24576], iov: [iovec; 196], msg: msghdr, ctrl: CtrlBuf,
    pins_by_owner: [u8; MAX_WORKERS],  // per-connection pin sub-quota (≤ p_conn)
    send_inflight: bool, recv_inflight: bool, tx_records: u64, tls: Option<Box<TlsState>>,
}
struct RespEntry { state: Pending | Ready | Sent, ctx: ReqCtx, frame: Frame, slot: u32, owner: u16, slot_gen: u32,
                   spill: u16 /* spill-pool index or NONE */, agg: u16 }
```

- Each parsed request pushes an entry at `tail` **before** dispatch. Replies (`Hit`/`Miss`/`Done`, from any shard, in any order) fill entries by `resp_idx`.
- `try_flush` sends only the contiguous Ready prefix from `head`. A slow SSD read on entry *i* delays only later entries on *the same connection*.
- `GetMulti`/`DeleteMulti` with K keys use K entries (or one aggregated entry with a counter `agg` for RESP `DEL`). The `KeyIter` cursor resumes when the ring has room, so huge multi-gets never allocate per key.
- **Parking:** ring full, arena low, no op credit / pin quota / fill quota for the target shard, or pinned bytes above the cap (4 MiB) → stop parsing and do not re-arm recv. A parked connection holds no provided buffer (its unparsed bytes are in `carry`). Un-park on progress, in FIFO order through an intrusive list.
- **Close:** set Closing, `gen++`, `ASYNC_CANCEL` the recv and send. Outstanding replies are drained and unpinned as they arrive. A Filling slot is aborted only after the body RECV CQE is reaped (§5.1(8)). Stashed slots stay with the worker for other connections. Then `close` via io_uring.

---

## 8. Zero-allocation discipline

Everything below is allocated once at startup, sized from config. Allocation and freeing on workers are forbidden. This is enforced in debug builds with a `#[global_allocator]` wrapper that panics on worker threads outside `fallback::with()`. Work that must allocate (rustls rekey key derivation) is moved to the control thread.

| Pool | Owner | Count (example, 64 KiB, N = 16) | Size each | Total | On exhaustion |
|---|---|---|---|---|---|
| Value slot arena | per-shard partition | 3,145,728 | 64 KiB | 192 GiB | Owner-side wait: Reserve waiter list, read queue; forced eviction (§5.1(5)) |
| SlotMeta | shard | 3,145,728 | 16 B | 50 MB | — |
| Entry slab | shard | 64.95M | 32 B | 2.08 GB | Sized to max live + ring capacity + H; full means a bug (assert) |
| Index buckets + stash | shard | 8.78M + 64/shard | 64 B | 0.56 GB | Stash overflow evicts the M tail (never at 0.85 load) |
| M ring | shard | 262,144 | 4 B | 16 MiB | Push-on-full runs one tail step |
| Staging pool | shard | 1,152 × S | S | 1.125 GiB | Reserved range of the arena; SSD reads only |
| Ghost table | shard | 74.2M | 8 B | 0.59 GB | Overwrite on collision (by design) |
| Count-min sketch (blocked) | shard | 2²² | 4 bit | 2 MiB/shard, 32 MiB | — |
| SSD back-map | global array, owner-partitioned by region | 56.7M | 8 B | 0.45 GB | — |
| RegionMeta | global | 55,432 | 64 B | 3.5 MB | — |
| IoOp table | shard | 1,408 + 128 | 64 B | 1.5 MB | Quota-bounded; SSD QD overflow queues within it |
| Read-waiter nodes | shard | N·P = 1,024 | 16 B | 256 KiB | Pin-quota-bounded |
| Reserve waiter list | shard | N·F = 128 | 16 B | 32 KiB | Fill-quota-bounded |
| Cross-shard SPSC | per ordered pair | N² × 256 | 64 B | 4 MiB | Credit/quota-bounded (≤ C + F + ⌈P/7⌉) |
| Region-control SPSC | per ordered pair | N² × 64 | 64 B | 1 MiB | Sender retries next tick |
| Op credits / pin quota / fill quota | per (A,B) | C = 32 / P = 64 / F = 8 | — | — | Park the connection |
| Stash | per (A,B) | ≤ 4 Filling slots | — | counted in H | Fall back to `Reserve` |
| Send spill pool | worker | 32 | S | 32 MiB | Close the stalled connection |
| Connections | worker | 65,536 total | 32 KiB | 2 GiB | Control thread refuses at the global cap |
| Provided recv buffers | worker | 2048 | 16 KiB | 512 MiB | `-ENOBUFS` → re-arm after refill |
| Discard scratch | worker | 1 | 64 KiB | 1 MiB | Shared (contents ignored) |
| Footer buffers | shard | 2 | 64 KiB | 2 MiB | — |
| Handoff and return SPSC | worker | 1024 | 16 B | — | Control thread retries on the next tick |
| TlsState pool | control thread | max_conns | ~512 B | 32 MiB | Allocated on the control thread only |
| Histograms and counters | worker | fixed buckets | — | ~1 MiB/worker | — |
| **FallbackPool** (the only exception) | worker | ≤ 64 lazily allocated | power of two, ≤ 1 MiB | ≤ 64 MiB/worker | Above the cap: `Fatal(TooLarge)` and close |

**Large-request fallback.** Values cannot be large, because the body length must equal V. The fallback covers only:
- multi-key request lines longer than `carry` (memcache `get k1 … k500`, RESP `MGET`, `DEL` arrays)
- HTTP header blocks over 8 KiB

When `Incomplete{min_more}` arrives and `carry` is full:
1. Take a buffer from `FallbackPool`, allocating once if the pool is empty.
2. Grow by power of two up to 1 MiB.
3. Return it after parsing; it is kept for reuse.

Metric `fallback_events` should be about 0. A non-zero rate means `MAX_HEADER` is mis-sized.

---

## 9. Admin, control plane, startup and shutdown

### 9.1 Startup (sizing from config)

1. Parse config (TOML): `value_size`, `memory_bytes`, `hugepage` (2M default / 1G), `devices[]`, `region_bytes`, `host_op`, `workers`, `cpu_list`, `max_conns`, `listeners[] {addr, proto, tls}`, wear (`rated_dwpd`, `seq_endurance_factor`, `service_life_days`, `max_host_bytes_per_day`), `policy`, `credits` (C, P, p_conn, F, stash), `spin_us`, `pin_stall_ms`, `body_timeout_ms`, `open_max_age_s`.
2. Validate the kernel: probe opcodes and flags, `CONFIG_TLS`, the AES-NI kTLS path (setsockopt test on a socketpair), `RLIMIT_MEMLOCK`/`CAP_IPC_LOCK`, hugepage availability, `statx(STATX_DIOALIGN)` = 4096 on each device, per-hardware-queue depth and CPU-to-hctx mapping (§6.1), and the CPU latency setting.
3. Compute geometry (S, slots/region, R, H, cache caps, staging pool, ring sizes, entries, buckets, ghost, sketch) from V and log the full table from §3.5.
4. Allocate and pre-fault all arenas. Each worker first-touches its own partition. Open `/dev/cpu_dma_latency` (or set per-CPU `pm_qos_resume_latency_us`) for worker cores.
5. Superblock: missing or mismatched geometry → format: discard the namespace (or the changed tail), write the superblock, all regions Clean. A clean-shutdown flag with warm restart enabled → §9.4. Otherwise start cold.
6. Spawn workers (pin, build rings, register buffers, files and pbuf), then the control thread binds listeners and the admin port. Set `tcp_mem`.

### 9.2 Admin and stats

- **Admin listener:** separate port, HTTP/1.1 on the control thread; localhost or mTLS. Allocation is fine here.
  - `GET /stats` (JSON), `GET /metrics` (Prometheus), `GET /config`, `POST /config` (live knobs: wear targets, `safety`, `m_clock`, `admit_requires_hit`, `d_rewrite_*`, `theta` bounds, spin, stall timeouts), `POST /drain`, `POST /shutdown`.
  - Live knobs reach workers as `Config` control messages; workers apply them between ticks.
- **Counters:** each worker owns a `CachePadded` struct of `u64` counters (relaxed stores) and fixed-bucket latency histograms (log-linear, preallocated). The control thread reads them with relaxed loads.
- **Key metrics:**
  - hits by tier (M/D), ghost hits, misses, ghost-admitted demotions
  - demotions (dirty vs. clean, rescued-hot); M evictions without a hit (dropped to G); demote_inflight vs W; staging pool occupancy and read-queue waits
  - drops to G by reason (no tokens, below θ, forced)
  - rewrites (if enabled); region reclaims; Draining stalls; region_wait; early seals; lap mismatches (should be 0)
  - **host bytes written vs. budget**, **NAND bytes written**, **Percentage Used trajectory vs. target**, **measured DLWA**, **D-tier age** (time since the oldest region was written)
  - pins, zombies, headroom in use (vs. H), slot_waits, Reserve waiters, stash hit rate
  - parked connections by reason (credit, pin quota, fill quota), pin-stall spills, spill-pool exhaustion closes, body timeouts, fallback events
  - TLS records, rekeys, control records, `EXPECT_NO_PAD` violations, kTLS TX path (zero-copy vs. copy)
  - **owner response latency**, cross-shard hop latency, doorbell wakeups vs. spin hits
  - TCP memory-pressure events
  - p50/p99/p99.9/p99.99 per op × tier
- **Background control duties:** rebalance write-budget weights every 10 s, poll SMART/OCP logs and run the wear controller every 60 s, rekey key derivation, accept-rate limiting, idle-connection reaper.

### 9.3 Shutdown

1. Stop accepting and broadcast `Drain`.
2. Workers stop parsing new requests, finish in-flight ones, flush, send close_notify, and close. Stashed slots are returned with `Abort`.
3. Workers stop new demotions and wait for SSD IO to reach 0 (default timeout 10 s).
4. If warm restart is enabled: each shard seals its open region with a footer. A **live bitmap** (1 bit per SSD slot: 7 MB at 64 KiB, 23 MB at 20 KB) is written to a reserved metadata area. Then the superblock is written with `clean = 1`. Otherwise just exit.

### 9.4 Warm restart: recommendation

**Optional, phase 6, and only after a clean shutdown.**
- The memory tier is always lost.
- The D tier is rebuilt by reading the footers (55,432 × 64–104 KiB ≈ 3.6–5.8 GB, a few seconds), applying the live bitmap, and inserting entries with `freq = 0` and the region's lap tag, in region-seq order.
- **After a crash, start cold.** Overwrites and DELs of SSD-resident keys are not persisted. Footer replay after a crash could resurrect stale or deleted values, and persisting tombstones would add wear and complexity that an ephemeral cache does not justify.

---

## 10. Risks, open questions, implementation plan

### 10.1 Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Per-shard partitioning lowers hit ratio vs. a global S3-FIFO | Small expected loss (millions of objects per shard) | Measure in the simulator with N independent shards on real traces |
| Ghost sizing \|M\|+\|D\|, the hit-or-ghost admission rule, and no D→DRAM promotion are extrapolations from the paper | Policy quality, SSD read load | Simulator sweeps (`ghost`, `m_clock`, `m_probation_frac`, `admit_requires_hit`, `d_rewrite_hits`); TinyLFU-admission baseline; report h_D (SSD read bandwidth) |
| DLWA > 1 despite global FIFO (unequal shard fill rates, stale LBAs, device behavior) | Wear | Namespace discard at format, open-region age bound, 7% host OP, wear controller on NAND bytes, FDP in phase 6 |
| Wear budget set too low (rated host DWPD on a sequential workload) | Hit ratio | Wear-rate controller on Percentage Used / NAND bytes; per-drive sequential-endurance config |
| kTLS crypto CPU and memory bandwidth on target hardware | Throughput ceiling | Benchmark AES-GCM kTLS per core on bare metal 6.14+ early (phase 4), identify the TX path, budget 5× payload memory traffic. Optional `tls_device`. Not on WSL2. |
| Hugetlb folio refcount contention on kTLS zero-copy TX | Cross-core tail | 2 MiB pages by default; 1 GiB only after benchmark |
| Owner response latency coupled to the owner's send crypto | Cross-shard tail | Chunked submission with owner passes; owner-response histogram; split roles if the bound is missed |
| `MSG_RING` wakeup latency and deep C-states | Cross-shard tail | Fenced sleeping-flag protocol, default spin 30 µs, CPU latency QoS, measure hop p99.99 at production power settings |
| Slow or malicious clients holding pins or Filling slots | Cross-connection HOL, headroom | Credits released on reply; pin and fill quotas with per-connection sub-quotas; pin-stall spill (100 ms); body-progress deadline; send deadline + cancel + shutdown |
| Kernels without 6.14 rekey | Forced reconnects every ~3.3M GETs per connection | Graceful close at 90%; prefer ChaCha on such kernels if CPU allows |
| Hot key above one owner core (~1M owner ops/s) | Owner saturation | Very unlikely at 20–100 KB (the NIC saturates first). Future: owner-granted read leases. |
| SSD read bandwidth below NIC rate at high D-hit ratio | Throughput ceiling | Drives = ⌈190k × h_D / 100k⌉; capacity-planning input |
| Docker seccomp blocks io_uring | Deployment | Ship a seccomp profile |
| QLC drives with 64 KiB indirection units and 20 KB values | Read-modify-write | Pad S to the IU, or require TLC |

### 10.2 Open questions for the user

1. **Q1:** should non-UUID-sized keys be rejected? This design rejects them.
2. **Q2:** must memcached client `flags` round-trip? If yes, add 4 B to `SlotMeta`, the back-map entry (8 → 12 B, +227 MB at 64 KiB) and the footer.
3. **Q3:** target drive SKU, DWPD rating, sequential-endurance rating, FDP support, and **whether the warranty is TBW-based or Percentage-Used-based**. This sets the wear controller's targets, the TBW cap and the OP default.
4. **Q4:** target kernel. 6.14+ gives rekey; 6.16+ gives FDP write streams.
5. **Q5:** is `exptime` ignore-with-counter acceptable, or should non-zero TTLs be rejected?
6. **Q6:** is warm restart needed at all?
7. **Q7:** expected D-hit ratio and peak GET rate, to size the number of SSDs for read bandwidth.

### 10.3 Crate module layout

```
ssdcache/
  src/main.rs                 // config load, sizing, thread spawn
  src/config.rs  sizing.rs    // geometry math from V (unit-tested against both §3.5 columns)
  src/mem/arena.rs            // hugepage mmap, partitioning, registration chunks, slot→(chunk,off) mapping
  src/mem/slots.rs            // SlotMeta, pin/retire/zombie, fallible alloc, floors, accounting asserts
  src/index/{bucket.rs, entry.rs, cuckoo.rs}
  src/policy/{s3fifo.rs, ghost.rs, sketch.rs, budget.rs, wear.rs}   // pure, no IO: shared with simulator
  src/flash/{region.rs, log.rs, backmap.rs, superblock.rs, footer.rs, discard.rs}
  src/shard.rs                // owner ops: lookup/reserve/commit/delete, completions, reclaim, grants
  src/xshard/{spsc.rs, msg.rs, doorbell.rs, credits.rs, quotas.rs, stash.rs}
  src/uring/{ring.rs, userdata.rs, pbuf.rs, probe.rs}
  src/net/{conn.rs, resp_ring.rs, hdr_arena.rs, flush.rs, spill.rs, fallback.rs}
  src/tls/{acceptor.rs, ktls.rs (setsockopt, crypto_info, cmsg), rekey.rs (state machine), keyupdate.rs}
  src/proto/{mod.rs, memc_text.rs, memc_meta.rs, resp.rs, http1.rs, key.rs}
  src/control/{admin_http.rs, stats.rs, smart.rs, rebalance.rs, rekey_service.rs}
  src/worker.rs               // event loop
  sim/                        // trace-replay binary using src/policy + src/shard with a fake IO backend
  fuzz/                       // cargo-fuzz targets per protocol parser
```

**Crates:**
- `io-uring` 0.7.x
- `rustls` 0.23.x (≥ 0.23.27, `aws-lc-rs` provider) and `rustls-pki-types`
- `libc`, `memchr`, `httparse`
- `xxhash-rust` (xxh3)
- `crossbeam-utils` (`CachePadded` only)
- `core_affinity` or `libc::sched_setaffinity`
- `serde` + `toml`, `clap`
- IOP's `histogram`/`metriken` for metrics
- dev: `loom` (SPSC, doorbell with fences), `proptest`, `cargo-fuzz`

No Tokio, no async runtime, no `ktls` crate.

### 10.4 Phased plan

| Phase | Deliverable | Exit criteria |
|---|---|---|
| 0 | `policy` + `sim`: tiered S3-FIFO (DRAM M → SSD D + G) with write budget, fake SSD with delayed-CQE injection, trace replay (libCacheSim/Twitter/Meta CacheLib traces) | Chosen defaults for thresholds and ghost size. Compare against v1.1's 4-queue design with promotion, CLOCK vs FIFO M, and `d_rewrite_hits` on/off; TinyLFU-admission baseline. Slot-accounting asserts hold under delayed CQEs. Report miss ratio + SSD bytes written/request + h_D. |
| 1 | Single worker, plaintext, memory-only, memcached text + meta, io_uring loop, RespRing, provided buffers, body-into-slot | Pipelining tests, no allocations (allocator guard), p99 baseline |
| 2 | N shards + SPSC/credits/quotas/stash/doorbell + control-thread handoff. RESP and HTTP. Chunked send submission. | loom-verified SPSC and fenced doorbell. Owner response latency and hop p99.99 measured at production power settings. N = 8/16/32 compared. Fuzzed parsers. Slow-client tests (pin stall spill, body timeout, quota parking) show no cross-connection p99.99 impact. |
| 3 | SSD tier: regions, global FIFO with retry and age bound, demotion, owner reads into staging, coalescing, reclaim + Draining + lap tags, budget + sketch, wear controller, SMART/OCP | Race table (§5.2) covered by deterministic fault-injection tests (delayed CQEs), including "GET read in flight + reclaim" and "SET during a demotion write". DLWA measured over 72 h on the target drive after namespace discard. |
| 4 | rustls handshake + kTLS + control records (both phases) + rekey via control thread + record counting | TLS interop (openssl s_client, redis-cli --tls, curl), including KeyUpdate mid-body. kTLS throughput per core on bare metal; TX path identified; 1 GiB vs 2 MiB pages under many senders. |
| 5 | Hardening: slow-client reaper, admin plane, live config, drain and shutdown, seccomp profile, NUMA guidance | 24 h soak at 70% load. p99.99 SLO met. Zero fallback events. Zero lap mismatches. |
| 6 | Optimizations: IOPOLL ring, multishot + `PBUF_RING_INC`, plaintext `SENDMSG_ZC`, FDP write streams, `tls_device` offload, RIPQ dual write heads, warm restart | Each one behind a flag, kept only if it improves measured p99.99 or wear |

---

## 11. References

**Eviction and admission**
- S3-FIFO, SOSP'23 — https://www.pdl.cmu.edu/PDL-FTP/Storage/FIFOqueues-SOSP23.pdf · https://junchengyang.com/publication/sosp23-s3fifo.pdf
- S3-FIFO blog — https://blog.junchengyang.com/system/cache/2023/08/01/s3fifo
- libCacheSim S3FIFO.c — https://raw.githubusercontent.com/1a1a11a/libCacheSim/develop/libCacheSim/cache/eviction/S3FIFO.c
- S3-FIFO artifact — https://github.com/Thesys-lab/sosp23-s3fifo
- FIFO can be Better than LRU (HotOS'23) — https://dl.acm.org/doi/10.1145/3593856.3595887
- SIEVE (NSDI'24) — https://www.usenix.org/conference/nsdi24/presentation/zhang-yazhuo
- ARC (FAST'03) — https://www.usenix.org/conference/fast-03/arc-self-tuning-low-overhead-replacement-cache
- CLOCK-Pro (ATC'05) — https://www.usenix.org/legacy/event/usenix05/tech/general/jiang.html
- LIRS (SIGMETRICS'02) — https://dl.acm.org/doi/10.1145/511334.511340
- 2Q (VLDB'94) — https://www.vldb.org/conf/1994/P439.PDF
- TinyLFU — https://arxiv.org/abs/1512.00727
- LRB (NSDI'20) — https://www.usenix.org/conference/nsdi20/presentation/song
- GL-Cache (FAST'23) — https://www.usenix.org/conference/fast23/presentation/yang-juncheng
- Flashield (NSDI'19) — https://www.usenix.org/conference/nsdi19/presentation/eisenman
- Baleen (FAST'24) — https://www.usenix.org/conference/fast24/presentation/wong
- CacheSack (ATC'22) — https://www.usenix.org/conference/atc22/presentation/yang-tzu-wei
- RIPQ (FAST'15) — https://www.usenix.org/conference/fast15/technical-sessions/presentation/tang

**Flash**
- CacheLib (OSDI'20) — https://www.usenix.org/conference/osdi20/presentation/berg · slides https://www.pdl.cmu.edu/PDL-FTP/slides/2020/osdi20_slides_berg.pdf
- CacheLib Navy overview — https://cachelib.org/docs/Cache_Library_Architecture_Guide/navy_overview
- HybridCache config — https://cachelib.org/docs/Cache_Library_User_Guides/Configure_HybridCache/
- Kangaroo (SOSP'21) — https://dl.acm.org/doi/10.1145/3477132.3483568 · https://par.nsf.gov/servlets/purl/10301351 · https://engineering.fb.com/2021/10/26/core-data/kangaroo/
- FairyWREN (OSDI'24) — https://www.usenix.org/conference/osdi24/presentation/mcallister · https://usenix.org/system/files/osdi24-mcallister.pdf
- Nemo (arXiv 2026) — https://arxiv.org/html/2603.09605v1
- FDP for CacheLib (EuroSys'25) — https://arxiv.org/abs/2503.11665 · https://arxiv.org/html/2503.11665v1
- Segcache (NSDI'21) — https://www.usenix.org/conference/nsdi21/presentation/yang-juncheng · https://www.usenix.net/system/files/nsdi21-yang.pdf · https://blog.junchengyang.com/system/cache/2021/04/01/segcache
- fatcache — https://github.com/twitter/fatcache/blob/master/notes/performance.md
- Linux 6.16 write streams — https://www.phoronix.com/news/Linux-6.16-Block-IO_uring · https://patchwork.kernel.org/project/io-uring/cover/20241210194722.1905732-1-kbusch@meta.com/mbox · https://lists.infradead.org/pipermail/linux-nvme/2025-May/056053.html
- I/O Passthru (FAST'24) — https://usenix.org/conference/fast24/presentation/joshi · LPC2022 slides https://linuxplumbersconf.org/event/16/contributions/1382/attachments/1119/2151/LPC2022_uring-passthru.pdf

**io_uring and kTLS**
- Kernel TLS docs — https://docs.kernel.org/networking/tls.html
- tls_sw.c — https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/net/tls/tls_sw.c
- io_uring/net.c — https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/io_uring/net.c
- io_uring/msg_ring.c — https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/io_uring/msg_ring.c
- io_uring/rsrc.c — https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/io_uring/rsrc.c
- TLS 1.3 rekey commit — https://github.com/torvalds/linux/commit/47069594e67e
- io_uring uapi — https://github.com/torvalds/linux/blob/master/include/uapi/linux/io_uring.h
- rustls kernel module — https://docs.rs/rustls/latest/rustls/kernel/index.html · https://docs.rs/crate/rustls/0.23.27/source/src/conn/kernel.rs · https://docs.rs/rustls/latest/src/rustls/conn/kernel.rs.html
- UnbufferedServerConnection — https://docs.rs/rustls/0.23.40/rustls/server/struct.UnbufferedServerConnection.html
- ServerConnection — https://docs.rs/rustls/latest/rustls/server/struct.ServerConnection.html
- rustls/ktls — https://github.com/rustls/ktls · https://docs.rs/ktls/latest/ktls/
- ktls-core — https://docs.rs/ktls-core/latest/ktls_core/tls/struct.ExtractedSecrets.html · https://docs.rs/crate/ktls-core/latest/source/src/setup.rs
- tokio-rs/io-uring — https://github.com/tokio-rs/io-uring
- liburing networking wiki — https://github.com/axboe/liburing/wiki/io_uring-and-networking-in-2023
- zc send fail-on-unsupported — https://git.zx2c4.com/linux-dev/diff/?id=edf81438799ccead7122948446d7e44b083e788d · https://lkml.iu.edu/hypermail/linux/kernel/2210.3/00493.html
- kTLS flag whitelist — https://lkml.iu.edu/hypermail/linux/kernel/2008.0/04607.html
- LWN TLS offload / rekey — https://lwn.net/Articles/1073180/ · https://lwn.net/Articles/1055522 · zerocopy send https://lwn.net/Articles/900083
- Man pages — https://man7.org/linux/man-pages/man3/io_uring_setup_buf_ring.3.html · https://man7.org/linux/man-pages/man2/io_uring_register.2.html · https://man7.org/linux/man-pages/man3/io_uring_prep_send_zc.3.html · https://man7.org/linux/man-pages/man7/io_uring.7.html · https://man.archlinux.org/man/io_uring_setup_flags.7.en.txt
- Recv bundles — https://android-kvm.googlesource.com/linux/+/2f9c9515bdfde9e4df1f35782284074d3625ff8a
- DEFER_TASKRUN commit — https://lab.nexedi.cn/kirr/linux/-/commit/c0e0d6ba25f180ab76d3c18f8b360a119dffa634
- MSG_SEND_FD commit — https://android-kvm.googlesource.com/linux/+/e6130eba8a848a7a6ba6c534bd8f6d60749ae1a9
- NVMe passthru iopoll — https://lore.kernel.org/all/20220805171331.GD17011@test-zns/T/
- ringline — https://github.com/brayniac/ringline
- monoio https://github.com/bytedance/monoio · glommio https://github.com/DataDog/glommio · https://docs.rs/glommio · tokio-uring https://github.com/tokio-rs/tokio-uring · compio https://github.com/compio-rs/compio
- Docker seccomp — https://github.com/moby/moby/pull/46762 · https://docs.docker.com/engine/security/seccomp/

**Threading and systems**
- Seastar — https://seastar.io/shared-nothing/ · https://mohakchugh.is-a.dev/blog/thread-per-core-shared-nothing-predictable-microsecond-latency · https://qconsf.com/sf2018/sf2016/system/files/presentation-slides/avikivity_slides.pdf
- ScyllaDB memory — https://www.scylladb.com/product/architecture/memory-management
- Dragonfly — https://dragonflydb.io/blog/transactions-in-dragonfly · https://www.dragonflydb.io/blog/2024-new-year-new-number · https://github.com/dragonflydb/dragonfly/blob/main/docs/dashtable.md
- Garnet — https://github.com/Microsoft/Garnet · https://microsoft.github.io/garnet · https://microsoft.github.io/garnet/docs/dev/network · https://github.com/microsoft/garnet/pull/332
- FASTER — https://users.cs.utah.edu/~pandey/courses/cs6968/spring23/papers/faster.pdf · https://www.microsoft.com/en-us/research/blog/microsoft-unveils-faster-key-value-store-large-state-management/
- CacheLib talks — https://www.snia.org/sites/default/files/PM-Summit/2022/PMCS22-Byrne-CacheLib.pdf · https://cachelib.org/docs/Cache_Library_Architecture_Guide/overview_a_random_walk
- memcached — https://github.com/memcached/memcached/blob/c5530027c8ea28674358327ab8212ebaf014c848/thread.c · https://docs.memcached.org/features/flashstorage/ · https://docs.memcached.org/protocols/meta/ · https://github.com/memcached/memcached/pull/716
- Pelikan — https://www.github.com/pelikan-io/pelikan · https://github.com/pelikan-io/pelikan · https://qconlondon.com/london-2017/system/files/presentation-slides/qconlondon2017.pdf
- KeyDB — https://github.com/soloestoy/KeyDB
- MICA (NSDI'14) — https://www.usenix.org/conference/nsdi14/technical-sessions/presentation/lim
- Shinjuku (NSDI'19) — https://mast.stanford.edu/pubs/shinjuku_preemptive_scheduling_for_microsecond_scale_tail_latency/
- RackSched — https://arxiv.org/pdf/2010.05969
- The Tail at Scale (summary) — https://blog.acolyer.org/2015/01/page/2
- MemC3 (NSDI'13) — https://usenix.org/conference/nsdi13/technical-sessions/presentation/fan
- libcuckoo summary — https://blog.acolyer.org/2016/11/03/algorithmic-improvements-for-fast-concurrent-cuckoo-hashing/
- Kangaroo (Meta blog, core-infra) — https://engineering.fb.com/2021/10/26/core-infra/kangaroo/
- reuseport_bpf_cpu — https://code.woboq.org/linux/linux/tools/testing/selftests/net/reuseport_bpf_cpu.c.html
- RFC 9112 §9.3.2 — https://www.rfc-editor.org/rfc/rfc9112#section-9.3.2

---

## 12. Review log

| # | Lens / severity | Critique | Verdict | Reason (one line) |
|---|---|---|---|---|
| 1 | correctness / critical | Reinsert candidate keeps a stale `e.ssd`; overwritten slot served silently | **Accepted** | Reclaim now clears `e.ssd` synchronously; reinsert coalesces with GET reads and installs or drops; lap tag checked before issue and at completion; inflight_reads counted from queue time; new deterministic test (§4.4, §5.1(4), race #10). |
| 2 | correctness / critical | "alloc never fails" is false (H double-counted, make_room frees nothing, W unbounded) | **Accepted** | Allocation is now fallible with admission control (Reserve waiter list, read queue, staging floor), `pending_free`, an enforced `demote_inflight < W`, and O(1) forced eviction of only immediately-freeing victims (§4.4, §5.1(5)). |
| 3 | correctness / major | Open region lapped by the cursor; skipped seqs break the FIFO; no Reclaim channel | **Accepted** | Open-region age bound (10 min or R/4 lag), close-before-reclaim, pending-seq retry instead of skip, and a separate non-credit region-control SPSC (§3.4, §2.4). |
| 4 | correctness / major | Credits held through pins and slow bodies give cross-connection HOL and ENOBUFS | **Accepted** | Op credits return at reply; separate pin and fill quotas with per-connection sub-quotas; body-progress deadline; a 24 KiB `carry` means parked connections never hold provided buffers (§2.4, §5.1(6), §6.3). |
| 5 | correctness / major | Doorbell store→load reordering allows a lost wakeup | **Accepted** | Consumer uses `store(Relaxed); fence(SeqCst)` before scanning; both sides loom-modeled as written (§2.4). |
| 6 | correctness / major | Abort can race a live body RECV; stale `Reserved` leaks | **Accepted** | Abort only after the body RECV CQE is reaped; a stale `Reserved` goes to the stash or is Aborted at once; `slot_gen` added to Commit/Abort (§5.1(7–8), races #13/#18). |
| 7 | correctness / minor | Rekey derivation allocates on the worker; TX rekey order is unspecified | **Accepted** | Key derivation moved to the control thread; explicit TX-rekey state machine with a hand-encoded 5-byte KeyUpdate (§6.2). |
| 8 | correctness / minor | Control records and `-EKEYEXPIRED` are not handled in Body phase | **Accepted** | Control-record sub-state is reachable from Header and Body phases and resumes at `slot + filled` (§6.2, §6.3, race #20). |
| 9 | correctness / minor | 1 GiB hugetlb folio refcount is a cross-core shared write under kTLS zero-copy TX | **Accepted** | Default page size is now 2 MiB, 1 GiB only after the benchmark; documented as the one shared write on the send path (§2.6, §3.2). |
| 10 | correctness / minor | `iov[64]` too small; `buf_index` mapping wrong with skipped slots | **Accepted** | `iov[196]` with a stop-when-full rule; dense slot ids mapped via `slot / slots_per_chunk` for both registered and plain addressing (§6.4, §3.2). |
| 11 | correctness / minor | Async FilesUpdate before RECV is unordered; MSG_SEND_FD note outdated | **Accepted** | Use the synchronous `register_files_update` (or IO_LINK); rationale for SPSC restated without the outdated lock claim (§2.3). |
| 12 | correctness / minor | Global N×128 `nr_requests` rule mixes per-hctx limits | **Accepted** | Startup validates per-hctx `nr_tags` ≥ per-shard QD and the CPU-to-hctx mapping (§6.1, §9.1). |
| 13 | perf-wear / major | Hop latency is coupled to the owner's crypto-heavy tick | **Accepted** | Chunked send submission (≤ 128 KiB per enter) with owner passes in between, 256 KiB per-send budget, owner-response histogram, cost model rewritten (§2.4, §2.5, §6.4). |
| 14 | perf-wear / major | Hit credit held until Unpin; slow clients exhaust pair credits | **Accepted (merged with #4)** | Credit and pin separated; per-connection pin cap of 8 per owner; 100 ms pin-stall spill to a preallocated pool, or close; send no longer uses MSG_WAITALL so progress is exact (§5.1(6)). |
| 15 | perf-wear / major | Rated DWPD with a 1/DLWA scale double-counts write amplification | **Accepted** | Wear controller targets Percentage Used via NAND bytes, divides by DLWA once, uses rated DWPD only as the initial value, and has a separate TBW cap and per-drive sequential-endurance config (§4.5, Q3). |
| 16 | perf-wear / major | make_room over-evicts during writes; W unbounded; forced steps on dirty victims | **Accepted (merged with #2)** | `mem_used − pending_free` condition, explicit W limit, forced steps free immediately, forced steps after promotion, simulator asserts with delayed CQEs (§4.4). |
| 17 | perf-wear / major | H = N·C oversized; C far above BDP; N larger than needed | **Accepted** | C = 32, separate pin/fill quotas, H = 1,408/shard (1.375 GiB vs 8.25 GiB), example N = 16, with N = 8/16/32 benchmarked in phase 2 (§2.1, §3.5). |
| 18 | perf-wear / major | S is 0.5% of the logical cache, so the W-TinyLFU rejection argument is wrong | **Accepted** | S documented relative to M+D as ghost-driven second-miss admission; W-TinyLFU row corrected; phase-0 S sweep and TinyLFU-admission baseline (§4.1, §4.7, §10.4). |
| 19 | perf-wear / minor | Mostly-idle workers pay wakeups and C-state exits on hops | **Accepted** | Default `spin_us = 30`, CPU latency QoS or C6 off, hop p99.99 measured at production power settings (§2.4, §2.6, §9.1). |
| 20 | perf-wear / minor | Sketch size inconsistent; 4 LLC misses per increment | **Accepted** | Blocked CMS sized per shard (2²² × 4 bit = 2 MiB/shard, 32 MiB total), 1 line per increment (§3.5, §8). |
| 21 | perf-wear / minor | Sizing does not generalize to 20 KB (id bits, ring sizes, metadata) | **Accepted** | All sizes derived from V; 20 KB column added (28-bit ids, ~14 GiB metadata); tests at both ends of the range (§3.1, §3.5). |
| 22 | perf-wear / minor | Host OP is useless without discarding stale LBAs | **Accepted** | Whole-namespace discard at format and tail discard after a geometry change, checked through measured DLWA (§3.4, §9.1). |
| 23 | perf-wear / minor | SO_SNDBUF 4 MiB × 65k connections exceeds memory; global tcp_mem throttling | **Accepted** | SO_SNDBUF 512 KiB (BDP), NOTSENT_LOWAT for writability, explicit `tcp_mem`, alert on pressure events (§6.4). |
| 24 | perf-wear / minor | Hash bit fields overlap (80 bits taken from 64) | **Accepted** | Non-overlapping bit map documented; ghost fingerprint from `lo[63:32]`; cuckoo alternate bucket uses an involution that works for any bucket count (§2.2). |
| 25 | perf-wear / minor | kTLS may use the copy path; EXPECT_NO_PAD optional; NIC offload not considered | **Accepted** | Phase-4 path identification, 5× memory-bandwidth budget, EXPECT_NO_PAD on by default, optional `tls_device` mode with the pin-release check (§6.2, §10.4). |
| 26 | perf-wear / minor | Reserve hop serializes pipelined SETs | **Accepted** | Reserve-credit slot stash (2–4 per pair, counted in H) moved into v1/phase 2 (D16, §6.6). |
| 27 | perf-wear / minor | Objects hit during a demotion write are evicted from DRAM | **Accepted** | `on_demote` keeps a hot object in M as a clean copy, so its next demotion is free (§4.4, §4.2). |
| 28 | perf-wear / minor | Target rates inconsistent (600k vs 190k); SSD read ceiling ignored | **Accepted** | One target of 190k GET/s at 64 KiB; drive-count formula ⌈190k × h_D / 100k⌉; SSD read bandwidth listed as a planning input (§2.6, §3.5, Q7). |
| — | derived change | Pin-stall spill needs exact send progress | **Added** | Sends no longer use `MSG_WAITALL`, so a short count or cancellation reports exactly which value bytes are still referenced (D10, §6.4). |

No critique was rejected. Items #14 and #16 duplicate #4 and #2 and are handled by the same changes.

### 12.1 v1.2 changes (user feedback)

| Feedback | Change | Sections |
|---|---|---|
| The SSD queue is the main store; collapse the two memory queues? | **Yes.** S and M merged into one DRAM CLOCK queue M, which is the probation queue for D (the S3-FIFO paper's "S in DRAM, M on flash" configuration). Admission to D needs a DRAM hit or a ghost hit, plus a wear token. The admission window grows from ≈ 60 s to ≈ 10 min. | §1, D4, D5, §4.1–4.3 |
| Never move values from SSD to the memory queues | Promotion and D→M reinsertion removed. D hits are served from a separate staging pool that is never cached. D is a strict FIFO; evictees go to G. An optional SSD→SSD rewrite replaces reinsertion. v1.1 review items #1 and #27 still hold (synchronous `e.ssd` clear; hit-during-write stays in M, which is not a move). | D3, §4.4, §4.6, §5.1, §5.2 rows 4, 8, 10, 17, §6.6 |
| Use kTLS: `splice` for values, or read + ZC send? | **Read + `SENDMSG`.** Software kTLS already encrypts from the user pages for full records (one pass), so `splice` saves nothing and moves every SSD read onto io-wq. ZC send is rejected by kTLS. `splice` stays a phase-6 option for NIC kTLS offload with `TLS_TX_ZEROCOPY_RO`, where it removes the last copy. | D10, §6.2, §6.4.1 |