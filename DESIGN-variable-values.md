# Variable value sizes: design proposal

Status: proposal. No code has changed. Section numbers such as §5.1 refer to `DESIGN.md`.

## 1. Goal and result

Each object has its own length, from 0 to 1 MiB (1,048,576 B), in one server instance. All of these must still hold:

- No allocations or locks on request threads.
- Bodies are received straight into their final memory, and hits are sent without a copy.
- SSD writes stay in one global FIFO, so DLWA stays near 1.
- Every race in the §5.2 table stays safe.
- A fixed 64 KiB workload performs as it does today.

The proposal has three main parts:

1. **DRAM:** replace fixed slots with a 4 KiB page allocator. It prefers one contiguous run and falls back to a chain of runs, so an allocation succeeds whenever enough pages are free.
2. **SSD:** keep the region FIFO, but write objects as page-aligned variable-length records. `Entry.ssd` stays a dense id, and it now names a record, not a fixed position.
3. **Accounting:** count pages and bytes where the code counts slots today. This covers eviction, wear budget and quotas.

A value under 4 KiB uses a full page in DRAM and on the SSD. Those values work correctly, but they waste space. Section 8 describes an optional small-object tier that fixes this.

## 2. What assumes one size today

| Area | Assumption | Change |
|---|---|---|
| `sizing.rs` | One stride `S`; ids and tables derive from it | Page-based geometry |
| `slots.rs` | One slot per object; free lists of equal slots | Run allocator; state stays on the first page |
| `Entry` | No length field | Add a 21-bit length |
| `shard.rs` reserve, stash | A Filling slot fits any body | `Reserve` carries the length; the stash goes away |
| `shard.rs` eviction | `mem_used`, `cache_cap`, watermarks in objects | Pages |
| `shard.rs` demotion | `ssd_location` computes position from the id; cost is constant | Position comes from the record; cost depends on length |
| `flash.rs` | Back-map and CRC per fixed SSD slot | Per record, plus a page offset |
| `worker.rs` | One contiguous value of length V | Per-entry length, a cursor over runs |
| `proto/*` | A body must equal V | A body must be at most `max_value_bytes` |
| Quotas (§5.1) | `H = N·P + N·F + W` slots | No longer a useful bound (section 5) |

## 3. DRAM: page run allocator

### 3.1 Options

| Option | Fit | Problem |
|---|---|---|
| Size-class slabs | Contiguous, one iovec | Memory is stuck in the wrong classes unless pages are moved between them. A SET in a rare class may need a long eviction scan, because the FIFO tail can hold other classes. |
| Log or ring of bytes (segcache style) | Contiguous, simple allocation | Dead values keep their space until the log wraps. Context 18b measured 55-63% dead items in segcache Fifo at 90/10. Reinsertion copies values. A slow client pins a segment or stops the tail. |
| Buddy allocator, contiguous only | Contiguous | A 1 MiB SET can fail with enough free memory, or evict much more than it needs. |
| Chain of fixed chunks | Never fragments | One chunk size must trade waste against iovec count. A random chain turns today's single-iovec 64 KiB send into 16 iovecs. |
| **Runs, with chain as fallback (proposed)** | Usually contiguous, never fails while pages are free | About 250 lines of allocator, and every reader must handle chains |

### 3.2 Allocator

- The page size is 4 KiB. It matches the SSD alignment, so a value in a page run can be written with `O_DIRECT` without a copy.
- Each shard partition has two pools, as it does today: cache and staging.
- Free runs sit in power-of-two bins of intrusive lists. Frees coalesce with neighbours in O(1), using run lengths at both ends of a free run.
- `alloc(n)` takes the smallest run of at least `n` pages and splits it. If no run is big enough, it takes the largest runs until it has `n` pages.
- **Key property:** `alloc(n)` succeeds if and only if `free_pages >= n`. It fails only when the pool is short of pages, never because of fragmentation.
- Runs do not cross a 1 GiB chunk, so `READ_FIXED` and `WRITE_FIXED` still work with one buffer index per run.
- Allocation is all or nothing. Nothing holds part of a value while it waits, so waiting cannot deadlock.

With uniform 64 KiB values, every free run has exactly the right size. Each value is then one run and one iovec, as it is today.

### 3.3 Page metadata

An array with one 16 B record per page, about 0.4% of DRAM:

```rust
struct PageMeta {
    next: u32,   // first page of the next run in this value, or NONE
    run: u32,    // run length in pages (also used by the free lists)
    pins: u16,   // first page only
    state: u8,   // first page only: same states as SlotMeta
    sgen: u32,   // first page only
    len: u32,    // first page only: value length while Filling
}
```

`slot` in messages becomes the first page id. `pin`, `unpin`, `retire`, zombies and generations keep their current logic, so the race table does not change. `next` and `run` are written by the owner before the slot reaches another worker, and they do not change while the slot is Filling or pinned. Other workers read them through the same Release/Acquire chain that publishes value bytes today (§5.2 "Visibility").

Filling and staging values use the same structure. A staging run for an SSD read is taken from the staging pool. Reads wait in FIFO order, so a 1 MiB read at the head cannot starve behind smaller reads.

## 4. SSD: variable records in the same FIFO

### 4.1 Layout

`Entry.ssd` stays a dense id, `region * records_per_region + i`. Only its meaning changes: it now names a record.

```rust
struct SsdRecord {         // replaces backmap[] and crcmap[], 16 B
    back: u64,             // (eh << 32) | ver
    crc: u32,
    page: u32,             // first page within the region
}
```

This keeps most shard code as it is: `lap_ok`, `region_of`, reclaim and the back-map liveness check all work on the id. Only `ssd_location` changes, and it now reads `page` from the record.

An object uses `max(1, ceil(len / 4096))` pages. It takes the next pages of the shard's open region. If it does not fit, the shard seals the region and opens the next one. A region also seals when its records are full.

Objects never cross a region. `region_bytes` must be at least 4 × `max_value_bytes`, so the wasted tail is small: on average about half an object per region.

### 4.2 Footer

Footers keep their 32 B records. The 8 spare bytes hold `page` and `len`. The footer magic changes to `SSDCFTR2`. Nothing reads footers yet, because warm restart is not implemented, so there is no migration.

### 4.3 Writes and reads

- One run: `WRITE_FIXED` or `READ_FIXED`, as today.
- Several runs: `WRITEV` or `READV` with a per-op iovec array. Each op needs up to 256 iovecs, so about 4 KiB per op. `WRITEV_FIXED` needs kernel 6.15 and our hosts run 6.12, so this is the only choice for now.
- Writes are rounded up to whole pages. The padding holds stale bytes from earlier objects, as padded slots do today. It is never sent, and the CRC covers only `len` bytes.

### 4.4 Metadata sizing

The record count must be fixed at startup, so it needs a size estimate. A new setting, `avg_value_bytes`, gives `records_per_region = region_bytes / avg_value_bytes`.

If real values are smaller than the estimate, regions seal early. The server stays correct but uses less of the device. The existing `early_seals` counter shows this. If values are larger, some record memory is unused.

Entry count is bounded by construction:

- DRAM objects are at most the number of pages, because each uses at least one.
- D objects are at most the number of records.

So the slab, index and M ring never need a count-based eviction rule. Ghost and sketch sizes use the estimate.

Example: 16 GiB DRAM, 40 GiB device, 8 workers, `avg_value_bytes = 65536`. SSD metadata stays close to today's, plus 16 B per DRAM page, which is 64 MiB. The entry slab grows, because DRAM may now hold 4M one-page objects: at most 128 MiB for 16 GiB of DRAM.

At `avg_value_bytes = 4096` on a 4 TB device: about 1G records. That is 16 GB of records plus about 40 GB of entries and index. Startup prints these sizes, and it fails if they exceed a limit.

## 5. Eviction, quotas and pinned memory

### 5.1 Eviction

The rule becomes: evict until `free_pages` is above a watermark. `mem_used`, `pending_free` and `cache_cap` all change to pages. A SET of a large value may evict many small ones. `make_room` keeps its per-step limit, and the reservation waits in the existing FIFO. The owner stays responsive, and the SET waits.

S3-FIFO stays count-based: M order and `freq` do not consider size. Object hit ratio and byte hit ratio can now differ, so stats report both.

### 5.2 Why `H` goes away

Today `H` reserves worst-case slots outside the cache. With 1 MiB values the worst case is about 640 MiB per shard at N = 8, about a third of a 16 GiB server's shard memory. It would be reserved for a case that rarely occurs.

Instead, zombies and Filling pages reduce `free_pages` directly, and eviction responds. The cache shrinks while memory is pinned and grows back afterwards. If everything is pinned, reservations wait. This is the same bounded wait as §5.1(5), but it is no longer backed by a fixed reserve.

### 5.3 Pinned bytes must be limited

This is a new requirement. Pin quotas count objects, so one stalled client can hold much more than before:

- At N = 8 and P = 64, one shard can have 512 MiB pinned, against about 40 MiB at 64 KiB today.
- Staging is smaller than that, so stalled clients could block all SSD reads on a shard.
- The README lists pinned-byte caps and the spill pool as not implemented. A stalled client holds its pins until it disconnects.

So this work must add the byte caps from §5.1(6): 4 MiB per connection, and a new per-pair cap. Worker A learns the size from `Hit`, so it enforces the caps at dispatch. A can overshoot by the requests already in flight, which is a 1 MiB worst case for each. The spill pool can stay out of scope.

One risk: these caps park connections, and contexts 12 and 13 suggested the parked path causes unfair latency under overload. That cause was not proven. The parked-connection fix may need to come first if tests show the problem.

### 5.4 SET path

- `Reserve` carries the length, and `Reserved` returns the first page. `Commit` needs no length, because the owner has it in `PageMeta`.
- **The stash is removed.** A slot granted ahead of time cannot fit a length nobody knows yet. So every cross-shard SET takes one more ring hop. Section 9 tests the cost. Removing it deletes `Grant` and the stash code.
- The fill quota F stays a count, so Filling memory is bounded by `N·F·1 MiB`, 64 MiB per shard at N = 8. A client that announces 1 MiB and sends nothing holds that memory for at most `body_timeout_ms`.

### 5.5 Wear budget

`Budget.admit` takes the cost of each object: its pages, plus a share of the footer. A failed region allocation refunds the same amount. `ssd_bytes_written` counts actual pages.

## 6. Worker and protocol changes

- `RespEntry` gets `vlen`. `Reply::Hit` gets `len`. It still fits one 64 B message.
- `Proto::encode` takes the entry's length, not V. `parse` takes the maximum.
- Over-limit lengths keep today's rule: a small excess is rejected and drained, and a large one is fatal.
- **Send:** `try_flush` walks the runs. `RespEntry` keeps a cursor, so a resumed send does not walk from the start. `MAX_IOV` remains a limit: a value that does not fit continues in the next `SENDMSG`. `SEND_BUDGET` is 256 KiB, so a 1 MiB value takes at least 4 sends, and each is followed by an owner pass.
- **Receive:** `Rx::Body` keeps a cursor. There is one `RECV` per run, with `MSG_WAITALL`.
- **Length 0:** uses one page, on the same path as any other value. Protocol code must handle `$0`, `VALUE k 0 0`, `Content-Length: 0` and no value iovec. The send code already skips empty segments.

### Entry

`Entry` must stay 32 B, and it needs 21 bits for lengths up to 1 MiB inclusive. `meta` has only 15 free bits. So `ver` narrows from 32 to 26 bits, and the length uses those 6 bits plus the 15 in `meta`.

A narrower `ver` is safe. Reclaim also checks `e.ssd == id`, and a wrap needs 67M overwrites of one key during one in-flight IO. The hard ceiling for `max_value_bytes` becomes 2 MiB − 1.

### Config

| Setting | Default | Note |
|---|---|---|
| `max_value_bytes` | 1048576 | Replaces `value_size`; up to 2 MiB − 1 |
| `avg_value_bytes` | 65536 | Sets SSD record count (section 4.4) |
| `staging_bytes` | derived | Today's value at the average size, and at least 4 × max |
| `conn_pinned_bytes` | 4 MiB | Section 5.3 |
| `pair_pinned_bytes` | derived | Section 5.3 |

`value_size` is removed. Configs that set it fail with an error that names the new settings.

## 7. Known costs and risks

- **CRC on the owner.** Today the owner computes CRCs inline: at demotion, and when a read completes. `crc.rs` uses one SSE4.2 stream, so a 1 MiB value could block the shard for roughly 100 µs or more, against about 6 µs at 64 KiB. These are estimates to measure. If the cost shows up in the tail, compute the CRC at `Commit` time on the connection side, or use a parallel CRC.
- **Vectored IO** gives up fixed buffers for fragmented values. The allocator keeps this rare for narrow size mixes, but a wide mix could fragment more. Stats report runs per value.
- **Fairness.** Large values use more network, crypto and device time per request, so mixed traffic will have a higher tail for small values. This comes with any mixed-size cache.
- **Device reads.** A 1 MiB read at the current per-shard queue depth is heavier than a 64 KiB read. `credits.qd` may need to be in bytes. I'd measure this before changing it.
- **Hit ratio.** One evicted 1 MiB value may be worth less than 256 small values. Size-aware admission is out of scope.

## 8. Optional: small-object tier

Without this tier, 100 B values waste 97% of each DRAM and SSD page. If such values matter, this tier adds:

- **DRAM:** classes from 128 B to 2 KiB, carved from pages. A page holds one class, and it returns to the allocator when it empties. Objects in a page arrive at about the same time, so FIFO tends to empty pages. No rebalancing thread is needed.
- **SSD:** a per-shard pack buffer. Small values are copied in and written as whole pages, and a record names a page plus an offset. A read still takes one 4 KiB page.

It costs a copy on demotion, and it adds a third way to store a value. I'd build it only if the expected workload needs it. Sections 3 to 6 do not block it.

## 9. Implementation order

Each step keeps all tests passing and is committed to `main` on its own.

1. **Lengths in fixed slots.** Add per-object lengths through `Entry`, replies, protocols and send paths, while every object still uses a slot of `max_value_bytes`. This is correct but wasteful, and it tests all length handling first.
2. **SSD records.** Add `SsdRecord`, variable page counts, and byte costs in the wear budget.
3. **Page allocator.** Build the allocator with property tests, then move the cache and staging pools to it, with one run per value.
4. **Run chains.** Add chains to send, receive, CRC and vectored IO.
5. **Accounting and quotas.** Move eviction to pages, remove `H` and the stash, and add pinned-byte caps.
6. **Tools.** Add size distributions to `sim` and `bench`.

### Tests

- **Allocator:** random alloc and free against a model. No leaks or overlaps, and `alloc` succeeds whenever enough pages are free.
- **Simulator:** mixed sizes with delayed and reordered IO, read errors and full invariant checks. Add a fragmentation stress case.
- **End to end:** byte-exact readback at 0, 1, 4095, 4096, 4097, 65536 and 1048576 B, on memcache, RESP and HTTP, in plaintext and TLS, from DRAM and from SSD. Cover overwrites that change size, and over-limit requests.
- **SystemsLab:** all at 90/10 with no backfill, under 10 minutes each:
  - Regression: fixed 64 KiB, against `5bae701`. GET and SET p99 and worker CPU should stay within run-to-run spread. This also measures the cost of removing the stash.
  - A fixed 1 MiB run and a fixed 1 KiB run.
  - A mixed-size run. cachecannon appears to have one fixed `workload.values.length`, which I have not confirmed. If so, run several instances with separate keyspaces and sizes.
  - A stalled-client test for pinned-byte caps.

## 10. Decisions needed

1. **Do values under about 4 KiB need to be space-efficient?** Without the tier in section 8 they work, but each uses a full page. My recommendation is to leave it out unless you expect many of them.
2. **Is removing the SET stash acceptable?** I recommend yes, with the regression test as the check. It simplifies a lot of code, and SETs are 10% of the default mix.
3. **What should `avg_value_bytes` default to?** I propose 65536, to match current tests. A lower value makes small values work better on the SSD, but it needs more metadata. For example, 4096 needs 16 times the SSD record memory.
4. **Is 1 MiB = 1,048,576 B right?** I've assumed it, because that is the usual memcached limit. The design allows up to 2 MiB − 1.
