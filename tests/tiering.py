#!/usr/bin/env python3
"""SSD-tier integrity test. Writes N objects (N >> DRAM slots), reads each once soon after
writing (so it earns SSD admission via the hit bit), then reads everything back from many
pipelined connections and verifies every returned byte. A hit must never return the wrong
value; misses are allowed (eviction), and the hit ratio from D is reported.
Usage: tiering.py [--port 11311] [--n 12000] [--v 65536] [--admin 18080]"""
import argparse, hashlib, json, socket, sys, threading, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=11311)
ap.add_argument("--admin", type=int, default=18080)
ap.add_argument("--n", type=int, default=12000)
ap.add_argument("--v", type=int, default=65536)
ap.add_argument("--threads", type=int, default=8)
a = ap.parse_args()
V = a.v

def key(i): return "%08x-0000-4000-8000-%012x" % (i, i * 2654435761 % (1 << 48))
def val(i):
    seed = hashlib.sha256(b"%d" % i).digest()
    return (seed * (V // len(seed) + 1))[:V]

class Conn:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", a.port)); self.s.settimeout(30); self.buf = b""
    def line(self):
        while b"\r\n" not in self.buf:
            c = self.s.recv(1 << 20)
            if not c: raise EOFError
            self.buf += c
        l, self.buf = self.buf.split(b"\r\n", 1); return l
    def exact(self, n):
        while len(self.buf) < n:
            c = self.s.recv(1 << 20)
            if not c: raise EOFError
            self.buf += c
        d, self.buf = self.buf[:n], self.buf[n:]; return d

def stats():
    return json.loads(urllib.request.urlopen("http://127.0.0.1:%d/stats" % a.admin).read())

bad = []
def writer(lo, hi):
    c = Conn()
    for i in range(lo, hi):
        k = key(i).encode()
        c.s.sendall(b"set %s 0 0 %d\r\n" % (k, V) + val(i) + b"\r\n" + b"get %s\r\n" % k)
        if c.line() != b"STORED": bad.append(("set", i)); continue
        h = c.line()
        if h.startswith(b"VALUE"):
            if c.exact(V + 2)[:V] != val(i): bad.append(("readback", i))
            c.line()

res = {"hit": 0, "miss": 0}
lock = threading.Lock()
def reader(ids):
    c = Conn(); hit = miss = 0
    for j in range(0, len(ids), 16):
        chunk = ids[j:j + 16]
        c.s.sendall(b"".join(b"get %s\r\n" % key(i).encode() for i in chunk))
        for i in chunk:
            h = c.line()
            if h == b"END": miss += 1; continue
            d = c.exact(V + 2)
            if h.split()[1] != key(i).encode() or d[:V] != val(i): bad.append(("get", i))
            hit += 1
            if c.line() != b"END": bad.append(("end", i))
    with lock:
        res["hit"] += hit; res["miss"] += miss

T = a.threads
step = (a.n + T - 1) // T
ths = [threading.Thread(target=writer, args=(t * step, min(a.n, (t + 1) * step))) for t in range(T)]
[t.start() for t in ths]; [t.join() for t in ths]
s1 = stats()
print("after writes: demotions=%d ssd_bytes=%d drops(no_hit=%d theta=%d no_tokens=%d forced=%d) region_opens=%d reclaims=%d"
      % (s1["demotions"], s1["ssd_bytes_written"], s1["drop_no_hit"], s1["drop_theta"], s1["drop_no_tokens"], s1["drop_forced"], s1["region_opens"], s1["reclaims"]))
ids = list(range(a.n))
ths = [threading.Thread(target=reader, args=(ids[t::T],)) for t in range(T)]
[t.start() for t in ths]; [t.join() for t in ths]
s2 = stats()
print("read-back: hits=%d misses=%d  (from DRAM %d, from SSD %d, coalesced %d)  ssd_reads=%d crc_mismatch=%d lap_mismatch=%d read_err=%d"
      % (res["hit"], res["miss"], s2["hits_m"] - s1["hits_m"], s2["hits_d"] - s1["hits_d"], s2["hits_d_coalesced"],
         s2["ssd_reads"], s2["crc_mismatch"], s2["lap_mismatch"], s2["ssd_read_err"]))
print("gauges: zombies=%d staging_held=%d filling=%d demote_inflight=%d stale=%d slot_waits=%d"
      % (s2["zombies"], s2["staging_held"], s2["filling"], s2["demote_inflight"], s2["stale_msgs"], s2["slot_waits"]))
print("CORRUPT:", len(bad), bad[:5])
ok = not bad and s2["hits_d"] > 0 and s2["crc_mismatch"] == 0 and s2["lap_mismatch"] == 0
sys.exit(0 if ok else 1)
