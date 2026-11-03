#!/usr/bin/env python3
"""Slow-client checks: a SET body that stalls must be cut off by body_timeout_ms and its
slot returned; other connections keep working meanwhile."""
import argparse, json, socket, sys, time, urllib.request, uuid

ap = argparse.ArgumentParser()
ap.add_argument("--workers", type=int, default=2, help="server worker count")
ap.add_argument("--stash", type=int, default=4, help="credits.stash on the server")
a = ap.parse_args()
V = 65536
def stats(): return json.loads(urllib.request.urlopen("http://127.0.0.1:18080/stats").read())
fails = 0
stalled = []
for i in range(8):  # stall several bodies (some will map to remote owners)
    s = socket.create_connection(("127.0.0.1", 11311))
    s.sendall(b"set %s 0 0 %d\r\n" % (str(uuid.uuid4()).encode(), V) + b"x" * 1000)
    stalled.append(s)
time.sleep(0.5)
mid = stats()
# Other clients are unaffected while bodies are stalled.
t = socket.create_connection(("127.0.0.1", 11311)); t.settimeout(2)
k = str(uuid.uuid4()).encode()
t.sendall(b"set %s 0 0 %d\r\n" % (k, V) + b"y" * V + b"\r\nget %s\r\n" % k)
buf = b""
while not buf.endswith(b"END\r\n"):
    buf += t.recv(1 << 20)
ok = buf.startswith(b"STORED\r\nVALUE")
print(("ok   " if ok else "FAIL ") + "other client unaffected during stalls"); fails += not ok
time.sleep(2.5)  # > body_timeout_ms (2 s) + scan period
after = stats()
closed = 0
for s in stalled:
    s.settimeout(1)
    try:
        closed += s.recv(10) == b""
    except Exception:
        pass
ok = after["body_timeouts"] - mid["body_timeouts"] >= 8 and closed == 8
print(("ok   " if ok else "FAIL ") + "stalled bodies timed out (%d) and connections closed (%d/8)" % (after["body_timeouts"], closed)); fails += not ok
time.sleep(0.6)
fin = stats()
# A timed-out body's slot goes back to the connection's worker stash, so it stays Filling.
# Stashes hold at most `stash` slots per (worker, remote owner) pair. A slow leak needs many
# cycles to exceed this bound: tests/stallcycles.py checks that.
bound = a.workers * (a.workers - 1) * a.stash
print("filling during stall: %d, after: %d, stash bound: %d" % (mid["filling"], fin["filling"], bound))
ok = fin["filling"] <= bound
print(("ok   " if ok else "FAIL ") + "Filling slots returned"); fails += not ok
print("FAILURES:", fails); sys.exit(1 if fails else 0)
