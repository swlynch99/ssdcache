#!/usr/bin/env python3
"""Filling slot leak check: stall many SET bodies for many cycles. Timed-out slots may stay in
worker stashes, so `filling` rises at first, but it must stay within the stash bound however
many bodies time out. A leak grows with the number of timeouts and goes past the bound."""
import argparse, json, socket, sys, time, urllib.request, uuid

ap = argparse.ArgumentParser()
ap.add_argument("--workers", type=int, default=2, help="server worker count")
ap.add_argument("--stash", type=int, default=4, help="credits.stash on the server")
ap.add_argument("--port", type=int, default=11311)
ap.add_argument("--admin", type=int, default=18080)
ap.add_argument("--v", type=int, default=65536)
ap.add_argument("--conns", type=int, default=96)
ap.add_argument("--cycles", type=int, default=30)
ap.add_argument("--wait", type=float, default=3.1, help="longer than body_timeout_ms + scan period")
a = ap.parse_args()

def stats():
    return json.loads(urllib.request.urlopen("http://127.0.0.1:%d/stats" % a.admin).read())

bound = a.workers * (a.workers - 1) * a.stash
start = stats()["body_timeouts"]
for c in range(a.cycles):
    conns = []
    for _ in range(a.conns):
        s = socket.create_connection(("127.0.0.1", a.port))
        s.sendall(b"set %s 0 0 %d\r\n" % (str(uuid.uuid4()).encode(), a.v) + b"x" * 1000)
        conns.append(s)
    time.sleep(a.wait)
    for s in conns:
        s.close()
    time.sleep(0.2)
    d = stats()
    print("cycle %d: filling %d (bound %d), timeouts %d" % (c, d["filling"], bound, d["body_timeouts"] - start), flush=True)
    if d["filling"] > bound:
        sys.exit("FAIL filling %d is past the stash bound %d" % (d["filling"], bound))
want = a.cycles * a.conns
got = stats()["body_timeouts"] - start
if got != want:
    sys.exit("FAIL %d bodies timed out, expected %d" % (got, want))
print("ok   %d stalled bodies, filling stayed within the bound" % got)
