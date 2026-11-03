#!/usr/bin/env python3
"""End-to-end smoke test against a running ssdcache (see tests/README in the commit log).
Usage: e2e.py [--mc 11311] [--resp 16379] [--http 18081] [--tls 11312] [--v 65536]"""
import argparse, os, socket, ssl, sys, uuid, http.client

ap = argparse.ArgumentParser()
ap.add_argument("--host", default="127.0.0.1")
ap.add_argument("--mc", type=int, default=11311)
ap.add_argument("--resp", type=int, default=16379)
ap.add_argument("--http", type=int, default=18081)
ap.add_argument("--tls", type=int, default=11312)
ap.add_argument("--v", type=int, default=65536)
a = ap.parse_args()
V = a.v
fails = 0

def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name)
    if not cond:
        fails += 1

def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError
        b += c
    return b

def recv_line(s):
    b = b""
    while not b.endswith(b"\r\n"):
        c = s.recv(1)
        if not c:
            raise EOFError
        b += c
    return b

def val(k):
    return (k.encode() * (V // len(k) + 1))[:V]

def memcache(s, label):
    k1, k2, k3 = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    s.sendall(b"set %s 0 0 %d\r\n" % (k1.encode(), V) + val(k1) + b"\r\n")
    check(f"{label} set", recv_line(s) == b"STORED\r\n")
    s.sendall(b"get %s\r\n" % k1.encode())
    hdr = recv_line(s)
    check(f"{label} get hdr", hdr == b"VALUE %s 0 %d\r\n" % (k1.encode(), V))
    body = recv_exact(s, V + 2)
    check(f"{label} get value", body[:V] == val(k1) and body[V:] == b"\r\n")
    check(f"{label} get END", recv_line(s) == b"END\r\n")
    # miss, multi-get, pipelining
    s.sendall(b"get %s %s %s\r\n" % (k2.encode(), k1.encode(), k3.encode()))
    hdr = recv_line(s)
    check(f"{label} multiget hit", hdr.startswith(b"VALUE " + k1.encode()))
    recv_exact(s, V + 2)
    check(f"{label} multiget END", recv_line(s) == b"END\r\n")
    # pipelined: set k2, get k2, delete k2, get k2, meta mg miss, mn
    pipe = (b"set %s 0 0 %d noreply\r\n" % (k2.encode(), V) + val(k2) + b"\r\n" +
            b"get %s\r\n" % k2.encode() + b"delete %s\r\n" % k2.encode() + b"get %s\r\n" % k2.encode() +
            b"mg %s v\r\n" % k3.encode() + b"mn\r\n")
    s.sendall(pipe)
    check(f"{label} pipe get hdr", recv_line(s).startswith(b"VALUE " + k2.encode()))
    check(f"{label} pipe get value", recv_exact(s, V + 2)[:V] == val(k2))
    check(f"{label} pipe END", recv_line(s) == b"END\r\n")
    check(f"{label} pipe DELETED", recv_line(s) == b"DELETED\r\n")
    check(f"{label} pipe get after delete", recv_line(s) == b"END\r\n")
    check(f"{label} meta miss", recv_line(s) == b"EN\r\n")
    check(f"{label} mn", recv_line(s) == b"MN\r\n")
    s.sendall(b"set %s 0 0 5\r\nhello\r\n" % k3.encode())
    check(f"{label} wrong length rejected", recv_line(s).startswith(b"CLIENT_ERROR"))
    s.sendall(b"get bad-key\r\n")
    check(f"{label} bad key", recv_line(s).startswith(b"CLIENT_ERROR"))
    s.sendall(b"version\r\n")
    check(f"{label} version", recv_line(s).startswith(b"VERSION"))

# memcache plaintext
s = socket.create_connection((a.host, a.mc)); s.settimeout(5)
memcache(s, "mc"); s.close()

# memcache over TLS (kTLS on the server)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
t = ctx.wrap_socket(socket.create_connection((a.host, a.tls)), server_hostname="localhost"); t.settimeout(5)
check("tls version", t.version() == "TLSv1.3")
memcache(t, "mc-tls"); t.close()

# RESP
r = socket.create_connection((a.host, a.resp)); r.settimeout(5)
def cmd(*args):
    out = b"*%d\r\n" % len(args)
    for x in args:
        x = x if isinstance(x, bytes) else x.encode()
        out += b"$%d\r\n%s\r\n" % (len(x), x)
    return out
k = str(uuid.uuid4()); k2 = str(uuid.uuid4())
r.sendall(cmd("PING")); check("resp ping", recv_line(r) == b"+PONG\r\n")
r.sendall(cmd("SET", k, val(k))); check("resp set", recv_line(r) == b"+OK\r\n")
r.sendall(cmd("SET", k, val(k), "NX")); check("resp set NX existing", recv_line(r) == b"$-1\r\n")
r.sendall(cmd("GET", k)); check("resp get hdr", recv_line(r) == b"$%d\r\n" % V)
check("resp get value", recv_exact(r, V + 2)[:V] == val(k))
r.sendall(cmd("MGET", k2, k))
check("resp mget arr", recv_line(r) == b"*2\r\n"); check("resp mget nil", recv_line(r) == b"$-1\r\n")
check("resp mget hit", recv_line(r) == b"$%d\r\n" % V); recv_exact(r, V + 2)
r.sendall(cmd("EXISTS", k, k2)); check("resp exists", recv_line(r) == b":1\r\n")
r.sendall(cmd("DEL", k, k2)); check("resp del", recv_line(r) == b":1\r\n")
r.sendall(cmd("GET", k)); check("resp get after del", recv_line(r) == b"$-1\r\n")
r.sendall(cmd("SET", k, val(k), "EX", "10")); check("resp ttl rejected", recv_line(r).startswith(b"-ERR"))
r.close()

# HTTP
k = str(uuid.uuid4())
h = http.client.HTTPConnection(a.host, a.http, timeout=5)
h.request("PUT", "/" + k, body=val(k)); resp = h.getresponse(); resp.read()
check("http put", resp.status == 204)
h.request("GET", "/" + k); resp = h.getresponse(); body = resp.read()
check("http get", resp.status == 200 and body == val(k))
h.request("HEAD", "/" + k); resp = h.getresponse(); resp.read()
check("http head", resp.status == 200)
h.request("DELETE", "/" + k); resp = h.getresponse(); resp.read()
check("http delete", resp.status == 204)
h.request("GET", "/" + k); resp = h.getresponse(); resp.read()
check("http get miss", resp.status == 404)
h.close()

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
