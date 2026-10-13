#!/usr/bin/env python3
"""Network fuzzer for bserve and bcurl (stdlib only).

    python3 fuzz/netfuzz.py server [--cases N] [--seed S]   # hostile clients vs bserve
    python3 fuzz/netfuzz.py client [--cases N] [--seed S]   # hostile server vs bcurl
    python3 fuzz/netfuzz.py checks                          # targeted checks vs bserve
    python3 fuzz/netfuzz.py all

Binaries default to the sanitized build (make debug): BSERVE / BCURL override.
Every frame bserve sends is validated against SPEC.md (lengths, types, flags,
IDs, status range, header block, content-length = body, HEAD has no DATA).
Exit status 0 = no finding; findings are printed as "FAIL ...".
"""
import argparse
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BSERVE = os.path.abspath(os.environ.get("BSERVE", os.path.join(REPO, "build/debug/bserve")))
BCURL = os.path.abspath(os.environ.get("BCURL", os.path.join(REPO, "build/debug/bcurl")))
SAN = ("AddressSanitizer", "LeakSanitizer", "UndefinedBehaviorSanitizer", "runtime error:",
       "SUMMARY: ")

REQUEST, RESPONSE, DATA, GOAWAY = 1, 2, 3, 4
END = 1
GET, HEAD, POST, PUT, DELETE = 1, 2, 3, 4, 5
STATIC = ["host", "user-agent", "accept", "content-type", "content-length",
          "last-modified", "date", "server", "location", "allow"]
NAME_OK = set(b"abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~")

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("FAIL " + msg, flush=True)


# ---- wire ------------------------------------------------------------------

def frame(t, flags, rid, payload=b""):
    return struct.pack(">HBBI", len(payload) & 0xffff, t, flags, rid) + payload


def field(name, value, literal=False):
    v = value if isinstance(value, bytes) else value.encode()
    if name in STATIC and not literal:
        return bytes([STATIC.index(name) + 1]) + struct.pack(">H", len(v)) + v
    n = name.encode()
    return b"\x00" + bytes([len(n)]) + n + struct.pack(">H", len(v)) + v


def req(rid, path, method=GET, fields=b"", flags=END):
    p = path if isinstance(path, bytes) else path.encode()
    return frame(REQUEST, flags, rid, bytes([method]) + struct.pack(">H", len(p)) + p + fields)


def resp(rid, status, fields=b"", flags=0):
    return frame(RESPONSE, flags, rid, struct.pack(">H", status) + fields)


def parse_block(b):
    """List of (name, value) or raises ValueError (SPEC 5.3)."""
    out, off = [], 0
    while off < len(b):
        idx = b[off]
        off += 1
        if idx > 10:
            raise ValueError("index %d" % idx)
        if idx == 0:
            if off >= len(b):
                raise ValueError("truncated nlen")
            nl = b[off]
            off += 1
            name = b[off:off + nl]
            if nl == 0 or len(name) != nl or any(c not in NAME_OK for c in name):
                raise ValueError("bad literal name")
            off += nl
            name = name.decode()
        else:
            name = STATIC[idx - 1]
        if off + 2 > len(b):
            raise ValueError("truncated vlen")
        vl = struct.unpack(">H", b[off:off + 2])[0]
        off += 2
        v = b[off:off + vl]
        if len(v) != vl or any(c in (0, 10, 13) for c in v):
            raise ValueError("bad value")
        off += vl
        out.append((name, v))
    return out


def recv_exact(s, n, deadline):
    buf = b""
    while len(buf) < n:
        s.settimeout(max(0.01, deadline - time.time()))
        try:
            chunk = s.recv(n - len(buf))
        except socket.timeout:
            return buf, "timeout"
        except OSError:
            return buf, "reset"
        if not chunk:
            return buf, "eof"
        buf += chunk
    return buf, None


def read_frame(s, timeout=10.0):
    """(type, flags, id, payload) or (None, reason)."""
    dl = time.time() + timeout
    h, why = recv_exact(s, 8, dl)
    if why:
        return None, (why if not h else "partial header (%s)" % why)
    ln, t, fl, rid = struct.unpack(">HBBI", h)
    if ln > 16384:
        return None, "Length %d > 16384" % ln
    p, why = recv_exact(s, ln, dl)
    if why:
        return None, "partial payload (%s)" % why
    return (t, fl, rid, p), None


class ServerChecker(object):
    """Validates every frame bserve sends on one connection (SPEC 3-7)."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.cur = None      # [id, head, status, cl, body]

    def feed(self, f, sent_head=None):
        t, fl, rid, p = f
        ctx = self.ctx
        if t not in (RESPONSE, DATA, GOAWAY):
            fail("%s: server sent frame type 0x%02x" % (ctx, t))
        if fl & ~END:
            fail("%s: server set reserved flag bits 0x%02x" % (ctx, fl))
        if t == GOAWAY:
            if rid != 0 or len(p) != 5 or p[4] not in (0, 1, 2):
                fail("%s: odd GOAWAY id=%d payload=%r" % (ctx, rid, p))
            if self.cur:
                fail("%s: GOAWAY inside response %d" % (ctx, self.cur[0]))
            return
        if t == RESPONSE:
            if self.cur:
                fail("%s: RESPONSE while response %d still open" % (ctx, self.cur[0]))
            if len(p) < 2:
                fail("%s: short RESPONSE" % ctx)
                return
            st = struct.unpack(">H", p[:2])[0]
            if not 200 <= st <= 599:
                fail("%s: status %d" % (ctx, st))
            try:
                hdrs = parse_block(p[2:])
            except ValueError as e:
                fail("%s: malformed header block from server: %s" % (ctx, e))
                hdrs = []
            cls = [v for n, v in hdrs if n == "content-length"]
            if len(set(cls)) > 1:
                fail("%s: conflicting content-length %r" % (ctx, cls))
            cl = int(cls[0]) if cls else None
            if sent_head is True and not fl & END:
                fail("%s: HEAD response without END" % ctx)
            self.cur = [rid, sent_head, st, cl, 0, []]
            if fl & END:
                self._done(ended=True)
            return
        if t == DATA:
            if not self.cur or self.cur[0] != rid:
                fail("%s: DATA id=%d with no open response" % (ctx, rid))
                return
            if self.cur[1] is True:
                fail("%s: DATA in a HEAD response" % ctx)
            self.cur[5].append(len(p))
            self.cur[4] += len(p)
            if fl & END:
                self._done(ended=True)

    def _done(self, ended):
        rid, head, st, cl, body, sizes = self.cur
        if cl is not None and head is False and cl != body:
            fail("%s: id %d content-length %d but body %d" % (self.ctx, rid, cl, body))
        if any(n != 16384 for n in sizes[:-1]):
            fail("%s: id %d DATA frames not filled: %r (SHOULD)" % (self.ctx, rid, sizes[:8]))
        self.last = (rid, st, cl, body)
        self.cur = None


def read_response(s, rid, ctx, head=False, timeout=10.0, chk=None):
    """Reads one full response; returns (status, headers, body) or (None, why)."""
    chk = chk or ServerChecker(ctx)
    status, hdrs, body = None, [], b""
    while True:
        f, why = read_frame(s, timeout)
        if f is None:
            return None, why
        chk.feed(f, sent_head=head)
        t, fl, frid, p = f
        if t == GOAWAY:
            return None, "GOAWAY code %r" % (p[4:5],)
        if t == RESPONSE:
            if frid != rid:
                return None, "RESPONSE id %d, expected %d" % (frid, rid)
            status = struct.unpack(">H", p[:2])[0]
            try:
                hdrs = parse_block(p[2:])
            except ValueError:
                hdrs = []
            if fl & END:
                return (status, hdrs, body), None
        elif t == DATA:
            body += p
            if fl & END:
                return (status, hdrs, body), None


def hdr(hdrs, name):
    for n, v in hdrs:
        if n == name:
            return v.decode("latin-1")
    return None


# ---- bserve fixture --------------------------------------------------------

def make_root(base):
    root = os.path.join(base, "root")
    os.mkdir(root)
    rng = random.Random(7)
    sizes = {"z0": 0, "b16383": 16383, "b16384": 16384, "b16385": 16385, "b65535": 65535,
             "big.bin": 1 << 20}
    for name, n in sizes.items():
        with open(os.path.join(root, name), "wb") as f:
            f.write(bytes(rng.getrandbits(8) for _ in range(min(n, 70000))) +
                    b"x" * max(0, n - 70000))
    with open(os.path.join(root, "hello.txt"), "w") as f:
        f.write("Hello, bhttp!\n")
    with open(os.path.join(root, "index.html"), "w") as f:
        f.write("<p>index</p>\n")
    os.mkdir(os.path.join(root, "sub"))
    with open(os.path.join(root, "sub", "index.html"), "w") as f:
        f.write("sub\n")
    os.mkdir(os.path.join(root, "noindex"))
    os.mkdir(os.path.join(root, "locked"))
    with open(os.path.join(root, "locked", "index.html"), "w") as f:
        f.write("locked\n")
    os.chmod(os.path.join(root, "locked"), 0)
    with open(os.path.join(root, "unreadable.txt"), "w") as f:
        f.write("no\n")
    os.chmod(os.path.join(root, "unreadable.txt"), 0)
    with open(os.path.join(root, ".hidden"), "w") as f:
        f.write("hidden\n")
    with open(os.path.join(root, "..."), "w") as f:
        f.write("three dots\n")
    with open(os.path.join(root, "%2e%2e"), "w") as f:
        f.write("literal\n")
    with open(os.path.join(base, "secret.txt"), "w") as f:
        f.write("SECRET outside root\n")
    os.mkdir(os.path.join(base, "rootx"))
    with open(os.path.join(base, "rootx", "secret.txt"), "w") as f:
        f.write("SECRET in sibling with shared prefix\n")
    os.symlink("../secret.txt", os.path.join(root, "esc"))
    os.symlink("/etc", os.path.join(root, "etc"))
    os.symlink("../rootx", os.path.join(root, "sib"))
    os.symlink("hello.txt", os.path.join(root, "inlink"))
    os.symlink("loop", os.path.join(root, "loop"))
    os.symlink("nowhere", os.path.join(root, "dangling"))
    os.mkfifo(os.path.join(root, "fifo"))
    return root


class Bserve(object):
    def __init__(self, root, idle=None):
        self.log = tempfile.NamedTemporaryFile(prefix="bserve-", suffix=".log", delete=False)
        args = [BSERVE] + (["-t", str(idle)] if idle else []) + [root, "0"]
        env = dict(os.environ, ASAN_OPTIONS="halt_on_error=1:detect_leaks=0",
                   UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1")
        self.p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=self.log, env=env)
        dl = time.time() + 10
        self.port = None
        while time.time() < dl and self.port is None:
            m = re.search(r"listening on (?:\[::\]|0\.0\.0\.0):(\d+)", self.text())
            if m:
                self.port = int(m.group(1))
            else:
                time.sleep(0.05)
        if self.port is None:
            raise RuntimeError("bserve did not start: " + self.text())

    def text(self):
        with open(self.log.name, "rb") as f:
            return f.read().decode("latin-1")

    def sanitizer(self):
        return [l for l in self.text().splitlines() if any(m in l for m in SAN)]

    def connect(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s

    def children(self):
        out = subprocess.run(["pgrep", "-P", str(self.p.pid)], stdout=subprocess.PIPE,
                             universal_newlines=True).stdout.split()
        return [int(x) for x in out]

    def stop(self):
        for c in self.children():
            try:
                os.kill(c, 9)
            except OSError:
                pass
        self.p.kill()
        self.p.wait()
        os.unlink(self.log.name)


def get(srv, path, method=GET, rid=1, ctx="get", host=True):
    s = srv.connect()
    try:
        s.sendall(req(rid, path, method, field("host", "x") if host else b""))
        return read_response(s, rid, ctx, head=(method == HEAD))
    finally:
        s.close()


def alive(srv, ctx):
    r, why = get(srv, "/hello.txt", ctx=ctx)
    if r is None or r[0] != 200 or r[2] != b"Hello, bhttp!\n":
        fail("%s: server no longer answers a valid request (%s %r)" % (ctx, why, r and r[:1]))
        return False
    return True


# ---- server fuzzing --------------------------------------------------------

def valid_stream(rng, start_id):
    """A pipelined stream of valid frames plus the expected (id, head) list."""
    out, exp, rid = [], [], start_id
    paths = ["/hello.txt", "/", "/sub", "/sub/", "/nope", "/b16384", "/z0", "/b16385",
             "/esc", "/.hidden", "/x/../y", "/sub/?a=..", "/fifo", "/unreadable.txt"]
    for _ in range(rng.randint(1, 8)):
        kind = rng.random()
        if kind < 0.15:
            out.append(frame(rng.choice([0, 5, 0x42, 0x7f, 0x80, 0xff]), rng.randint(0, 255),
                             rng.randint(0, 2**32 - 1), os.urandom(rng.randint(0, 64))))
            continue
        m = rng.choice([GET, GET, GET, HEAD, POST, DELETE])
        fields = b"".join(field(rng.choice(STATIC + ["x-a"]), "v%d" % rng.randint(0, 9))
                          for _ in range(rng.randint(0, 4)))
        if m in (POST, DELETE) and rng.random() < 0.7:
            body = os.urandom(rng.randint(0, 40000))
            out.append(req(rid, rng.choice(paths), m, field("content-length", str(len(body))) + fields, flags=0))
            for i in range(0, len(body), 16384):
                out.append(frame(DATA, 0, rid, body[i:i + 16384]))
            out.append(frame(DATA, END, rid, b""))
        else:
            out.append(req(rid, rng.choice(paths), m, fields))
        exp.append((rid, m == HEAD))
        rid += 1
    return b"".join(out), exp


def mutate(rng, data):
    b = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        op = rng.random()
        if not b:
            b += os.urandom(8)
        i = rng.randrange(len(b))
        if op < 0.3:
            b[i] ^= 1 << rng.randrange(8)
        elif op < 0.5:
            b[i] = rng.choice([0, 1, 2, 3, 4, 0x3f, 0x40, 0x7f, 0x80, 0xff])
        elif op < 0.65:
            del b[i:i + rng.randint(1, 16)]
        elif op < 0.8:
            b[i:i] = os.urandom(rng.randint(1, 16))
        else:
            b[i:i + 2] = struct.pack(">H", rng.choice([0, 1, 16383, 16384, 16385, 65535]))
    return bytes(b)


def send_split(s, data, rng):
    i = 0
    while i < len(data):
        n = rng.choice([1, 2, 3, 7, 8, 9, 100, 4096, 70000])
        try:
            s.sendall(data[i:i + n])
        except OSError:      # the reader gave up and closed the socket
            return
        i += n


def heads_sent(data):
    """Request ID -> True (HEAD) / False / None (ID reused with mixed methods),
    from the REQUEST frames actually present in the bytes sent."""
    out, off = {}, 0
    while off + 8 <= len(data):
        ln, t, fl, rid = struct.unpack(">HBBI", data[off:off + 8])
        if ln > 16384:
            break
        if t == REQUEST and ln >= 1 and off + 8 < len(data):
            h = data[off + 8] == HEAD
            out[rid] = h if out.get(rid, h) == h else None
        off += 8 + ln
    return out


def drain_check(s, ctx, sent=b"", timeout=3.0):
    """Reads everything until close/timeout, validating each frame."""
    chk = ServerChecker(ctx)
    heads = heads_sent(sent)
    while True:
        f, why = read_frame(s, timeout)
        if f is None:
            if why and why.startswith("Length"):
                fail("%s: %s" % (ctx, why))
            return why
        head = heads.get(f[2], False) if f[0] == RESPONSE and f[2] != 0 else False
        chk.feed(f, sent_head=head)


def fuzz_server(cases, seed):
    rng = random.Random(seed)
    base = tempfile.mkdtemp(prefix="netfuzz-")
    srv = Bserve(make_root(base), idle=2)
    stats = {"connections": 0, "bytes": 0}
    t0 = time.time()
    try:
        for n in range(cases):
            ctx = "server case %d seed %d" % (n, seed)
            kind = n % 8
            try:
                s = srv.connect()
            except OSError as e:
                fail("%s: connect failed: %s" % (ctx, e))
                time.sleep(0.2)
                continue
            stats["connections"] += 1
            try:
                if kind == 0:                                   # random bytes
                    data = os.urandom(rng.randint(1, 20000))
                    s.sendall(data)
                    drain_check(s, ctx, data)
                elif kind in (1, 2):                            # mutated valid stream
                    data, exp = valid_stream(rng, 1)
                    data = mutate(rng, data)
                    send_split(s, data, rng)
                    if rng.random() < 0.5:
                        s.shutdown(socket.SHUT_WR)
                    drain_check(s, ctx, data)
                elif kind == 3:                                 # pipelined valid, split writes, ordered answers
                    data, exp = valid_stream(rng, 1)
                    threading.Thread(target=send_split, args=(s, data, rng), daemon=True).start()
                    chk = ServerChecker(ctx)
                    for rid, head in exp:
                        r, why = read_response(s, rid, ctx, head=head, chk=chk)
                        if r is None:
                            fail("%s: valid pipelined request %d: %s" % (ctx, rid, why))
                            break
                elif kind == 4:                                 # truncated frame then close
                    data, exp = valid_stream(rng, 1)
                    data = data[:rng.randint(1, len(data))]
                    s.sendall(data)
                    s.shutdown(socket.SHUT_WR)
                    drain_check(s, ctx, data)
                elif kind == 5:                                 # mid-response disconnect (RST)
                    s.sendall(req(1, rng.choice(["/big.bin", "/b65535"])))
                    s.recv(rng.randint(1, 30000))
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                elif kind == 6:                                 # oversized / header-only junk
                    ln = rng.choice([16385, 40000, 65535])
                    s.sendall(struct.pack(">HBBI", ln, rng.randint(0, 255), 0, rng.randint(0, 9)))
                    drain_check(s, ctx)
                else:                                           # many requests, long-lived
                    data = b"".join(req(rid, rng.choice(["/hello.txt", "/z0", "/nope", "/sub"]),
                                        rng.choice([GET, HEAD]))
                                    for rid in range(1, rng.randint(20, 200)))
                    s.sendall(data)
                    s.shutdown(socket.SHUT_WR)
                    drain_check(s, ctx, data)
            except OSError:
                pass
            finally:
                s.close()
            if n % 50 == 49:
                alive(srv, ctx)
                if srv.sanitizer():
                    break
        alive(srv, "server final")
        time.sleep(0.5)
        san = srv.sanitizer()
        if san:
            fail("server: sanitizer output:\n  " + "\n  ".join(san[:20]))
        if srv.p.poll() is not None:
            fail("server: bserve parent exited with %r" % srv.p.returncode)
    finally:
        srv.stop()
        os.chmod(os.path.join(base, "root", "locked"), 0o755)
        shutil.rmtree(base, ignore_errors=True)
    print("server fuzz: %d cases, %d connections, %.1fs, seed %d" %
          (cases, stats["connections"], time.time() - t0, seed))


# ---- targeted checks against bserve ----------------------------------------

def checks():
    base = tempfile.mkdtemp(prefix="netchecks-")
    root = make_root(base)
    srv = Bserve(root, idle=2)
    t0 = time.time()
    try:
        expect = {
            "/hello.txt": 200, "/inlink": 200, "/esc": 404, "/etc/passwd": 404,
            "/etc/": 404, "/sib/secret.txt": 404, "/loop": 404, "/dangling": 404,
            "/fifo": 404, "/.hidden": 404, "/...": 404, "/%2e%2e": 200,
            "/../secret.txt": 400, "/./hello.txt": 400, "/sub/..": 400, "/sub/.": 400,
            "//hello.txt": 200, "/sub": 301, "/sub/": 200, "/noindex/": 404,
            "/noindex": 301, "/hello.txt/": 404, "/unreadable.txt": 403,
            "/locked/": 403, "/?/../..": 200, "/hello.txt?../../secret": 200,
            "hello.txt": 400, "?x": 400, "/a\x00b": 400, "/a\x7f": 400, "/a\x1fb": 400,
            "/\xc0\xae\xc0\xae/secret.txt": 404, "/sub\\..\\..\\secret.txt": 404,
        }
        for path, want in expect.items():
            r, why = get(srv, path.encode("latin-1"), ctx="check " + repr(path))
            got = r[0] if r else why
            if got != want:
                fail("check %r: expected %s, got %s" % (path, want, got))
            if r and b"SECRET" in r[2]:
                fail("check %r: served a file outside ROOT" % path)
        # HEAD of the same: same headers, END, no DATA (validated by the checker)
        for path in ["/hello.txt", "/sub", "/nope", "/../x", "/unreadable.txt"]:
            get(srv, path.encode(), HEAD, ctx="HEAD " + path)
        # length boundaries: content-length, DATA sizes (checked), exact bytes
        for name, n in [("z0", 0), ("b16383", 16383), ("b16384", 16384), ("b16385", 16385),
                        ("b65535", 65535), ("big.bin", 1 << 20)]:
            r, why = get(srv, "/" + name, ctx="size " + name)
            if r is None or len(r[2]) != n or hdr(r[1], "content-length") != str(n):
                fail("size %s: %s %r" % (name, why, r and (r[0], len(r[2]), hdr(r[1], "content-length"))))
        # very long paths
        for n in [900, 1100, 4100, 16381]:
            r, why = get(srv, "/" + "a" * (n - 1), ctx="long path %d" % n, host=False)
            if r is None or r[0] != 404:
                fail("long path %d: %s %r" % (n, why, r and r[0]))
        r, why = get(srv, "/" + "a/" * 8189, ctx="many segments", host=False)
        if r is None or r[0] not in (404,):
            fail("many segments: %s %r" % (why, r and r[0]))
        # REQUEST payload of 16384 exactly, and 16385 (connection error)
        s = srv.connect()
        p = b"/" + b"q" * (16384 - 4)
        s.sendall(frame(REQUEST, END, 1, bytes([GET]) + struct.pack(">H", len(p)) + p))
        r, why = read_response(s, 1, "16384-byte REQUEST")
        if r is None or r[0] != 404:
            fail("16384-byte REQUEST: %s %r" % (why, r and r[0]))
        s.sendall(struct.pack(">HBBI", 16385, REQUEST, END, 2) + b"\x01" * 16385)
        r, why = read_response(s, 0, "16385-byte REQUEST")
        if r is None or r[0] != 400:
            fail("16385 Length: expected 400 id 0, got %s %r" % (why, r and r[0]))
        f, why = read_frame(s, 5)
        if f is None or f[0] != GOAWAY or f[3][4:5] != b"\x01":
            fail("16385 Length: expected GOAWAY 0x01, got %r %s" % (f and f[:3], why))
        s.close()
        # header count / literal length overflow
        many = b"".join(field("x-%d" % (i % 10), "") for i in range(16000 // 7))
        s = srv.connect()
        s.sendall(req(1, "/hello.txt", GET, many))
        r, why = read_response(s, 1, "many headers")
        if r is None or r[0] != 200:
            fail("2285 header entries: %s %r" % (why, r and r[0]))
        for bad in [b"\x00\xff" + b"a" * 10, b"\x00\x05ab", b"\x01\xff\xff" + b"v" * 10,
                    b"\x00\x00\x00\x00", b"\x0b\x00\x00", b"\x00\x01A\x00\x00",
                    b"\x01\x00\x01\n", field("content-length", "3") + field("content-length", "03"),
                    field("content-length", "99999999999999999999"), field("content-length", "")]:
            s.sendall(req(2, "/hello.txt", GET, bad))
            r, why = read_response(s, 2, "bad block %r" % bad[:12])
            if r is None or r[0] != 400:
                fail("bad header block %r: expected 400, got %s %r" % (bad[:12], why, r and r[0]))
        s.close()
        # request bodies: unknown frame inside body is skipped, content-length mismatch is 400
        s = srv.connect()
        s.sendall(req(1, "/hello.txt", POST, field("content-length", "5"), flags=0) +
                  frame(0x42, 1, 0, b"zz") + frame(DATA, 0, 1, b"ab") + frame(DATA, END, 1, b"cde"))
        r, why = read_response(s, 1, "body ok")
        if r is None or r[0] != 405:
            fail("POST with body: expected 405, got %s %r" % (why, r and r[0]))
        s.sendall(req(2, "/hello.txt", POST, field("content-length", "5"), flags=0) +
                  frame(DATA, END, 2, b"abcd"))
        r, why = read_response(s, 2, "body short")
        if r is None or r[0] != 400:
            fail("content-length 5 with 4-byte body: expected 400, got %s %r" % (why, r and r[0]))
        s.close()
        # slowloris: one byte per 0.4 s must still hit the 2 s idle deadline
        s = srv.connect()
        t1 = time.time()
        data = req(1, "/hello.txt")
        got = None
        for i in range(len(data) - 1):
            try:
                s.sendall(data[i:i + 1])
            except OSError:
                break
            s.settimeout(0.4)
            try:
                got = s.recv(100)
                break
            except socket.timeout:
                pass
        dt = time.time() - t1
        if not got or got[2:3] != b"\x04" or dt > 4:
            fail("slowloris: expected GOAWAY within ~2 s, got %r after %.1fs" % (got, dt))
        s.close()
        # fd / memory leak over thousands of requests on one connection
        s = srv.connect()
        time.sleep(0.2)
        kids = srv.children()
        def fds(pid):
            out = subprocess.run(["lsof", "-p", str(pid)], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, universal_newlines=True).stdout
            return len(out.splitlines())
        def rss(pid):
            out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], stdout=subprocess.PIPE,
                                 universal_newlines=True).stdout.strip()
            return int(out or 0)
        child = kids[-1] if kids else None
        parent_fd0 = fds(srv.p.pid)
        before = (fds(child), rss(child)) if child else (0, 0)
        paths = ["/hello.txt", "/nope", "/sub", "/b16385", "/unreadable.txt", "/esc"]
        chk = ServerChecker("leak loop")
        for i in range(1, 3001):
            s.sendall(req(i, paths[i % len(paths)], GET if i % 3 else HEAD))
            r, why = read_response(s, i, "leak loop", head=(i % 3 == 0), chk=chk)
            if r is None:
                fail("leak loop request %d: %s" % (i, why))
                break
        after = (fds(child), rss(child)) if child else (0, 0)
        s.close()
        for i in range(1000):
            try:
                c = srv.connect()
                c.sendall(req(1, "/hello.txt"))
                read_response(c, 1, "conn loop")
                c.close()
            except OSError as e:
                fail("connection loop %d: %s" % (i, e))
                break
        time.sleep(1)
        parent_fd1 = fds(srv.p.pid)
        print("leaks: child fds %d -> %d, child RSS %d KiB -> %d KiB over 3000 requests; "
              "parent fds %d -> %d over 1000 connections; children now %d" %
              (before[0], after[0], before[1], after[1], parent_fd0, parent_fd1,
               len(srv.children())))
        if after[0] > before[0] + 2:
            fail("fd leak in connection process: %d -> %d" % (before[0], after[0]))
        if parent_fd1 > parent_fd0 + 2:
            fail("fd leak in listener: %d -> %d" % (parent_fd0, parent_fd1))
        alive(srv, "checks final")
        san = srv.sanitizer()
        if san:
            fail("checks: sanitizer output:\n  " + "\n  ".join(san[:20]))
    finally:
        srv.stop()
        os.chmod(os.path.join(root, "locked"), 0o755)
        shutil.rmtree(base, ignore_errors=True)
    # search-only directories (mode 0311: lookups allowed, listing not), as
    # in a classic public_html; path lookup needs only search permission
    base = tempfile.mkdtemp(prefix="netchecks-")
    root = make_root(base)
    pub = os.path.join(root, "pub")
    os.mkdir(pub)
    with open(os.path.join(pub, "file.txt"), "w") as f:
        f.write("pub\n")
    os.chmod(pub, 0o311)
    os.chmod(root, 0o311)
    srv = None
    try:
        try:
            srv = Bserve(root)
        except RuntimeError as e:
            fail("ROOT mode 0311: bserve does not start: %s" % str(e).strip().splitlines()[-1])
        if srv:
            for path, want in (("/hello.txt", 200), ("/pub/file.txt", 200), ("/pub", 301)):
                r, why = get(srv, path.encode(), ctx="search-only " + path)
                if r is None or r[0] != want:
                    fail("search-only dir: %s expected %d, got %s" % (path, want, r[0] if r else why))
            os.chmod(root, 0)
            r, why = get(srv, "/hello.txt", ctx="root 000")
            print("ROOT mode 000 after start: /hello.txt -> %s" % (r[0] if r else why))
            if srv.sanitizer():
                fail("unreadable ROOT: sanitizer output")
    finally:
        os.chmod(root, 0o755)
        os.chmod(pub, 0o755)
        if srv:
            srv.stop()
        os.chmod(os.path.join(root, "locked"), 0o755)
        shutil.rmtree(base, ignore_errors=True)
    print("checks: %.1fs" % (time.time() - t0))


# ---- malicious server vs bcurl ---------------------------------------------

def run_bcurl(script, urls, timeout=45, hold=0.0, verbose=True):
    """script(conn, rng) talks to bcurl; returns (exit, stdout, stderr, secs)."""
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    port = ls.getsockname()[1]
    env = dict(os.environ, ASAN_OPTIONS="halt_on_error=1",
               UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1")
    args = [BCURL] + (["-v"] if verbose else []) + ["127.0.0.1:%d%s" % (port, u) for u in urls]
    t0 = time.time()
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    def serve():
        ls.settimeout(10)
        try:
            c, _ = ls.accept()
        except OSError:
            return
        try:
            script(c)
            time.sleep(hold)
        except OSError:
            pass
        finally:
            c.close()
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        ls.close()
        return None, out, err, time.time() - t0
    ls.close()
    return p.returncode, out, err, time.time() - t0


def answer(frames_for):
    """Script: for each request bcurl sends, write frames_for(id)."""
    def script(c):
        rid = 0
        while True:
            f, why = read_frame(c, 10)
            if f is None:
                return
            rid = f[2]
            data = frames_for(rid)
            if data is None:
                return
            c.settimeout(None)   # a socket timeout bounds the whole sendall
            c.sendall(data)
    return script


OKF = (field("content-type", "text/plain") + field("content-length", "5"))


def client_scenarios():
    big = 20 * 1024 * 1024
    def huge(rid):
        return resp(rid, 200, field("content-length", str(big))) + b"".join(
            frame(DATA, 0, rid, b"z" * 16384) for _ in range(big // 16384)) + \
            frame(DATA, END, rid, b"")
    return [
        ("ok", answer(lambda r: resp(r, 200, OKF) + frame(DATA, END, r, b"hello")), 0),
        ("unknown types everywhere", answer(lambda r: frame(0x42, 0xff, 0, b"x" * 300) +
            frame(0xff, 1, r, b"") + resp(r, 200, OKF) + frame(0x05, 0xfe, 99, b"q") +
            frame(DATA, 0, r, b"he") + frame(0x80, 1, r, b"") + frame(DATA, END, r, b"llo")), 0),
        ("unknown 16384-byte frame", answer(lambda r: frame(0x7f, 1, r, b"u" * 16384) +
            resp(r, 200, b"", END)), 0),
        ("content-length too big", answer(lambda r: resp(r, 200, field("content-length", "6")) +
            frame(DATA, END, r, b"hello")), 2),
        ("content-length too small", answer(lambda r: resp(r, 200, field("content-length", "4")) +
            frame(DATA, END, r, b"hello")), 2),
        ("conflicting content-length", answer(lambda r: resp(r, 200, field("content-length", "5") +
            field("content-length", "05", True)) + frame(DATA, END, r, b"hello")), 2),
        ("content-length 20 digits", answer(lambda r: resp(r, 200, field("content-length", "0" * 20),
            END)), 2),
        ("content-length with END", answer(lambda r: resp(r, 200, field("content-length", "5"), END)), 2),
        ("Length 16385", answer(lambda r: struct.pack(">HBBI", 16385, DATA, 1, r) + b"x" * 16385), 2),
        ("Length 65535 unknown", answer(lambda r: struct.pack(">HBBI", 65535, 0x42, 0, 0)), 2),
        ("RESPONSE id 0", answer(lambda r: resp(0, 400, b"", END)), 2),
        ("RESPONSE wrong id", answer(lambda r: resp(r + 1, 200, b"", END)), 2),
        ("DATA wrong id", answer(lambda r: resp(r, 200) + frame(DATA, END, r + 7, b"")), 2),
        ("DATA before RESPONSE", answer(lambda r: frame(DATA, END, r, b"x")), 2),
        ("second RESPONSE", answer(lambda r: resp(r, 200) + resp(r, 200, b"", END)), 2),
        ("server REQUEST", answer(lambda r: req(r, "/")), 2),
        ("status 199", answer(lambda r: resp(r, 199, b"", END)), 2),
        ("status 600", answer(lambda r: resp(r, 600, b"", END)), 2),
        ("status 65535", answer(lambda r: resp(r, 65535, b"", END)), 2),
        ("short RESPONSE", answer(lambda r: frame(RESPONSE, END, r, b"\x00")), 2),
        ("bad header index", answer(lambda r: resp(r, 200, b"\x0b\x00\x00", END)), 2),
        ("header value CR", answer(lambda r: resp(r, 200, field("server", "a\rb"), END)), 2),
        ("uppercase literal", answer(lambda r: resp(r, 200, field("X-A", "1", True), END)), 2),
        ("literal runs past", answer(lambda r: resp(r, 200, b"\x00\xff" + b"a" * 10, END)), 2),
        ("GOAWAY before END", answer(lambda r: resp(r, 200) + frame(GOAWAY, 0, 0, b"\0\0\0\0\0")), 2),
        ("short GOAWAY", answer(lambda r: frame(GOAWAY, 0, 0, b"")), 2),
        ("EOF mid-header", answer(lambda r: resp(r, 200)[:5]), 2),
        ("EOF mid-payload", answer(lambda r: resp(r, 200, OKF)[:-3]), 2),
        ("EOF mid-body", answer(lambda r: resp(r, 200) + frame(DATA, 0, r, b"abc")), 2),
        ("EOF before anything", answer(lambda r: None), 2),
        ("404", answer(lambda r: resp(r, 404, b"", END)), 4),
        ("503", answer(lambda r: resp(r, 503, b"", END)), 5),
        ("301", answer(lambda r: resp(r, 301, field("location", "/d/"), END)), 0),
        ("huge 20 MiB body", answer(huge), 0),
        ("overrun: content-length 5, 1 MiB body", answer(lambda r: resp(r, 200,
            field("content-length", "5")) + b"".join(frame(DATA, 0, r, b"o" * 16384)
            for _ in range(64)) + frame(DATA, END, r, b"")), 2),
    ]


def multi_scenarios():
    def worst(r):
        return resp(r, [404, 500, 200][r - 1], b"", END)
    def goaway_between(r):
        return resp(r, 200, b"", END) + (frame(GOAWAY, 0, 0, struct.pack(">IB", 1, 0)) if r == 1 else b"")
    def junk_between(r):
        return resp(r, 200, b"", END) + (frame(DATA, END, 1, b"late") if r == 1 else b"")
    return [
        ("404 then 500 then 200", answer(worst), ["/a", "/b", "/c"], 5),
        ("GOAWAY between requests", answer(goaway_between), ["/a", "/b", "/c"], 2),
        ("stray DATA after response", answer(junk_between), ["/a", "/b"], 2),
    ]


def fuzz_client(cases, seed):
    rng = random.Random(seed)
    t0 = time.time()
    count = 0
    for name, script, want in client_scenarios():
        code, out, err, dt = run_bcurl(script, ["/x"], verbose=not name.startswith("huge"))
        count += 1
        san = [l for l in err.decode("latin-1").splitlines() if any(m in l for m in SAN)]
        if san:
            fail("bcurl %s: sanitizer: %s" % (name, san[:3]))
        if code != want:
            fail("bcurl %s: exit %r, expected %d (%.1fs) %s" % (name, code, want, dt,
                 [l for l in err.decode("latin-1").splitlines() if l.startswith("bcurl:")][-1:]))
        if name.startswith("overrun") and len(out) > 5:
            fail("bcurl %s: wrote %d bytes to stdout past content-length 5 before failing"
                 % (name, len(out)))
        if name == "huge 20 MiB body" and len(out) != 20 * 1024 * 1024:
            fail("bcurl huge body: stdout %d bytes" % len(out))
    for name, script, urls, want in multi_scenarios():
        code, out, err, dt = run_bcurl(script, urls)
        count += 1
        if code != want:
            fail("bcurl %s: exit %r, expected %d" % (name, code, want))
    # random / mutated server streams
    good = lambda r: (resp(r, 200, OKF) + frame(0x42, 0, 0, b"k") + frame(DATA, 0, r, b"he") +
                      frame(DATA, END, r, b"llo"))
    for n in range(cases):
        if n % 3 == 0:
            blob = os.urandom(rng.randint(0, 3000))
        else:
            blob = mutate(rng, good(1) + good(2))
        def script(c, blob=blob):
            read_frame(c, 5)
            c.sendall(blob)
        code, out, err, dt = run_bcurl(script, ["/a", "/b"], timeout=40)
        count += 1
        san = [l for l in err.decode("latin-1").splitlines() if any(m in l for m in SAN)]
        if san or code not in (0, 2, 4, 5):
            fail("bcurl random case %d seed %d: exit %r san %s blob %s" %
                 (n, seed, code, san[:2], blob[:64].hex()))
    print("client fuzz: %d bcurl runs, %.1fs, seed %d" % (count, time.time() - t0, seed))


def client_slow():
    """Timeouts: a server that drips one byte at a time, and one that sends an
    unknown frame every 5 s for 70 s (each frame restarts bcurl's 30 s timer)."""
    def drip(c):
        read_frame(c, 5)
        for b in resp(1, 200, OKF):
            c.sendall(bytes([b]))
            time.sleep(3)
    def keepalive(c):
        read_frame(c, 5)
        for _ in range(14):
            c.sendall(frame(0x42, 0, 0, b""))
            time.sleep(5)
    res = {}
    def go(name, script):
        res[name] = run_bcurl(script, ["/x"], timeout=75)
    ts = [threading.Thread(target=go, args=a) for a in (("drip", drip), ("keepalive", keepalive))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    for name, (code, out, err, dt) in res.items():
        print("bcurl vs %s server: exit %r after %.1fs" % (name, code, dt))
        if code is None or dt > 60:
            fail("bcurl vs %s server: ran %.0fs although its timeout is 30 s; it only stops when "
                 "the server closes (no overall deadline)" % (name, dt))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["server", "client", "checks", "slow", "all"])
    ap.add_argument("--cases", type=int, default=400)
    ap.add_argument("--seed", type=int, default=int(time.time()) % 100000)
    a = ap.parse_args()
    if a.mode in ("server", "all"):
        fuzz_server(a.cases, a.seed)
    if a.mode in ("checks", "all"):
        checks()
    if a.mode in ("client", "all"):
        fuzz_client(max(1, a.cases // 4), a.seed)
    if a.mode in ("slow", "all"):
        client_slow()
    print("%d finding(s)" % len(FAILS))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
