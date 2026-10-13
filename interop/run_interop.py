#!/usr/bin/env python3
"""Interop matrix for bhttp/1: the C pair (bserve, bcurl) against the
independent Python pair (pybserve, pybcurl), plus raw-frame conformance checks.

    python3 interop/run_interop.py [--slow] [--only C|Py] [--keep]

Builds the C programs with `make` if needed, generates the test files in a
temporary directory, picks free ports, and kills every server it starts.
Exit status is 0 only if every test passed.

Sections:
  0. Reference bytes: the SPEC.md §10 example and the HEXDUMP.md capture are
     decoded and re-encoded by the Python codec and must match byte for byte.
  1. Pairing matrix: every client against every server, through a frame-aware
     TCP proxy that counts connections and frames, and can inject unknown frame
     types or corrupt one frame to provoke an error.
  2. Server conformance: hand-built frames sent straight to each server.
  3. Client conformance: each client against a scripted server that misbehaves
     in the ways SPEC.md §7 "Clients" lists.
"""

import argparse
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable, Dict, List, NamedTuple, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import pybhttp as bh  # noqa: E402
from pybhttp import DATA, FLAG_END, GOAWAY, MAX_PAYLOAD, REQUEST, RESPONSE, Frame  # noqa: E402

HOST = "127.0.0.1"
PY = sys.executable or "python3"
CLIENT_TIMEOUT = 20.0
GET, HEAD, POST = 0x01, 0x02, 0x03


class TestFail(Exception):
    pass


class Skip(Exception):
    pass


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise TestFail(msg)


# ---------------------------------------------------------------------------
# Implementations under test
# ---------------------------------------------------------------------------

class ServerImpl(NamedTuple):
    name: str
    argv: Callable[..., List[str]]  # (root, port, idle_seconds=None, max_connections=None)


class ClientImpl(NamedTuple):
    name: str
    argv: Callable[[bool, List[str]], List[str]]
    url: Callable[[int, str], str]


# Reference-client exit codes (SPEC.md §11); both clients follow them.
EXIT_OK, EXIT_USAGE, EXIT_FAILED, EXIT_4XX, EXIT_5XX = 0, 1, 2, 4, 5


def _url(port: int, path: str) -> str:
    return "bhttp://%s:%d%s" % (HOST, port, path)


def _opt(flag: str, value: Optional[int]) -> List[str]:
    return [flag, str(value)] if value else []


SERVERS = {
    "C": ServerImpl("C", lambda root, port, idle=None, cap=None:
                    [os.path.join(REPO, "bserve")] + _opt("-t", idle) + _opt("-c", cap)
                    + [root, str(port)]),
    "Py": ServerImpl("Py", lambda root, port, idle=None, cap=None:
                     [PY, os.path.join(HERE, "pybserve.py")] + _opt("--idle", idle) + _opt("-c", cap)
                     + [root, str(port)]),
}
CLIENTS = {
    "C": ClientImpl("C", lambda v, urls: [os.path.join(REPO, "bcurl")] + (["-v"] if v else []) + urls,
                    _url),
    "Py": ClientImpl("Py", lambda v, urls: [PY, os.path.join(HERE, "pybcurl.py")] + (["-v"] if v else []) + urls,
                     _url),
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def free_port() -> int:
    s = socket.socket()
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def raw_frame(ftype: int, flags: int, rid: int, payload: bytes = b"") -> bytes:
    """Like bh.encode_frame but without the size check, so tests can lie."""
    return bh.HEADER.pack(len(payload) & 0xFFFF, ftype, flags, rid) + payload


def request_payload(path: bytes, method: int = GET, headers: Optional[bh.Headers] = None) -> bytes:
    hdrs = headers if headers is not None else [("host", b"%s" % HOST.encode())]
    return struct.pack("!BH", method, len(path)) + path + bh.encode_headers(hdrs)


class ClientRun(NamedTuple):
    code: Optional[int]  # None if it had to be killed
    out: bytes
    err: bytes


def run_client(impl: ClientImpl, port: int, paths: List[str], verbose: bool = False) -> ClientRun:
    return run_argv(impl.argv(verbose, [impl.url(port, p) for p in paths]))


def run_argv(argv: List[str]) -> ClientRun:
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=CLIENT_TIMEOUT)
        return ClientRun(p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired as exc:
        return ClientRun(None, exc.stdout or b"", exc.stderr or b"")


def short(data: bytes, n: int = 120) -> str:
    text = data.decode("utf-8", "replace").strip().replace("\n", " | ")
    return text[:n] + ("..." if len(text) > n else "")


def expect_success(run: ClientRun, want: bytes) -> None:
    check(run.code is not None, "client hung (killed after %ds)" % CLIENT_TIMEOUT)
    check(run.code == 0, "exit %s, want 0; stderr: %s" % (run.code, short(run.err)))
    check(run.out == want, "stdout is %d bytes, want %d (first diff at %s)"
          % (len(run.out), len(want), first_diff(run.out, want)))


def expect_exit(run: ClientRun, want: int, what: str) -> None:
    check(run.code is not None, "client hung (killed after %ds)" % CLIENT_TIMEOUT)
    check(run.code >= 0, "client died from signal %d" % -run.code)
    check(run.code == want, "exit %d for %s, §11 says %d; stderr: %s"
          % (run.code, what, want, short(run.err)))


def expect_protocol_error(run: ClientRun) -> None:
    expect_exit(run, EXIT_FAILED, "a protocol error")


def first_diff(a: bytes, b: bytes) -> str:
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return "byte %d" % i
    return "byte %d" % min(len(a), len(b))


# ---------------------------------------------------------------------------
# Test tree (generated at run time; nothing big is committed)
# ---------------------------------------------------------------------------

class Tree(NamedTuple):
    base: str
    root: str
    files: Dict[str, bytes]


def make_tree() -> Tree:
    base = tempfile.mkdtemp(prefix="bhttp-interop-")
    root = os.path.join(base, "root")
    os.makedirs(os.path.join(root, "sub"))
    os.makedirs(os.path.join(root, "idxdir", "index.html"))  # index.html that is a directory
    os.makedirs(os.path.join(base, "outside"))
    rnd = random.Random(1)
    files = {
        "/small.txt": b"Hello, bhttp!\nThe only thing that crosses between us is the spec.\n",
        "/empty.txt": b"",
        "/big.bin": bytes(rnd.getrandbits(8) for _ in range(20 * MAX_PAYLOAD + 1234)),
        "/exact.bin": bytes(rnd.getrandbits(8) for _ in range(2 * MAX_PAYLOAD)),
        "/sub/index.html": b"<h1>sub index</h1>\n",
        "/sub/page.html": b"<p>page</p>\n",
        "/%2e%2e": b"a file literally named %2e%2e\n",
        "/.hidden": b"hidden\n",
        "/sub/.secret": b"secret\n",
        "/noread.txt": b"you may not read this\n",
    }
    for rel, data in files.items():
        with open(root + rel, "wb") as f:
            f.write(data)
    os.chmod(root + "/noread.txt", 0)
    with open(os.path.join(base, "outside", "secret.txt"), "wb") as f:
        f.write(b"outside the root\n")
    os.symlink("small.txt", os.path.join(root, "link_in"))
    os.symlink(os.path.join(base, "outside", "secret.txt"), os.path.join(root, "link_out"))
    os.symlink("../outside", os.path.join(root, "dir_out"))
    os.mkfifo(os.path.join(root, "fifo"))
    return Tree(base, root, files)


def remove_tree(tree: Tree) -> None:
    os.chmod(tree.root + "/noread.txt", 0o644)
    shutil.rmtree(tree.base, ignore_errors=True)


# ---------------------------------------------------------------------------
# Server processes
# ---------------------------------------------------------------------------

class RunningServer:
    def __init__(self, impl: ServerImpl, root: str, logdir: str,
                 idle: Optional[int] = None, cap: Optional[int] = None) -> None:
        self.impl = impl
        self.root = root
        self.idle = idle
        self.cap = cap
        self.log_path = os.path.join(logdir, "server-%s.log" % impl.name)
        self.proc: Optional[subprocess.Popen] = None
        self.port = 0
        self.crashes: List[str] = []

    def start(self) -> None:
        self.port = free_port()
        log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(self.impl.argv(self.root, self.port, self.idle, self.cap), stdout=log,
                                     stderr=log, stdin=subprocess.DEVNULL)
        log.close()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("%s server exited with %s at start-up (see %s)"
                                   % (self.impl.name, self.proc.returncode, self.log_path))
            try:
                socket.create_connection((HOST, self.port), timeout=1).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("%s server did not listen on port %d" % (self.impl.name, self.port))

    def check_alive(self, test: str) -> None:
        """Restart after a crash so one bug does not fail every later test."""
        assert self.proc is not None
        if self.proc.poll() is not None:
            self.crashes.append("%s (exit %s)" % (test, self.proc.returncode))
            self.start()
            raise TestFail("server process died (exit %s)" % self.proc.returncode)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


# ---------------------------------------------------------------------------
# Frame-aware proxy
# ---------------------------------------------------------------------------

def _unknown_frames() -> List[Tuple[int, int, Optional[int], bytes]]:
    """Unknown frames to inject: (type, flags, id or None for 'same as next frame', payload).

    Payloads include bytes that look like real frame headers, so a receiver that
    tries to resynchronise instead of skipping exactly Length bytes is caught.
    """
    fake_request = raw_frame(REQUEST, FLAG_END, 1, request_payload(b"/fake"))
    fake_data = raw_frame(DATA, FLAG_END, 1, b"WRONG")
    rnd = random.Random(7)
    return [
        (0x05, 0x00, None, b""),
        (0x7F, FLAG_END, 0, fake_data),
        (0x80, 0xFF, None, fake_request),
        (0xFF, FLAG_END, 0xFFFFFFFF, b"\x00"),
        (0x00, 0x00, None, bytes(rnd.getrandbits(8) for _ in range(300))),
        (0x42, FLAG_END, None, (fake_data * 2000)[:MAX_PAYLOAD]),
    ]


class Proxy:
    """Sits between a client and a server; counts connections, records frames.

    mode: None, "inject" (unknown frame before every frame, both directions),
    "bad_method" (first REQUEST gets method 0x63), "wrong_id" (RESPONSE IDs +1000),
    "fragment" (forward in 1-7 byte writes).
    """

    def __init__(self, upstream: int, mode: Optional[str] = None) -> None:
        self.upstream = upstream
        self.mode = mode
        self.connections = 0
        self.frames: List[Tuple[str, Frame]] = []
        self.lock = threading.Lock()
        self.unknown = _unknown_frames()
        self.injected = 0
        self.mutated = False
        self.lsock = socket.socket()
        self.lsock.bind((HOST, 0))
        self.lsock.listen(16)
        self.port = self.lsock.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def close(self) -> None:
        self.lsock.close()

    def _accept_loop(self) -> None:
        while True:
            try:
                down, _ = self.lsock.accept()
            except OSError:
                return
            with self.lock:
                self.connections += 1
            try:
                up = socket.create_connection((HOST, self.upstream))
            except OSError:
                down.close()
                continue
            for s in (down, up):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            done = threading.Semaphore(0)
            threading.Thread(target=self._pump, args=(down, up, "c2s", done), daemon=True).start()
            threading.Thread(target=self._pump, args=(up, down, "s2c", done), daemon=True).start()
            threading.Thread(target=self._closer, args=(down, up, done), daemon=True).start()

    @staticmethod
    def _closer(a: socket.socket, b: socket.socket, done: threading.Semaphore) -> None:
        done.acquire()
        done.acquire()
        a.close()
        b.close()

    def _pump(self, src: socket.socket, dst: socket.socket, direction: str,
              done: threading.Semaphore) -> None:
        buf = bytearray()
        passthrough = False
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                if passthrough:
                    dst.sendall(data)
                    continue
                buf += data
                out = bytearray()
                while len(buf) >= bh.HEADER_LEN:
                    length, ftype, flags, rid = bh.HEADER.unpack(bytes(buf[:8]))
                    if length > MAX_PAYLOAD:  # not ours to judge: pass it on raw
                        passthrough = True
                        out += buf
                        buf.clear()
                        break
                    if len(buf) < 8 + length:
                        break
                    frame = Frame(ftype, flags, rid, bytes(buf[8:8 + length]))
                    del buf[:8 + length]
                    with self.lock:
                        self.frames.append((direction, frame))
                    for f in self._transform(direction, frame):
                        out += raw_frame(*f)
                self._send(dst, bytes(out))
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            done.release()

    def _send(self, dst: socket.socket, data: bytes) -> None:
        if self.mode != "fragment":
            dst.sendall(data)
            return
        rnd = random.Random(len(data))
        pos = 0
        while pos < len(data):
            step = rnd.randint(1, 7)
            dst.sendall(data[pos:pos + step])
            pos += step
            time.sleep(0.0005)

    def _transform(self, direction: str, frame: Frame) -> List[Frame]:
        if self.mode == "inject":
            with self.lock:
                ftype, flags, rid, payload = self.unknown[self.injected % len(self.unknown)]
                self.injected += 1
            return [Frame(ftype, flags, frame.rid if rid is None else rid, payload), frame]
        if self.mode == "bad_method" and direction == "c2s" and frame.type == REQUEST \
                and not self.mutated:
            self.mutated = True
            return [frame._replace(payload=b"\x63" + frame.payload[1:])]
        if self.mode == "wrong_id" and direction == "s2c" and frame.type == RESPONSE:
            return [frame._replace(rid=frame.rid + 1000)]
        return [frame]

    # observations

    def s2c(self, ftype: int) -> List[Frame]:
        with self.lock:
            return [f for d, f in self.frames if d == "s2c" and f.type == ftype]

    def c2s(self, ftype: int) -> List[Frame]:
        with self.lock:
            return [f for d, f in self.frames if d == "c2s" and f.type == ftype]

    def statuses(self) -> List[Tuple[int, int]]:
        return [(f.rid, struct.unpack("!H", f.payload[:2])[0])
                for f in self.s2c(RESPONSE) if len(f.payload) >= 2]


# ---------------------------------------------------------------------------
# 1. Pairing matrix
# ---------------------------------------------------------------------------

def through_proxy(server: RunningServer, mode: Optional[str] = None) -> Proxy:
    return Proxy(server.port, mode)


def pair_small(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    px = through_proxy(srv)
    run = run_client(cli, px.port, ["/small.txt"])
    px.close()
    expect_success(run, tree.files["/small.txt"])
    check(px.statuses() == [(1, 200)], "statuses seen %s" % px.statuses())


def pair_404(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    px = through_proxy(srv)
    run = run_client(cli, px.port, ["/no-such-file.txt"])
    px.close()
    check(run.code is not None, "client hung")
    check(px.statuses() == [(1, 404)], "statuses seen %s, want [(1, 404)]" % px.statuses())
    expect_exit(run, EXIT_4XX, "a 404")


def pair_big(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    px = through_proxy(srv)
    run = run_client(cli, px.port, ["/big.bin"])
    px.close()
    want = tree.files["/big.bin"]
    expect_success(run, want)
    sizes = [len(f.payload) for f in px.s2c(DATA)]
    need = -(-len(want) // MAX_PAYLOAD)
    check(len(sizes) >= need, "%d DATA frames, want >= %d" % (len(sizes), need))
    check(max(sizes) <= MAX_PAYLOAD, "a DATA frame of %d bytes" % max(sizes))
    check(all(s == MAX_PAYLOAD for s in sizes[:-1]), "DATA frames not full before the last (SHOULD): %s"
          % sorted(set(sizes[:-1])))


def pair_exact(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    px = through_proxy(srv)
    run = run_client(cli, px.port, ["/exact.bin", "/empty.txt"])
    px.close()
    expect_success(run, tree.files["/exact.bin"])
    check(px.connections == 1, "%d connections" % px.connections)


KEEPALIVE = ["/small.txt", "/big.bin", "/sub/", "/empty.txt", "/link_in", "/%2e%2e", "/small.txt?q=1"]


def keepalive_body(tree: Tree) -> bytes:
    return b"".join(tree.files[p] for p in
                    ["/small.txt", "/big.bin", "/sub/index.html", "/empty.txt", "/small.txt",
                     "/%2e%2e", "/small.txt"])


def pair_keepalive(cli: ClientImpl, srv: RunningServer, tree: Tree, mode: Optional[str] = None,
                   paths: Optional[List[str]] = None, want: Optional[bytes] = None) -> None:
    px = through_proxy(srv, mode)
    run = run_client(cli, px.port, paths or KEEPALIVE)
    px.close()
    expect_success(run, want if want is not None else keepalive_body(tree))
    check(px.connections == 1, "%d TCP connections accepted, want 1" % px.connections)
    ids = [f.rid for f in px.c2s(REQUEST)]
    check(ids == list(range(1, len(ids) + 1)), "request IDs %s" % ids)


def pair_unknown(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    pair_keepalive(cli, srv, tree, mode="inject")


def pair_fragment(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    paths = ["/small.txt", "/sub/page.html", "/small.txt"]
    want = tree.files["/small.txt"] + tree.files["/sub/page.html"] + tree.files["/small.txt"]
    pair_keepalive(cli, srv, tree, mode="fragment", paths=paths, want=want)


def pair_bad_request(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    """Proxy turns request 1 into an unknown method: 400 on ID 1, connection kept, 2 works."""
    px = through_proxy(srv, "bad_method")
    run = run_client(cli, px.port, ["/small.txt", "/sub/page.html"])
    px.close()
    check(run.code is not None, "client hung")
    st = px.statuses()
    check(st[:1] == [(1, 400)], "statuses %s, want 400 for id 1" % st)
    check(st[1:] == [(2, 200)], "statuses %s, want 200 for id 2 on the same connection" % st)
    check(px.connections == 1, "%d connections" % px.connections)
    check(px.s2c(GOAWAY) == [], "server sent GOAWAY after a request error")
    check(run.out.endswith(tree.files["/sub/page.html"]), "page body missing from stdout")
    expect_exit(run, EXIT_4XX, "a 400 then a 200")


def pair_wrong_id(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    """Proxy rewrites the RESPONSE ID: the client must fail, not print the page."""
    px = through_proxy(srv, "wrong_id")
    run = run_client(cli, px.port, ["/small.txt"])
    px.close()
    expect_protocol_error(run)
    check(tree.files["/small.txt"] not in run.out, "printed the body of a mismatched response")


def pair_refused(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    run = run_client(cli, free_port(), ["/small.txt"])
    expect_exit(run, EXIT_FAILED, "connection refused")


def pair_verbose(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    px = through_proxy(srv)
    run = run_client(cli, px.port, ["/small.txt", "/big.bin"], verbose=True)
    px.close()
    expect_success(run, tree.files["/small.txt"] + tree.files["/big.bin"])
    check(len(run.err) > 0, "-v wrote nothing to stderr")


def pair_busy(cli: ClientImpl, srv: RunningServer, tree: Tree) -> None:
    """§2 BUSY: a client turned away at the cap fails with exit 2 and prints nothing."""
    with OwnServer(srv, tree, cap=1) as own:
        held = get_served(own.port, tree)
        try:
            run = run_client(cli, own.port, ["/small.txt"])
        finally:
            held.close()
    expect_exit(run, EXIT_FAILED, "a server at its connection cap")
    check(run.out == b"", "printed %r" % short(run.out))


PAIR_TESTS = [
    ("200 small file, byte-exact", pair_small),
    ("404 -> §11 exit 4", pair_404),
    ("large file, >1 DATA frame", pair_big),
    ("body of exactly 2x16384", pair_exact),
    ("7 URLs over one connection", pair_keepalive),
    ("unknown frames injected", pair_unknown),
    ("1-7 byte TCP segments", pair_fragment),
    ("malformed req -> 400, kept", pair_bad_request),
    ("wrong response ID -> error", pair_wrong_id),
    ("connection refused exit", pair_refused),
    ("server BUSY -> exit 2", pair_busy),
    ("-v keeps stdout clean", pair_verbose),
]


# ---------------------------------------------------------------------------
# 2. Server conformance (raw frames)
# ---------------------------------------------------------------------------

class Msg(NamedTuple):
    rid: int
    status: int
    headers: bh.Headers
    body: bytes
    data_sizes: List[int]
    flags: int


class Raw:
    def __init__(self, port: int, timeout: float = 5.0) -> None:
        self.sock = socket.create_connection((HOST, port), timeout=timeout)
        self.reader = bh.FrameReader(self.sock)

    def close(self) -> None:
        self.sock.close()

    def send(self, ftype: int, flags: int, rid: int, payload: bytes = b"") -> None:
        self.sock.sendall(raw_frame(ftype, flags, rid, payload))

    def get(self, rid: int, path: bytes, method: int = GET, flags: int = FLAG_END,
            headers: Optional[bh.Headers] = None) -> None:
        self.send(REQUEST, flags, rid, request_payload(path, method, headers))

    def frame(self) -> Frame:
        try:
            f = self.reader.read()
        except bh.IdleTimeout:
            raise TestFail("no frame within 5 s")
        except (ConnectionResetError, bh.TruncatedFrame) as exc:
            raise TestFail("connection broke: %s" % exc)
        if f is None:
            raise TestFail("connection closed by server")
        return f

    def message(self) -> Msg:
        f = self.frame()
        check(f.type == RESPONSE, "got %s, want RESPONSE" % bh.KNOWN_TYPES.get(f.type))
        try:
            status, headers = bh.decode_response(f.payload)
        except bh.Malformed as exc:
            raise TestFail("malformed RESPONSE: %s" % exc)
        body, sizes, end = bytearray(), [], f.end
        while not end:
            d = self.frame()
            check(d.type == DATA, "got %s inside a body" % bh.KNOWN_TYPES.get(d.type))
            check(d.rid == f.rid, "DATA id %d inside response %d" % (d.rid, f.rid))
            body += d.payload
            sizes.append(len(d.payload))
            end = d.end
        return Msg(f.rid, status, headers, bytes(body), sizes, f.flags)

    def expect(self, rid: int, status: int) -> Msg:
        m = self.message()
        check((m.rid, m.status) == (rid, status), "got %d on id %d, want %d on id %d"
              % (m.status, m.rid, status, rid))
        cl = [v for n, v in m.headers if n == "content-length"]
        if cl and not (m.flags & FLAG_END and m.body == b""):
            check(int(cl[0]) == len(m.body), "content-length %s but body %d" % (cl[0], len(m.body)))
        return m

    def expect_still_open(self, tree: Tree, rid: int = 99) -> None:
        self.get(rid, b"/small.txt")
        m = self.expect(rid, 200)
        check(m.body == tree.files["/small.txt"], "wrong body after the error")

    def expect_conn_error(self) -> None:
        """400 on ID 0, GOAWAY 0x01, then EOF (SPEC.md §7, §2)."""
        m = self.message()
        check((m.rid, m.status) == (0, 400), "got %d on id %d, want 400 on id 0" % (m.status, m.rid))
        g = self.frame()
        check(g.type == GOAWAY and g.rid == 0, "got %s id %d, want GOAWAY id 0"
              % (bh.KNOWN_TYPES.get(g.type), g.rid))
        last_id, code = bh.decode_goaway(g.payload)
        check(code == bh.GOAWAY_PROTOCOL_ERROR, "GOAWAY code %d, want 1" % code)
        self.expect_eof(6.0)

    def expect_eof(self, within: float) -> None:
        self.sock.settimeout(within)
        try:
            extra = self.reader.read()
        except bh.IdleTimeout:
            raise TestFail("connection not closed within %.0f s" % within)
        except ConnectionResetError:
            raise TestFail("connection reset instead of an orderly close")
        check(extra is None, "unexpected %s after GOAWAY" % (extra and bh.KNOWN_TYPES.get(extra.type)))


def srv_case(fn: Callable[[Raw, Tree], None]) -> Callable[[RunningServer, Tree], None]:
    def run(srv: RunningServer, tree: Tree) -> None:
        raw = Raw(srv.port)
        try:
            fn(raw, tree)
        finally:
            raw.close()
    return run


def request_error(payload: bytes, rid: int = 7, ftype: int = REQUEST) -> Callable[[Raw, Tree], None]:
    def fn(raw: Raw, tree: Tree) -> None:
        raw.send(ftype, FLAG_END, rid, payload)
        raw.expect(rid, 400)
        raw.expect_still_open(tree)
    return fn


def s_http1_text(raw: Raw, tree: Tree) -> None:
    raw.sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    raw.expect_conn_error()


def s_too_long(raw: Raw, tree: Tree) -> None:
    raw.get(1, b"/small.txt")
    raw.expect(1, 200)
    raw.get(2, b"/small.txt")
    raw.expect(2, 200)
    raw.sock.sendall(struct.pack("!HBBI", MAX_PAYLOAD + 1, DATA, 0, 3) + b"x" * (MAX_PAYLOAD + 1))
    m = raw.message()
    check((m.rid, m.status) == (0, 400), "got %d on id %d, want 400 on id 0" % (m.status, m.rid))
    g = raw.frame()
    check(g.type == GOAWAY, "want GOAWAY, got %s" % bh.KNOWN_TYPES.get(g.type))
    last_id, code = bh.decode_goaway(g.payload)
    check((last_id, code) == (2, 1), "GOAWAY last-id %d code %d, want 2 and 1" % (last_id, code))
    raw.expect_eof(6.0)


def s_too_long_unknown(raw: Raw, tree: Tree) -> None:
    raw.sock.sendall(struct.pack("!HBBI", 0xFFFF, 0x99, 0, 0))
    raw.expect_conn_error()


def s_conn_error_body(raw: Raw, tree: Tree) -> None:
    raw.get(1, b"/small.txt", method=POST, flags=0)
    raw.send(DATA, 0, 1, b"part one")
    raw.send(DATA, FLAG_END, 2, b"wrong id")
    raw.expect_conn_error()


def s_request_in_body(raw: Raw, tree: Tree) -> None:
    raw.get(1, b"/small.txt", method=POST, flags=0)
    raw.get(2, b"/small.txt")
    raw.expect_conn_error()


def s_unknown_frames(raw: Raw, tree: Tree) -> None:
    raw.send(0x05, FLAG_END, 1, b"")
    raw.send(0x80, 0xFF, 0, raw_frame(REQUEST, FLAG_END, 1, request_payload(b"/fake")))
    raw.get(1, b"/small.txt")
    m = raw.expect(1, 200)
    check(m.body == tree.files["/small.txt"], "wrong body")
    raw.get(2, b"/sub/page.html", method=GET, flags=0)  # GET with a body
    raw.send(0x7F, FLAG_END, 2, b"not the end")
    raw.send(DATA, 0, 2, b"abc")
    raw.send(0xFF, 0, 2, b"\x00" * MAX_PAYLOAD)
    raw.send(DATA, FLAG_END, 2, b"")
    m = raw.expect(2, 200)
    check(m.body == tree.files["/sub/page.html"], "wrong body")


def s_ids_copied(raw: Raw, tree: Tree) -> None:
    for rid in (0xFFFFFFFF, 5, 3):
        raw.get(rid, b"/small.txt")
        raw.expect(rid, 200)


def s_flag_bits(raw: Raw, tree: Tree) -> None:
    raw.get(1, b"/small.txt", flags=0xFF)
    raw.expect(1, 200)


def s_literal_headers(raw: Raw, tree: Tree) -> None:
    hdrs = bh.encode_headers([("x-a", b"1")]) + b"\x00\x04host" + b"\x00\x01h" + \
        b"\x00\x0auser-agent\x00\x00"
    raw.send(REQUEST, FLAG_END, 1, struct.pack("!BH", GET, 10) + b"/small.txt" + hdrs)
    raw.expect(1, 200)


def s_no_headers(raw: Raw, tree: Tree) -> None:
    raw.send(REQUEST, FLAG_END, 1, b"\x01\x00\x0a/small.txt")
    raw.expect(1, 200)


def s_head(raw: Raw, tree: Tree) -> None:
    raw.get(1, b"/big.bin", method=HEAD)
    m = raw.expect(1, 200)
    check(bool(m.flags & FLAG_END) and not m.data_sizes, "HEAD response has DATA / no END")
    cl = dict(m.headers).get("content-length")
    check(cl == str(len(tree.files["/big.bin"])).encode(), "HEAD content-length %r" % cl)
    raw.expect_still_open(tree)


def s_405(raw: Raw, tree: Tree) -> None:
    raw.get(1, b"/small.txt", method=POST, flags=0)
    raw.send(DATA, 0, 1, b"x" * MAX_PAYLOAD)
    raw.send(DATA, FLAG_END, 1, b"tail")
    m = raw.expect(1, 405)
    allow = [v for n, v in m.headers if n == "allow"]
    check(allow == [b"GET, HEAD"], "allow %r" % allow)
    raw.expect_still_open(tree)


def s_bad_request_with_body(raw: Raw, tree: Tree) -> None:
    raw.send(REQUEST, 0, 4, struct.pack("!BH", 0x63, 2) + b"/x")
    raw.send(DATA, 0, 4, b"body")
    raw.send(DATA, FLAG_END, 4, b"end")
    raw.expect(4, 400)
    raw.expect_still_open(tree)


def path_status(path: bytes, status: int, body_key: Optional[str] = None,
                location: Optional[bytes] = None) -> Callable[[Raw, Tree], None]:
    def fn(raw: Raw, tree: Tree) -> None:
        raw.get(1, path)
        m = raw.expect(1, status)
        if body_key:
            check(m.body == tree.files[body_key], "wrong body (%d bytes)" % len(m.body))
        if location is not None:
            loc = [v for n, v in m.headers if n == "location"]
            check(loc == [location], "location %r, want %r" % (loc, location))
        raw.expect_still_open(tree)
    return fn


def s_fifo(raw: Raw, tree: Tree) -> None:
    """A server that open()s the FIFO before checking its type blocks; unblock it after."""
    try:
        path_status(b"/fifo", 404)(raw, tree)
    finally:
        try:
            fd = os.open(tree.root + "/fifo", os.O_WRONLY | os.O_NONBLOCK)
            os.close(fd)
        except OSError:
            pass  # no reader: nobody is stuck


def s_forbidden(raw: Raw, tree: Tree) -> None:
    if os.geteuid() == 0:
        raise Skip("running as root")
    path_status(b"/noread.txt", 403)(raw, tree)


def s_idle(raw: Raw, tree: Tree) -> None:
    raw.get(1, b"/small.txt")
    raw.expect(1, 200)
    raw.sock.settimeout(45)
    start = time.monotonic()
    g = raw.frame()
    waited = time.monotonic() - start
    check(g.type == GOAWAY, "want GOAWAY on idle, got %s" % bh.KNOWN_TYPES.get(g.type))
    check(bh.decode_goaway(g.payload) == (1, 0), "GOAWAY %s, want last-id 1 code 0"
          % (bh.decode_goaway(g.payload),))
    check(waited >= 10, "idle close after %.1f s (SHOULD be >= 10)" % waited)
    raw.expect_eof(6.0)


def s_truncated(raw: Raw, tree: Tree) -> None:
    raw.sock.sendall(b"\x00\x10\x01")
    raw.sock.shutdown(socket.SHUT_WR)
    raw.expect_eof(5.0)


def s_client_goaway(raw: Raw, tree: Tree) -> None:
    raw.get(1, b"/small.txt")
    raw.expect(1, 200)
    raw.send(GOAWAY, 0, 0, bh.encode_goaway(0, 0))
    raw.expect_eof(5.0)


def s_client_goaway_id(raw: Raw, tree: Tree) -> None:
    """§4: a GOAWAY's Request ID is ignored on receipt."""
    raw.get(1, b"/small.txt")
    raw.expect(1, 200)
    raw.send(GOAWAY, 0, 7, bh.encode_goaway(0, 0))
    raw.expect_eof(5.0)


def conn_error(*frames: bytes) -> Callable[[Raw, Tree], None]:
    """Send these frames; expect 400 on ID 0, GOAWAY 0x01 and a close (§7)."""
    def fn(raw: Raw, tree: Tree) -> None:
        raw.sock.sendall(b"".join(frames))
        raw.expect_conn_error()
    return fn


POST_OPEN = raw_frame(REQUEST, 0, 1, request_payload(b"/small.txt", method=POST))


def s_goaway_in_body(raw: Raw, tree: Tree) -> None:
    """§7: a GOAWAY while a body is open simply ends the connection."""
    raw.sock.sendall(POST_OPEN + raw_frame(DATA, 0, 1, b"x")
                     + raw_frame(GOAWAY, 0, 0, bh.encode_goaway(0, 0)))
    raw.expect_eof(5.0)


def s_response_opens_no_body(raw: Raw, tree: Tree) -> None:
    """§6/§7: only a REQUEST opens a body, so the DATA after a RESPONSE is stray too."""
    raw.send(RESPONSE, 0, 9, b"\x00\xc8")
    raw.send(DATA, FLAG_END, 9, b"x")
    raw.expect(9, 400)
    raw.expect(9, 400)
    raw.expect_still_open(tree)


def cl(*values: bytes) -> bh.Headers:
    return [("content-length", v) for v in values]


def s_cl_body(values: List[bytes], body: bytes, status: int) -> Callable[[Raw, Tree], None]:
    """GET carrying a body in DATA frames, with the given content-length copies."""
    def fn(raw: Raw, tree: Tree) -> None:
        raw.send(REQUEST, 0, 1, request_payload(b"/small.txt", headers=cl(*values)))
        raw.send(DATA, 0, 1, body[:2])
        raw.send(DATA, FLAG_END, 1, body[2:])
        m = raw.expect(1, status)
        if status == 200:
            check(m.body == tree.files["/small.txt"], "wrong body")
        raw.expect_still_open(tree)
    return fn


def s_head_status(path: bytes, status: int) -> Callable[[Raw, Tree], None]:
    """§6: every response to HEAD, whatever its status, has END and no DATA."""
    def fn(raw: Raw, tree: Tree) -> None:
        raw.get(1, path, method=HEAD)
        m = raw.expect(1, status)
        check(bool(m.flags & FLAG_END) and not m.data_sizes, "HEAD %d response has DATA" % status)
        raw.expect_still_open(tree)
    return fn


IMF_FIXDATE = (r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d\d (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
               r"\d{4} \d\d:\d\d:\d\d GMT$")


def s_dates(raw: Raw, tree: Tree) -> None:
    """§5.3: date and last-modified are IMF-fixdate."""
    import re
    raw.get(1, b"/small.txt")
    m = raw.expect(1, 200)
    for name in ("date", "last-modified"):
        values = [v.decode("latin-1") for n, v in m.headers if n == name]
        check(len(values) == 1, "%d %s headers" % (len(values), name))
        check(re.match(IMF_FIXDATE, values[0]) is not None, "%s %r is not IMF-fixdate" % (name, values[0]))


def s_content_types(raw: Raw, tree: Tree) -> None:
    """§8: content-type follows the extension table."""
    want = {b"/small.txt": b"text/plain; charset=utf-8",
            b"/sub/page.html": b"text/html; charset=utf-8",
            b"/big.bin": b"application/octet-stream"}
    for rid, (path, ctype) in enumerate(want.items(), 1):
        raw.get(rid, path, method=HEAD)
        got = [v for n, v in raw.expect(rid, 200).headers if n == "content-type"]
        check(got == [ctype], "%s: content-type %r, want %r" % (path.decode(), got, ctype))


class OwnServer:
    """A server of the same implementation with its own -t / -c, stopped on exit."""

    def __init__(self, srv: RunningServer, tree: Tree, idle: Optional[int] = None,
                 cap: Optional[int] = None) -> None:
        self.server = RunningServer(srv.impl, tree.root, tree.base, idle=idle, cap=cap)

    def __enter__(self) -> RunningServer:
        self.server.start()
        time.sleep(0.3)  # let the start-up probe connection be reaped before counting
        return self.server

    def __exit__(self, *exc: object) -> None:
        self.server.stop()


def get_served(port: int, tree: Tree, within: float = 5.0) -> Raw:
    """Open a connection that gets a 200 (retrying while the server says BUSY)."""
    deadline = time.monotonic() + within
    last = ""
    while time.monotonic() < deadline:
        raw = Raw(port)
        try:
            raw.get(1, b"/small.txt")
            m = raw.expect(1, 200)
            check(m.body == tree.files["/small.txt"], "wrong body")
            return raw
        except TestFail as exc:
            last = str(exc)
            raw.close()
            time.sleep(0.2)
    raise TestFail("no connection was served within %.0f s (%s)" % (within, last))


def s_busy(srv: RunningServer, tree: Tree) -> None:
    """§2: beyond the cap, GOAWAY Last-ID 0 code BUSY, then close; a freed slot is reused."""
    with OwnServer(srv, tree, cap=2) as own:
        held = [get_served(own.port, tree) for _ in range(2)]
        try:
            extra = Raw(own.port)
            g = extra.frame()
            check(g.type == GOAWAY, "third connection got %s, want GOAWAY" % bh.KNOWN_TYPES.get(g.type))
            check(bh.decode_goaway(g.payload) == (0, bh.GOAWAY_BUSY), "GOAWAY %s, want last-id 0 BUSY"
                  % (bh.decode_goaway(g.payload),))
            extra.expect_eof(5.0)
            extra.close()
            held[0].close()
            get_served(own.port, tree).close()  # the slot comes back
            held[1].expect_still_open(tree)     # held connections are untouched
        finally:
            for raw in held:
                raw.close()


def idle_case(steps: Callable[[Raw, Callable[[], float]], int]) -> Callable[[RunningServer, Tree], None]:
    """Own server with T = 2 s.  `steps` drives the connection and returns the Last-ID
    the idle GOAWAY must carry; the GOAWAY must then come 1.5-3.5 s after its last step."""
    def run(srv: RunningServer, tree: Tree) -> None:
        with OwnServer(srv, tree, idle=2) as own:
            raw = Raw(own.port)
            try:
                start = time.monotonic()
                last_id = steps(raw, lambda: time.monotonic() - start)
                quiet_from = time.monotonic()
                raw.sock.settimeout(6)
                g = raw.frame()
                waited = time.monotonic() - quiet_from
                check(g.type == GOAWAY, "got %s, want the idle GOAWAY" % bh.KNOWN_TYPES.get(g.type))
                check(bh.decode_goaway(g.payload) == (last_id, 0), "GOAWAY %s, want last-id %d NO_ERROR"
                      % (bh.decode_goaway(g.payload), last_id))
                check(waited <= 3.5, "idle GOAWAY %.1f s after the last activity, T = 2 s" % waited)
            finally:
                raw.close()
    return run


def at(clock: Callable[[], float], when: float) -> None:
    time.sleep(max(0.0, when - clock()))


def idle_unknown(srv: RunningServer, tree: Tree) -> None:
    """Unknown frames every 0.4 s don't keep a connection: GOAWAY T after the REQUEST."""
    with OwnServer(srv, tree, idle=2) as own:
        raw = Raw(own.port)
        try:
            raw.get(1, b"/small.txt")
            raw.expect(1, 200)
            answered = time.monotonic()
            raw.sock.settimeout(0.4)
            while time.monotonic() - answered < 6:
                try:
                    raw.send(0x42, 0, 0, b"still here")
                    g = raw.frame()
                except (OSError, TestFail):
                    continue  # nothing yet
                waited = time.monotonic() - answered
                check(g.type == GOAWAY, "got %s, want the idle GOAWAY" % bh.KNOWN_TYPES.get(g.type))
                check(bh.decode_goaway(g.payload) == (1, 0), "GOAWAY %s, want last-id 1 NO_ERROR"
                      % (bh.decode_goaway(g.payload),))
                check(waited <= 3.5, "GOAWAY %.1f s after the REQUEST, T = 2 s" % waited)
                return
            raise TestFail("unknown frames kept the connection open for 6 s with T = 2 s")
        finally:
            raw.close()


def idle_requests(raw: Raw, clock: Callable[[], float]) -> int:
    """Four requests 1.3 s apart (3.9 s > T): each complete REQUEST resets T."""
    for rid in range(1, 5):
        at(clock, (rid - 1) * 1.3)
        raw.get(rid, b"/small.txt")
        raw.expect(rid, 200)
    return 4


def idle_body(raw: Raw, clock: Callable[[], float]) -> int:
    """A request body trickled over 3.9 s (> T): each DATA frame of it resets T."""
    raw.send(REQUEST, 0, 1, request_payload(b"/small.txt", method=POST))
    for i, when in enumerate((1.3, 2.6, 3.9)):
        at(clock, when)
        raw.send(DATA, FLAG_END if i == 2 else 0, 1, b"part")
    raw.expect(1, 405)
    return 1


def s_head_error(payload: bytes) -> Callable[[Raw, Tree], None]:
    """§6: a 400 to a REQUEST whose Method byte is HEAD has END and no DATA too."""
    def fn(raw: Raw, tree: Tree) -> None:
        raw.send(REQUEST, FLAG_END, 1, payload)
        m = raw.expect(1, 400)
        check(bool(m.flags & FLAG_END) and not m.data_sizes, "400 to HEAD has DATA")
        raw.expect_still_open(tree)
    return fn


def s_idle_trickle(srv: RunningServer, tree: Tree) -> None:
    """§2: bytes of a partial frame do not extend T (own server with T = 3 s)."""
    own = RunningServer(srv.impl, tree.root, tree.base, idle=3)
    own.start()
    try:
        sock = socket.create_connection((HOST, own.port), timeout=0.2)
        frame = raw_frame(REQUEST, FLAG_END, 1, request_payload(b"/small.txt"))
        start, got, sent = time.monotonic(), b"", 0
        while time.monotonic() - start < 8 and len(got) < 13:
            if sent < len(frame) and time.monotonic() - start >= sent * 0.8:
                try:
                    sock.sendall(frame[sent:sent + 1])
                    sent += 1
                except OSError:
                    break
            try:
                data = sock.recv(64)
                if not data:
                    break
                got += data
            except socket.timeout:
                pass
        waited = time.monotonic() - start
        sock.close()
        check(len(got) >= 13 and got[2] == GOAWAY, "no GOAWAY within 8 s (got %r)" % got[:16])
        check(bh.decode_goaway(got[8:13]) == (0, 0), "GOAWAY %s, want last-id 0 code 0"
              % (bh.decode_goaway(got[8:13]),))
        check(2.5 <= waited <= 4.5, "GOAWAY after %.1f s with T = 3 s" % waited)
    finally:
        own.stop()


SERVER_TESTS = [
    ("HTTP/1.1 text -> conn error", srv_case(s_http1_text)),
    ("Length 16385 -> 400/0, GOAWAY", srv_case(s_too_long)),
    ("unknown type, Length 65535", srv_case(s_too_long_unknown)),
    ("DATA other ID in body", srv_case(s_conn_error_body)),
    ("REQUEST while body open", srv_case(s_request_in_body)),
    ("RESPONSE same ID in body", srv_case(conn_error(POST_OPEN, raw_frame(RESPONSE, FLAG_END, 1, b"\x00\xc8")))),
    ("REQUEST same ID in body", srv_case(conn_error(POST_OPEN, raw_frame(REQUEST, FLAG_END, 1, request_payload(b"/"))))),
    ("GOAWAY in body: close", srv_case(s_goaway_in_body)),
    ("REQUEST with ID 0", srv_case(conn_error(raw_frame(REQUEST, FLAG_END, 0, request_payload(b"/small.txt"))))),
    ("REQUEST ID 0 without END", srv_case(conn_error(raw_frame(REQUEST, 0, 0, request_payload(b"/small.txt"))))),
    ("RESPONSE with ID 0", srv_case(conn_error(raw_frame(RESPONSE, FLAG_END, 0, b"\x00\xc8")))),
    ("DATA with ID 0", srv_case(conn_error(raw_frame(DATA, FLAG_END, 0, b"x")))),
    ("payload of 2 bytes", srv_case(request_error(b"\x01\x00"))),
    ("payload of 3 bytes", srv_case(request_error(b"\x01\x00\x01"))),
    ("unknown method 0x06", srv_case(request_error(b"\x06\x00\x01/"))),
    ("Path Length 0", srv_case(request_error(b"\x01\x00\x00"))),
    ("Path Length past payload", srv_case(request_error(b"\x01\x00\x09/small"))),
    ("path without leading /", srv_case(request_error(request_payload(b"small.txt")))),
    ("path with .. segment", srv_case(request_error(request_payload(b"/sub/../small.txt")))),
    ("path with . segment", srv_case(request_error(request_payload(b"/./small.txt")))),
    ("path ending in /..", srv_case(request_error(request_payload(b"/sub/..")))),
    ("path with NUL", srv_case(request_error(request_payload(b"/small.txt\x00")))),
    ("path with 0x7f", srv_case(request_error(request_payload(b"/sm\x7fall.txt")))),
    ("query only (?x)", srv_case(request_error(request_payload(b"?x=/")))),
    ("header index 11", srv_case(request_error(request_payload(b"/small.txt", headers=[]) + b"\x0b\x00\x00"))),
    ("header runs past payload", srv_case(request_error(request_payload(b"/small.txt", headers=[]) + b"\x01\x00\x09abc"))),
    ("literal name empty", srv_case(request_error(request_payload(b"/small.txt", headers=[]) + b"\x00\x00\x00\x00"))),
    ("literal name uppercase", srv_case(request_error(request_payload(b"/small.txt", headers=[]) + b"\x00\x03X-A\x00\x00"))),
    ("header value with CR", srv_case(request_error(request_payload(b"/small.txt", headers=[]) + b"\x01\x00\x02a\r"))),
    ("RESPONSE sent to server", srv_case(request_error(b"\x00\xc8", rid=9, ftype=RESPONSE))),
    ("RESPONSE opens no body", srv_case(s_response_opens_no_body)),
    ("DATA with no open body", srv_case(request_error(b"stray", rid=11, ftype=DATA))),
    ("bad REQUEST w/ body -> 1x400", srv_case(s_bad_request_with_body)),
    ("req c-l 5, no body -> 400", srv_case(request_error(request_payload(b"/small.txt", headers=cl(b"5"))))),
    ("req c-l 'x' -> 400", srv_case(request_error(request_payload(b"/small.txt", headers=cl(b"x"))))),
    ("req c-l empty -> 400", srv_case(request_error(request_payload(b"/small.txt", headers=cl(b""))))),
    ("req c-l 20 digits -> 400", srv_case(request_error(request_payload(b"/small.txt", headers=cl(b"0" * 20))))),
    ("req c-l copies 0,1 -> 400", srv_case(request_error(request_payload(b"/small.txt", headers=cl(b"0", b"1"))))),
    ("req c-l 5, body 3 -> 400", srv_case(s_cl_body([b"5"], b"abc", 400))),
    ("req c-l 3 = body -> 200", srv_case(s_cl_body([b"3"], b"abc", 200))),
    ("req c-l 007 = body -> 200", srv_case(s_cl_body([b"007"], b"abcdefg", 200))),
    ("req c-l 3,3 = body -> 200", srv_case(s_cl_body([b"3", b"3"], b"abc", 200))),
    ("req c-l copies 3,03 -> 400", srv_case(s_cl_body([b"3", b"03"], b"abc", 400))),
    ("unknown frames skipped", srv_case(s_unknown_frames)),
    ("IDs copied (0xffffffff,5,3)", srv_case(s_ids_copied)),
    ("unused flag bits ignored", srv_case(s_flag_bits)),
    ("literal form of table names", srv_case(s_literal_headers)),
    ("empty header block", srv_case(s_no_headers)),
    ("HEAD: END, no DATA, c-l", srv_case(s_head)),
    ("HEAD 404: END, no DATA", srv_case(s_head_status(b"/nope", 404))),
    ("HEAD 301: END, no DATA", srv_case(s_head_status(b"/sub", 301))),
    ("HEAD bad path: 400, no DATA", srv_case(s_head_error(request_payload(b"/a/../b", method=HEAD)))),
    ("HEAD bad c-l: 400, no DATA", srv_case(s_head_error(request_payload(b"/small.txt", method=HEAD, headers=cl(b"5"))))),
    ("date, last-modified IMF-fixdate", srv_case(s_dates)),
    ("content-type per §8 table", srv_case(s_content_types)),
    ("POST + body -> 405, allow", srv_case(s_405)),
    ("/sub -> 301 location /sub/", srv_case(path_status(b"/sub", 301, location=b"/sub/"))),
    ("/sub/ -> index.html", srv_case(path_status(b"/sub/", 200, "/sub/index.html"))),
    ("301 location drops query", srv_case(path_status(b"/sub?x=1", 301, location=b"/sub/"))),
    ("dir/ whose index is a dir: 404", srv_case(path_status(b"/idxdir/", 404))),
    ("query dropped", srv_case(path_status(b"/small.txt?a=1&b=/..", 200, "/small.txt"))),
    ("%2e%2e is a literal name", srv_case(path_status(b"/%2e%2e", 200, "/%2e%2e"))),
    ("/.hidden -> 404", srv_case(path_status(b"/.hidden", 404))),
    ("/sub/.secret -> 404", srv_case(path_status(b"/sub/.secret", 404))),
    ("missing file -> 404", srv_case(path_status(b"/nope", 404))),
    ("symlink inside root -> 200", srv_case(path_status(b"/link_in", 200, "/small.txt"))),
    ("symlink outside root -> 404", srv_case(path_status(b"/link_out", 404))),
    ("dir symlink outside -> 404", srv_case(path_status(b"/dir_out/secret.txt", 404))),
    ("FIFO (not regular) -> 404", srv_case(s_fifo)),
    ("unreadable file -> 403", srv_case(s_forbidden)),
    ("empty file", srv_case(path_status(b"/empty.txt", 200, "/empty.txt"))),
    ("truncated frame -> close", srv_case(s_truncated)),
    ("client GOAWAY -> close", srv_case(s_client_goaway)),
    ("GOAWAY ID 7 ignored -> close", srv_case(s_client_goaway_id)),
    ("partial frame doesn't extend T", s_idle_trickle),
    ("unknown frames don't extend T", idle_unknown),
    ("each REQUEST resets T", idle_case(idle_requests)),
    ("each body DATA resets T", idle_case(idle_body)),
    ("cap 2: 3rd gets GOAWAY BUSY", s_busy),
]
SLOW_SERVER_TESTS = [("idle close with GOAWAY 0x00", srv_case(s_idle))]


# ---------------------------------------------------------------------------
# 3. Client conformance (scripted server)
# ---------------------------------------------------------------------------

Script = Callable[[socket.socket, bh.FrameReader, Frame], None]


class ScriptedServer:
    """Accepts connections; for every REQUEST it runs `script(sock, reader, request)`."""

    def __init__(self, script: Script) -> None:
        self.script = script
        self.requests: List[Frame] = []
        self.connections = 0
        self.threads: List[threading.Thread] = []
        self.lsock = socket.socket()
        self.lsock.bind((HOST, 0))
        self.lsock.listen(4)
        self.port = self.lsock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def close(self) -> None:
        """Stop accepting, then let every connection finish reading what the client sent."""
        self.lsock.close()
        for t in list(self.threads):
            t.join(5)

    def _loop(self) -> None:
        while True:
            try:
                sock, _ = self.lsock.accept()
            except OSError:
                return
            self.connections += 1
            t = threading.Thread(target=self._conn, args=(sock,), daemon=True)
            self.threads.append(t)
            t.start()

    def _conn(self, sock: socket.socket) -> None:
        reader = bh.FrameReader(sock)
        try:
            while True:
                f = reader.read(time.monotonic() + 10)
                if f is None:
                    break
                if f.type == REQUEST:
                    self.requests.append(f)
                    self.script(sock, reader, f)
        except Exception:
            pass
        finally:
            sock.close()


def send(sock: socket.socket, *frames: bytes) -> None:
    sock.sendall(b"".join(frames))


def ok_response(rid: int, body: bytes, literal: bool = False) -> bytes:
    if literal:
        hdrs = b"\x00\x0ccontent-type\x00\x0atext/plain" + \
            b"\x00\x0econtent-length" + struct.pack("!H", len(str(len(body)))) + str(len(body)).encode()
    else:
        hdrs = bh.encode_headers([("content-type", b"text/plain"),
                                  ("content-length", str(len(body)).encode())])
    if not body:
        return raw_frame(RESPONSE, FLAG_END, rid, b"\x00\xc8" + hdrs)
    out = raw_frame(RESPONSE, 0, rid, b"\x00\xc8" + hdrs)
    chunks = [body[i:i + MAX_PAYLOAD] for i in range(0, len(body), MAX_PAYLOAD)]
    for i, c in enumerate(chunks):
        out += raw_frame(DATA, FLAG_END if i == len(chunks) - 1 else 0, rid, c)
    return out


BODY = b"scripted body\n"


def scripted(script: Script, paths: Optional[List[str]] = None,
             check_run: Optional[Callable[[ClientRun, ScriptedServer], None]] = None,
             urls: Optional[Callable[[int], List[str]]] = None):
    """Run a client against a ScriptedServer; `urls` gives literal URLs instead of paths."""
    def run(cli: ClientImpl, tree: Tree) -> None:
        srv = ScriptedServer(script)
        try:
            if urls:
                r = run_argv(cli.argv(False, urls(srv.port)))
            else:
                r = run_client(cli, srv.port, paths or ["/x"])
        finally:
            srv.close()
        (check_run or (lambda r, s: expect_protocol_error(r)))(r, srv)
    return run


def c_unknown_everywhere(sock, reader, req):
    rid = req.rid
    hdr = b"\x00\x0ccontent-type\x00\x0atext/plain\x00\x0econtent-length\x00\x0214"
    send(sock,
         raw_frame(0x05, FLAG_END, rid, b""),
         raw_frame(0xFE, 0, 0, raw_frame(RESPONSE, FLAG_END, rid, b"\x01\x94")),
         raw_frame(RESPONSE, 0x80, rid, b"\x00\xc8" + hdr),
         raw_frame(0x7F, FLAG_END, rid, b"END? no"),
         raw_frame(DATA, 0x40, rid, BODY[:5]),
         raw_frame(0x00, 0, rid, b"\xff" * MAX_PAYLOAD),
         raw_frame(DATA, 0x02, rid, BODY[5:]),
         raw_frame(0x80, FLAG_END, rid, raw_frame(DATA, FLAG_END, rid, b"WRONG")),
         raw_frame(DATA, FLAG_END | 0x80, rid, b""))


def c_good(sock, reader, req):
    send(sock, ok_response(req.rid, BODY + str(req.rid).encode()))


def c_wrong_id(sock, reader, req):
    send(sock, ok_response(req.rid + 1, BODY))


def c_data_first(sock, reader, req):
    send(sock, raw_frame(DATA, FLAG_END, req.rid, BODY), ok_response(req.rid, BODY))


def c_id0(sock, reader, req):
    send(sock, raw_frame(RESPONSE, FLAG_END, 0, b"\x01\x90"),
         raw_frame(GOAWAY, 0, 0, bh.encode_goaway(0, 1)))


def c_status(code: int) -> Script:
    def s(sock, reader, req):
        send(sock, raw_frame(RESPONSE, FLAG_END, req.rid, struct.pack("!H", code)))
    return s


def c_cl_mismatch(sock, reader, req):
    hdrs = bh.encode_headers([("content-length", b"99")])
    send(sock, raw_frame(RESPONSE, 0, req.rid, b"\x00\xc8" + hdrs),
         raw_frame(DATA, FLAG_END, req.rid, BODY))


def c_cl_not_digits(sock, reader, req):
    hdrs = bh.encode_headers([("content-length", b"1x")])
    send(sock, raw_frame(RESPONSE, 0, req.rid, b"\x00\xc8" + hdrs),
         raw_frame(DATA, FLAG_END, req.rid, b"a"))


def c_eof_before_end(sock, reader, req):
    send(sock, raw_frame(RESPONSE, 0, req.rid, b"\x00\xc8"), raw_frame(DATA, 0, req.rid, BODY))
    sock.shutdown(socket.SHUT_WR)


def c_eof_mid_frame(sock, reader, req):
    send(sock, raw_frame(RESPONSE, 0, req.rid, b"\x00\xc8"), raw_frame(DATA, FLAG_END, req.rid, BODY)[:-3])
    sock.shutdown(socket.SHUT_WR)


def c_goaway_before_end(sock, reader, req):
    send(sock, raw_frame(RESPONSE, 0, req.rid, b"\x00\xc8"), raw_frame(DATA, 0, req.rid, BODY),
         raw_frame(GOAWAY, 0, 0, bh.encode_goaway(0, 0)))


def c_too_long(sock, reader, req):
    send(sock, raw_frame(RESPONSE, 0, req.rid, b"\x00\xc8"),
         struct.pack("!HBBI", MAX_PAYLOAD + 1, DATA, FLAG_END, req.rid) + b"z" * (MAX_PAYLOAD + 1))


def c_second_response(sock, reader, req):
    send(sock, raw_frame(RESPONSE, 0, req.rid, b"\x00\xc8"),
         raw_frame(RESPONSE, FLAG_END, req.rid, b"\x00\xc8"))


def c_request_from_server(sock, reader, req):
    send(sock, raw_frame(REQUEST, FLAG_END, req.rid, request_payload(b"/")))


def c_bad_header_block(sock, reader, req):
    send(sock, raw_frame(RESPONSE, FLAG_END, req.rid, b"\x00\xc8\x0b\x00\x00"))


def c_fragmented(sock, reader, req):
    data = ok_response(req.rid, BODY * 50)
    for i in range(0, len(data), 3):
        sock.sendall(data[i:i + 3])
        time.sleep(0.0005)


def c_uneven_data(sock, reader, req):
    rid = req.rid
    send(sock, raw_frame(RESPONSE, 0, rid, b"\x00\xc8"), raw_frame(DATA, 0, rid, BODY[:1]),
         raw_frame(DATA, 0, rid, BODY[1:9]), raw_frame(DATA, 0, rid, b""),
         raw_frame(DATA, FLAG_END, rid, BODY[9:]))


def c_goaway_after_end(sock, reader, req):
    send(sock, ok_response(req.rid, BODY), raw_frame(GOAWAY, 0, 0, bh.encode_goaway(req.rid, 0)))
    time.sleep(0.2)
    sock.shutdown(socket.SHUT_WR)


def c_goaway_pending(sock, reader, req):
    """Response 1 and a GOAWAY(Last-ID 1) in one segment: request 2 must not be sent (§4)."""
    send(sock, ok_response(req.rid, BODY), raw_frame(0x7E, 0, 0, b"skip me"),
         raw_frame(GOAWAY, 0, 0, bh.encode_goaway(req.rid, 0)))
    time.sleep(0.3)


def expect_no_second_request(r: ClientRun, s: ScriptedServer) -> None:
    check(r.code is not None, "client hung")
    check([f.rid for f in s.requests] == [1], "requests sent: IDs %s, want only 1"
          % [f.rid for f in s.requests])
    check(r.out == BODY, "stdout %r, want the first body" % short(r.out))
    expect_exit(r, EXIT_FAILED, "a GOAWAY before the second request")


def expect_body(want: bytes) -> Callable[[ClientRun, ScriptedServer], None]:
    def fn(r: ClientRun, s: ScriptedServer) -> None:
        expect_success(r, want)
    return fn


def expect_ids(r: ClientRun, s: ScriptedServer) -> None:
    expect_success(r, b"".join(BODY + str(i).encode() for i in (1, 2, 3)))
    check(s.connections == 1, "%d connections" % s.connections)
    check([f.rid for f in s.requests] == [1, 2, 3], "IDs %s" % [f.rid for f in s.requests])
    for f in s.requests:
        check(f.flags == FLAG_END, "REQUEST flags 0x%02x, want END only" % f.flags)
        try:
            method, path, headers = bh.decode_request(f.payload)
        except bh.Malformed as exc:
            raise TestFail("client sent a malformed REQUEST: %s" % exc)
        check(method == GET, "method %d" % method)
        check(any(n == "host" for n, _ in headers), "no host header (SHOULD)")
        check(f.payload.find(b"\x00\x04host") < 0, "host sent in literal form (SHOULD be indexed)")
    paths = [bh.decode_request(f.payload)[1] for f in s.requests]
    check(paths == [b"/a", b"/b/c", b"/d?x=1"], "paths %s" % paths)


def expect_status_error(r: ClientRun, s: ScriptedServer) -> None:
    check(r.code is not None, "client hung")
    check(r.code != 0, "exit 0")


def c_statuses(*codes: int) -> Script:
    """Answer request n with codes[n-1], no body."""
    def s(sock, reader, req):
        code = codes[(req.rid - 1) % len(codes)]
        send(sock, raw_frame(RESPONSE, FLAG_END, req.rid, struct.pack("!H", code)))
    return s


def c_lengths(values: List[bytes], body: bytes) -> Script:
    def s(sock, reader, req):
        hdrs = bh.encode_headers([("content-length", v) for v in values])
        send(sock, raw_frame(RESPONSE, 0, req.rid, b"\x00\xc8" + hdrs),
             raw_frame(DATA, FLAG_END, req.rid, body))
    return s


def c_close_after_first(sock, reader, req):
    send(sock, ok_response(req.rid, BODY))
    sock.shutdown(socket.SHUT_RDWR)
    raise ConnectionAbortedError("scripted close")  # ends this connection


def c_busy(sock, reader, req):
    send(sock, raw_frame(GOAWAY, 0, 0, bh.encode_goaway(0, bh.GOAWAY_BUSY)))
    sock.shutdown(socket.SHUT_WR)
    time.sleep(0.2)


def expect_code(code: int, what: str, conns: Optional[int] = None,
                out: Optional[bytes] = None) -> Callable[[ClientRun, ScriptedServer], None]:
    def fn(r: ClientRun, s: ScriptedServer) -> None:
        expect_exit(r, code, what)
        if conns is not None:
            check(s.connections == conns, "%d connections, want %d" % (s.connections, conns))
        if out is not None:
            check(r.out == out, "stdout %r, want %r" % (r.out[:40], out[:40]))
    return fn


def expect_path(want: bytes) -> Callable[[ClientRun, ScriptedServer], None]:
    """The raw Path of the first REQUEST (§11 URL grammar)."""
    def fn(r: ClientRun, s: ScriptedServer) -> None:
        check(bool(s.requests), "no REQUEST sent (exit %s; %s)" % (r.code, short(r.err)))
        payload = s.requests[0].payload
        (plen,) = struct.unpack_from("!H", payload, 1)
        check(payload[3:3 + plen] == want, "sent path %r, want %r" % (payload[3:3 + plen], want))
        expect_success(r, BODY + b"1")
    return fn


def url_case(suffix: str, want: bytes):
    return scripted(c_good, check_run=expect_path(want),
                    urls=lambda port: ["bhttp://%s:%d%s" % (HOST, port, suffix)])


def usage_case(make_args: Callable[[int], List[str]]):
    return scripted(c_good, check_run=expect_code(EXIT_USAGE, "a usage error", conns=0), urls=make_args)


CLIENT_TESTS = [
    ("IDs 1,2,3, one conn, host", scripted(c_good, ["/a", "/b/c", "/d?x=1"], expect_ids)),
    ("unknown frames + flag bits", scripted(c_unknown_everywhere, None, expect_body(BODY))),
    ("1-3 byte TCP segments", scripted(c_fragmented, None, expect_body(BODY * 50))),
    ("uneven + empty DATA frames", scripted(c_uneven_data, None, expect_body(BODY))),
    ("GOAWAY after END is fine", scripted(c_goaway_after_end, None, expect_body(BODY))),
    ("pending GOAWAY: no 2nd REQUEST", scripted(c_goaway_pending, ["/a", "/b"], expect_no_second_request)),
    ("wrong RESPONSE ID", scripted(c_wrong_id)),
    ("DATA before RESPONSE", scripted(c_data_first)),
    ("RESPONSE on ID 0", scripted(c_id0)),
    ("status 199", scripted(c_status(199))),
    ("status 600", scripted(c_status(600))),
    ("content-length mismatch", scripted(c_cl_mismatch)),
    ("content-length not digits", scripted(c_cl_not_digits)),
    ("EOF before END", scripted(c_eof_before_end)),
    ("EOF inside a frame", scripted(c_eof_mid_frame)),
    ("GOAWAY before END -> 2", scripted(c_goaway_before_end)),
    ("Length 16385", scripted(c_too_long)),
    ("second RESPONSE", scripted(c_second_response)),
    ("REQUEST from server", scripted(c_request_from_server)),
    ("malformed header block", scripted(c_bad_header_block)),
    ("c-l copies 2,3 -> 2", scripted(c_lengths([b"2", b"3"], b"ab"))),
    ("c-l 20 digits -> 2", scripted(c_lengths([b"0" * 19 + b"2"], b"ab"))),
    ("c-l empty -> 2", scripted(c_lengths([b""], b""))),
    ("c-l 007 = 7 bytes -> 0", scripted(c_lengths([b"007"], b"1234567"), None, expect_body(b"1234567"))),
    ("c-l 2,2 = 2 bytes -> 0", scripted(c_lengths([b"2", b"2"], b"ab"), None, expect_body(b"ab"))),
    ("c-l copies 2,02 -> 2", scripted(c_lengths([b"2", b"02"], b"ab"))),
    ("GOAWAY BUSY -> 2, no output", scripted(c_busy, ["/a", "/b"], expect_code(EXIT_FAILED, "GOAWAY BUSY", out=b""))),
    ("§11 exit: 301 -> 0", scripted(c_statuses(301), ["/a"], expect_code(EXIT_OK, "a 301"))),
    ("§11 exit: 500 -> 5", scripted(c_statuses(500), ["/a"], expect_code(EXIT_5XX, "a 500"))),
    ("§11 exit: 200,404 -> 4", scripted(c_statuses(200, 404), ["/a", "/b"], expect_code(EXIT_4XX, "200 then 404"))),
    ("§11 exit: 404,500 -> 5", scripted(c_statuses(404, 500), ["/a", "/b"], expect_code(EXIT_5XX, "404 then 500"))),
    ("§11 exit: 500,404 -> 5", scripted(c_statuses(500, 404), ["/a", "/b"], expect_code(EXIT_5XX, "500 then 404"))),
    ("§11 exit: 2 beats 4 (404, bad)", scripted(c_statuses(404, 199), ["/a", "/b"],
                                                 expect_code(EXIT_FAILED, "404 then a protocol error"))),
    ("§11: closed, never reopened", scripted(c_close_after_first, ["/a", "/b"],
                                              expect_code(EXIT_FAILED, "a close between requests", conns=1, out=BODY))),
    ("§11 URL: #fragment not sent", url_case("/x#frag", b"/x")),
    ("§11 URL: host:port?q -> /?q", url_case("?q=1", b"/?q=1")),
    ("§11 URL: host:port -> /", url_case("", b"/")),
    ("§11 URL: host:port#f -> /", url_case("#f", b"/")),
    ("§11 URL: path sent unchanged", url_case("/a/../b%2e?x#y", b"/a/../b%2e?x")),
    ("§11 usage: two origins -> 1", usage_case(lambda p: [_url(p, "/a"), _url(p + 1, "/b")])),
    ("§11 usage: http:// -> 1", usage_case(lambda p: ["http://%s:%d/a" % (HOST, p)])),
    ("§11 usage: bad port -> 1", usage_case(lambda p: ["%s:%dx/a" % (HOST, p)])),
    ("§11 usage: unknown option -> 1", usage_case(lambda p: ["-Q", _url(p, "/a")])),
    ("§11 usage: no URL -> 1", usage_case(lambda p: [])),
    ("§11 usage: URL too big -> 1", usage_case(lambda p: [_url(p, "/" + "a" * 16400)])),
]


# ---------------------------------------------------------------------------
# 0. Reference bytes: the spec's own examples through the Python codec
# ---------------------------------------------------------------------------

def ref_spec_example() -> None:
    """SPEC.md §10, byte for byte, both ways."""
    req = bytes.fromhex("0004010100000001" "0100012f")
    resp = bytes.fromhex("0002020100000001" "0194")
    check(bh.encode_frame(REQUEST, FLAG_END, 1, bh.encode_request(GET, b"/", [])) == req,
          "encoding GET / differs from §10")
    check(bh.encode_frame(RESPONSE, FLAG_END, 1, bh.encode_response(404, [])) == resp,
          "encoding 404 differs from §10")
    check(bh.decode_request(req[8:]) == (GET, b"/", []), "decoding §10 REQUEST")
    check(bh.decode_response(resp[8:]) == (404, []), "decoding §10 RESPONSE")
    check(bh.encode_headers([("host", b"localhost:9000")]) == b"\x01\x00\x0elocalhost:9000",
          "indexed host entry differs from §10")
    check(bh.encode_headers([("x-a", b"1")]) == bytes.fromhex("0003782d61000131"),
          "literal x-a entry differs from §10")


def hexdump_frames() -> List[Tuple[str, bytes]]:
    """The raw frames from the capture in HEXDUMP.md, as (direction, bytes)."""
    import re
    path = os.path.join(REPO, "HEXDUMP.md")
    if not os.path.exists(path):
        raise Skip("no HEXDUMP.md")
    with open(path) as f:
        capture = f.read().split("```text", 1)[1].split("```", 1)[0]
    frames: List[Tuple[str, bytearray]] = []
    for line in capture.splitlines():
        m = re.match(r"([<>])\s+([0-9a-f]{4})  ((?:[0-9a-f]{2} {1,2})+)", line + " ")
        if not m:
            continue
        if m.group(2) == "0000":
            frames.append((m.group(1), bytearray()))
        frames[-1][1].extend(bytes.fromhex(m.group(3).replace(" ", "")))
    return [(d, bytes(b)) for d, b in frames]


def ref_hexdump() -> None:
    """Decode every frame in HEXDUMP.md, re-encode it, and demand identical bytes."""
    frames = hexdump_frames()
    check(len(frames) == 3, "found %d frames in HEXDUMP.md, want 3" % len(frames))
    for direction, raw in frames:
        length, ftype, flags, rid = bh.decode_header(raw[:8])
        check(length == len(raw) - 8, "Length %d but %d payload bytes" % (length, len(raw) - 8))
        payload = raw[8:]
        if ftype == REQUEST:
            again = bh.encode_request(*bh.decode_request(payload))
        elif ftype == RESPONSE:
            again = bh.encode_response(*bh.decode_response(payload))
        else:
            again = payload
        check(bh.encode_frame(ftype, flags, rid, again) == raw,
              "%s frame does not re-encode to the same bytes" % bh.KNOWN_TYPES.get(ftype))


REF_SECTION = "0. Reference bytes (SPEC.md §10, HEXDUMP.md) through the Python codec"
REF_TESTS = [
    ("SPEC.md §10 example", ref_spec_example),
    ("HEXDUMP.md decodes+re-encodes", ref_hexdump),
]


# ---------------------------------------------------------------------------
# Runner and report
# ---------------------------------------------------------------------------

class Result(NamedTuple):
    section: str
    test: str
    column: str
    verdict: str  # PASS / FAIL / SKIP
    detail: str


def guarded(srv: RunningServer, test: str, fn: Callable[[], None]) -> Callable[[], None]:
    """Run fn, then make sure the server survived it (restarting it if not)."""
    def go() -> None:
        try:
            fn()
        finally:
            srv.check_alive(test)
    return go


def attempt(fn: Callable[[], None]) -> Tuple[str, str]:
    try:
        fn()
        return "PASS", ""
    except Skip as exc:
        return "SKIP", str(exc)
    except TestFail as exc:
        return "FAIL", str(exc)
    except Exception as exc:  # a harness-level surprise is still a failure to look at
        return "FAIL", "%s: %s" % (type(exc).__name__, exc)


def build_c() -> None:
    if not os.path.exists(os.path.join(REPO, "Makefile")):
        raise SystemExit("no Makefile in %s: the C implementation is not there yet" % REPO)
    print("building C implementation with make ...", flush=True)
    subprocess.run(["make", "-C", REPO], check=True, stdout=subprocess.DEVNULL)


def print_table(results: List[Result], section: str, columns: List[str]) -> None:
    rows = [r for r in results if r.section == section]
    if not rows:
        return
    tests: List[str] = []
    for r in rows:
        if r.test not in tests:
            tests.append(r.test)
    cell = {(r.test, r.column): r.verdict for r in rows}
    width = max(len(t) for t in tests) + 2
    print("\n" + section)
    print("-" * len(section))
    print("%-*s%s" % (width, "test", "".join("%-8s" % c for c in columns)))
    for t in tests:
        print("%-*s%s" % (width, t, "".join("%-8s" % cell.get((t, c), "-") for c in columns)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--slow", action="store_true", help="also run the 30 s idle-timeout test")
    ap.add_argument("--only", choices=["C", "Py"], help="test one implementation against itself")
    ap.add_argument("--keep", action="store_true", help="keep the temp directory and server logs")
    args = ap.parse_args()

    impls = [args.only] if args.only else ["C", "Py"]
    if "C" in impls:
        build_c()
    tree = make_tree()
    servers = {name: RunningServer(SERVERS[name], tree.root, tree.base) for name in impls}
    results: List[Result] = []
    for test, ref in REF_TESTS:
        verdict, detail = attempt(ref)
        results.append(Result(REF_SECTION, test, "Py", verdict, detail))
    try:
        for s in servers.values():
            s.start()

        sec = "1. Pairing matrix (client -> server)"
        for test, fn in PAIR_TESTS:
            for c in impls:
                for s in impls:
                    srv = servers[s]
                    verdict, detail = attempt(guarded(srv, test, lambda: fn(CLIENTS[c], srv, tree)))
                    results.append(Result(sec, test, "%s->%s" % (c, s), verdict, detail))

        sec = "2. Server conformance (raw frames)"
        for test, fn in SERVER_TESTS + (SLOW_SERVER_TESTS if args.slow else []):
            for s in impls:
                srv = servers[s]
                verdict, detail = attempt(guarded(srv, test, lambda: fn(srv, tree)))
                results.append(Result(sec, test, s, verdict, detail))

        sec = "3. Client conformance (scripted server)"
        for test, fn in CLIENT_TESTS:
            for c in impls:
                verdict, detail = attempt(lambda: fn(CLIENTS[c], tree))
                results.append(Result(sec, test, c, verdict, detail))

    finally:
        for s in servers.values():
            s.stop()
        if not args.keep:
            remove_tree(tree)
        else:
            print("kept %s" % tree.base)

    pairs = ["%s->%s" % (c, s) for c in impls for s in impls]
    print_table(results, REF_SECTION, ["Py"])
    print_table(results, "1. Pairing matrix (client -> server)", pairs)
    print_table(results, "2. Server conformance (raw frames)", impls)
    print_table(results, "3. Client conformance (scripted server)", impls)

    failed = [r for r in results if r.verdict == "FAIL"]
    skipped = [r for r in results if r.verdict == "SKIP"]
    if failed:
        print("\nFailures")
        print("--------")
        for r in failed:
            print("[%s] %s: %s" % (r.column, r.test, r.detail))
    for r in skipped:
        print("skipped [%s] %s: %s" % (r.column, r.test, r.detail))
    crashes = {s.impl.name: s.crashes for s in servers.values() if s.crashes}
    for name, where in crashes.items():
        print("%s server crashed during: %s" % (name, "; ".join(where)))
    total = len(results)
    print("\n%d checks: %d passed, %d failed, %d skipped"
          % (total, total - len(failed) - len(skipped), len(failed), len(skipped)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
