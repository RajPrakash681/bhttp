#!/usr/bin/env python3
"""pybserve ROOT PORT [--idle SECONDS]: a bhttp/1 file server written from SPEC.md.

One thread per connection.  Requests are answered strictly in order (§2).
Logs one line per accepted connection and per request to stderr.
"""

import argparse
import email.utils
import errno
import os
import socket
import socketserver
import sys
import threading
import time
from typing import List, Optional, Tuple

import pybhttp as bh
from pybhttp import Frame, Headers

SERVER_NAME = b"pybserve/1"
DEFAULT_IDLE = 30.0
DRAIN_SECONDS = 2.0
ALLOWED = b"GET, HEAD"

CONTENT_TYPES = {
    b".html": b"text/html", b".htm": b"text/html", b".txt": b"text/plain",
    b".css": b"text/css", b".js": b"text/javascript", b".json": b"application/json",
    b".png": b"image/png", b".jpg": b"image/jpeg", b".jpeg": b"image/jpeg",
    b".gif": b"image/gif", b".svg": b"image/svg+xml", b".pdf": b"application/pdf",
    b".ico": b"image/x-icon", b".xml": b"application/xml", b".wasm": b"application/wasm",
}

_log_lock = threading.Lock()


def log(msg: str) -> None:
    with _log_lock:
        sys.stderr.write("pybserve: %s\n" % msg)
        sys.stderr.flush()


class ConnError(Exception):
    """§7 connection error: answer 400 on ID 0, GOAWAY 0x01, close."""


class PeerGone(Exception):
    """EOF, a truncated frame or a client GOAWAY: just close."""


# --- path mapping (§8) -------------------------------------------------------

def content_type(path: bytes) -> bytes:
    ext = os.path.splitext(path)[1].lower()
    return CONTENT_TYPES.get(ext, b"application/octet-stream")


def resolve(root: bytes, path: bytes) -> Tuple[int, bytes]:
    """Map a request Path (already syntax-checked) to (status, fs_path_or_location)."""
    url_path = path.split(b"?", 1)[0]
    query = path[len(url_path):]
    fs_rel = url_path + b"index.html" if url_path.endswith(b"/") else url_path
    if any(seg.startswith(b".") for seg in fs_rel.split(b"/")):
        return 404, b""
    real = os.path.realpath(root + fs_rel)
    if real != root and not real.startswith(root.rstrip(b"/") + b"/"):
        return 404, b""
    if os.path.isdir(real):
        return 301, url_path + b"/" + query
    if not os.path.isfile(real):
        return 404, b""
    if not os.access(real, os.R_OK):
        return 403, b""
    return 200, real


def http_date(ts: float) -> bytes:
    return email.utils.formatdate(ts, usegmt=True).encode("ascii")


# --- one connection ----------------------------------------------------------

class Connection:
    def __init__(self, sock: socket.socket, root: bytes, idle: float) -> None:
        self.sock = sock
        self.root = root
        self.idle = idle
        self.reader = bh.FrameReader(sock)
        self.last_answered = 0

    # sending

    def send(self, ftype: int, flags: int, rid: int, payload: bytes = b"") -> None:
        self.sock.sendall(bh.encode_frame(ftype, flags, rid, payload))

    def send_response(self, rid: int, status: int, headers: Headers,
                      body: bytes = b"", head_only: bool = False) -> None:
        base: Headers = [("date", http_date(time.time())), ("server", SERVER_NAME)]
        if body:
            base += [("content-type", b"text/plain"),
                     ("content-length", str(len(body)).encode())]
        payload = bh.encode_response(status, base + headers)
        if head_only or not body:
            self.send(bh.RESPONSE, bh.FLAG_END, rid, payload)
            return
        self.send(bh.RESPONSE, 0, rid, payload)
        self.send_body_chunks(rid, body)

    def send_body_chunks(self, rid: int, body: bytes) -> None:
        for off in range(0, len(body), bh.MAX_PAYLOAD):
            chunk = body[off:off + bh.MAX_PAYLOAD]
            last = off + bh.MAX_PAYLOAD >= len(body)
            self.send(bh.DATA, bh.FLAG_END if last else 0, rid, chunk)

    def send_error(self, rid: int, status: int, reason: str, head_only: bool = False,
                   extra: Optional[Headers] = None) -> None:
        body = ("%d %s\n" % (status, reason)).encode()
        self.send_response(rid, status, extra or [], body, head_only)

    # main loop

    def serve(self) -> None:
        try:
            while True:
                frame = self.next_frame()
                if frame is None:
                    return
                self.dispatch(frame)
        except PeerGone:
            pass
        except ConnError as exc:
            log("connection error: %s" % exc)
            self.abort()
        except bh.IdleTimeout:
            log("idle for %.0fs, closing" % self.idle)
            self.goaway_and_close(bh.GOAWAY_NO_ERROR)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.sock.close()

    def next_frame(self) -> Optional[Frame]:
        try:
            return self.reader.read(self.idle)
        except bh.FrameTooLarge as exc:
            raise ConnError(str(exc))
        except bh.TruncatedFrame:
            raise PeerGone()

    def dispatch(self, frame: Frame) -> None:
        if frame.type == bh.REQUEST:
            self.handle_request(frame)
        elif frame.type == bh.RESPONSE:
            self.request_error(frame.rid, "RESPONSE sent to a server")
        elif frame.type == bh.DATA:
            self.request_error(frame.rid, "DATA with no open request body")
        elif frame.type == bh.GOAWAY:
            raise PeerGone()

    def request_error(self, rid: int, reason: str) -> None:
        log("400 id=%d: %s" % (rid, reason))
        self.send_error(rid, 400, "Bad Request: " + reason)
        self.last_answered = rid

    # requests

    def read_body(self, rid: int) -> bytes:
        """Read DATA frames for `rid` through END (§6)."""
        body = bytearray()
        while True:
            frame = self.next_frame()
            if frame is None:
                raise PeerGone()
            if frame.type == bh.GOAWAY:
                raise PeerGone()
            if frame.type != bh.DATA or frame.rid != rid:
                raise ConnError("%s for id %d while body of id %d is open"
                                       % (bh.KNOWN_TYPES[frame.type], frame.rid, rid))
            body += frame.payload
            if frame.end:
                return bytes(body)

    def handle_request(self, frame: Frame) -> None:
        body = b"" if frame.end else self.read_body(frame.rid)
        rid = frame.rid
        if rid == 0:
            return self.request_error(0, "REQUEST with ID 0")
        try:
            method, path, headers = bh.decode_request(frame.payload)
            declared = bh.content_length(headers)
        except bh.Malformed as exc:
            return self.request_error(rid, str(exc))
        if declared is not None and declared != len(body):
            return self.request_error(rid, "content-length %d but body is %d bytes"
                                      % (declared, len(body)))
        name = bh.METHODS[method]
        log("%s %s id=%d" % (name, path.decode("latin-1"), rid))
        if name not in ("GET", "HEAD"):
            self.send_error(rid, 405, "Method Not Allowed", extra=[("allow", ALLOWED)])
        else:
            self.serve_file(rid, path, head_only=(name == "HEAD"))
        self.last_answered = rid

    def serve_file(self, rid: int, path: bytes, head_only: bool) -> None:
        status, where = resolve(self.root, path)
        if status == 301:
            return self.send_error(rid, 301, "Moved Permanently", head_only,
                                   extra=[("location", where)])
        if status != 200:
            reason = {403: "Forbidden", 404: "Not Found"}[status]
            return self.send_error(rid, status, reason, head_only)
        try:
            f = open(where, "rb")
            st = os.fstat(f.fileno())
        except OSError as exc:
            if exc.errno == errno.EACCES:
                return self.send_error(rid, 403, "Forbidden", head_only)
            return self.send_error(rid, 500, "Internal Server Error", head_only)
        with f:
            headers: Headers = [
                ("content-type", content_type(where)),
                ("content-length", str(st.st_size).encode()),
                ("last-modified", http_date(st.st_mtime)),
                ("date", http_date(time.time())),
                ("server", SERVER_NAME),
            ]
            payload = bh.encode_response(200, headers)
            if head_only or st.st_size == 0:
                return self.send(bh.RESPONSE, bh.FLAG_END, rid, payload)
            self.send(bh.RESPONSE, 0, rid, payload)
            self.stream_file(rid, f, st.st_size)

    def stream_file(self, rid: int, f, size: int) -> None:
        """DATA frames, all full except the last.  A read error closes without END (§6)."""
        sent = 0
        while sent < size:
            try:
                chunk = f.read(min(bh.MAX_PAYLOAD, size - sent))
            except OSError:
                chunk = b""
            if not chunk:
                log("read error after RESPONSE, closing without END")
                raise PeerGone()
            sent += len(chunk)
            self.send(bh.DATA, bh.FLAG_END if sent >= size else 0, rid, chunk)

    # closing

    def abort(self) -> None:
        """Connection error (§7): 400 on ID 0, GOAWAY PROTOCOL_ERROR, graceful close."""
        try:
            self.send_error(0, 400, "Bad Request: connection error")
        except OSError:
            return
        self.goaway_and_close(bh.GOAWAY_PROTOCOL_ERROR)

    def goaway_and_close(self, code: int) -> None:
        """GOAWAY, shut down our side, drain input for up to 2 s (§2)."""
        try:
            self.send(bh.GOAWAY, 0, 0, bh.encode_goaway(self.last_answered, code))
            self.sock.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + DRAIN_SECONDS
            while time.monotonic() < deadline:
                self.sock.settimeout(max(0.01, deadline - time.monotonic()))
                if not self.sock.recv(65536):
                    break
        except OSError:
            pass


# --- listener ----------------------------------------------------------------

class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int, root: bytes, idle: float) -> None:
        self.root = root
        self.idle = idle
        super().__init__(("", port), Handler)


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock: socket.socket = self.request
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        log("accepted connection from %s:%d" % self.client_address[:2])
        Connection(sock, self.server.root, self.server.idle).serve()


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="pybserve", description=__doc__.splitlines()[0])
    ap.add_argument("root")
    ap.add_argument("port", type=int)
    ap.add_argument("--idle", type=float, default=DEFAULT_IDLE,
                    help="idle timeout in seconds (default %(default)s)")
    args = ap.parse_args(argv)
    root = os.path.realpath(os.fsencode(args.root))
    if not os.path.isdir(root):
        ap.error("ROOT is not a directory")
    try:
        server = Server(args.port, root, args.idle)
    except OSError as exc:
        print("pybserve: cannot listen on port %d: %s" % (args.port, exc), file=sys.stderr)
        return 1
    log("serving %s on port %d" % (os.fsdecode(root), server.server_address[1]))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
