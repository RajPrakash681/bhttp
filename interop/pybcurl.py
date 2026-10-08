#!/usr/bin/env python3
"""pybcurl [-v] URL...: a bhttp/1 client written from SPEC.md.

URL is bhttp://HOST[:PORT]/PATH (the scheme may be omitted; PORT defaults to
9000).  Consecutive URLs for the same HOST:PORT share one connection and are
sent one at a time with IDs 1, 2, 3, ...  Bodies go to stdout, in order.

Exit status:
  0  every URL got a complete response with status 200-399
  1  every URL got a complete response, at least one with status >= 400
  2  usage error (bad option or URL)
  3  could not connect, or the connection failed at the socket level
  4  protocol error (SPEC.md §7 "Clients"); later URLs are not fetched
"""

import socket
import sys
from typing import BinaryIO, List, NamedTuple, Optional, Tuple

import pybhttp as bh
from pybhttp import Frame

DEFAULT_PORT = 9000
USER_AGENT = b"pybcurl/1"

EXIT_OK, EXIT_HTTP_ERROR, EXIT_USAGE, EXIT_CONNECT, EXIT_PROTOCOL = 0, 1, 2, 3, 4


class UsageError(Exception):
    pass


class ProtocolError(Exception):
    pass


class Url(NamedTuple):
    host: str
    port: int
    authority: bytes  # sent as the `host` header
    path: bytes       # sent raw: nobody percent-decodes (§5.1)


def parse_url(text: str) -> Url:
    rest = text
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
        if scheme.lower() not in ("bhttp", "http"):
            raise UsageError("unsupported scheme %r" % scheme)
    rest = rest.split("#", 1)[0]  # a fragment never goes on the wire
    end = len(rest)
    for stop in "/?":  # the authority ends at the first '/' or '?' (RFC 3986 §3.2)
        if stop in rest:
            end = min(end, rest.index(stop))
    authority, path = rest[:end], rest[end:]
    if not path.startswith("/"):
        path = "/" + path  # bhttp://host?q asks for /?q
    if authority.startswith("["):  # [v6addr]:port
        close = authority.find("]")
        after = authority[close + 1:] if close >= 0 else "x"
        if after and not after.startswith(":"):
            raise UsageError("bad IPv6 literal in %r" % text)
        host, port_text = authority[1:close], after[1:]
    else:
        host, _, port_text = authority.partition(":")
    if not host:
        raise UsageError("no host in %r" % text)
    if port_text and not (port_text.isdigit() and 0 < int(port_text) < 65536):
        raise UsageError("bad port in %r" % text)
    # The path is sent as typed, `..` and all: judging it is the server's job (§7).
    return Url(host, int(port_text) if port_text else DEFAULT_PORT,
               authority.encode("utf-8"), path.encode("utf-8"))


class Client:
    def __init__(self, verbose: bool, out: BinaryIO) -> None:
        self.verbose = verbose
        self.out = out
        self.sock: Optional[socket.socket] = None
        self.reader: Optional[bh.FrameReader] = None
        self.where: Optional[Tuple[str, int]] = None
        self.next_id = 1

    def trace(self, arrow: str, frame: Frame) -> None:
        if self.verbose:
            sys.stderr.write("%s %s\n" % (arrow, bh.describe(frame)))

    def connect(self, url: Url) -> None:
        if self.where == (url.host, url.port):
            return
        self.close()
        sock = socket.create_connection((url.host, url.port), timeout=60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.verbose:
            sys.stderr.write("* connected to %s port %d\n" % (url.host, url.port))
        self.sock, self.where, self.next_id = sock, (url.host, url.port), 1
        self.reader = bh.FrameReader(sock, on_frame=lambda f: self.trace("<", f))

    def close(self) -> None:
        if self.sock:
            self.sock.close()
        self.sock = self.reader = self.where = None

    def fetch(self, url: Url) -> int:
        """Send one GET and copy its body to stdout; returns the status."""
        self.connect(url)
        rid, self.next_id = self.next_id, self.next_id + 1
        headers = [("host", url.authority), ("user-agent", USER_AGENT), ("accept", b"*/*")]
        payload = bh.encode_request(bh.METHOD_CODES["GET"], url.path, headers)
        if len(payload) > bh.MAX_PAYLOAD:
            raise UsageError("request for %r does not fit in one frame" % url.path)
        frame = Frame(bh.REQUEST, bh.FLAG_END, rid, payload)
        self.trace(">", frame)
        assert self.sock is not None
        self.sock.sendall(bh.encode_frame(*frame))
        return self.read_response(rid)

    def next_frame(self) -> Frame:
        assert self.reader is not None
        try:
            frame = self.reader.read()
        except (bh.FrameTooLarge, bh.TruncatedFrame) as exc:
            raise ProtocolError(str(exc))
        except bh.IdleTimeout:
            raise socket.timeout("no frame from the server for 60 s")
        if frame is None:
            raise ProtocolError("connection closed before END")
        return frame

    def read_response(self, rid: int) -> int:
        frame = self.next_frame()
        self.check_common(frame, rid)
        if frame.type == bh.DATA:
            raise ProtocolError("DATA before RESPONSE")
        try:
            status, headers = bh.decode_response(frame.payload)
            declared = bh.content_length(headers)
        except bh.Malformed as exc:
            raise ProtocolError("malformed RESPONSE: %s" % exc)
        received = 0
        done = frame.end
        while not done:
            frame = self.next_frame()
            self.check_common(frame, rid)
            if frame.type == bh.RESPONSE:
                raise ProtocolError("second RESPONSE for id %d" % rid)
            self.out.write(frame.payload)
            received += len(frame.payload)
            done = frame.end
        self.out.flush()
        if declared is not None and declared != received:
            raise ProtocolError("content-length %d but body was %d bytes" % (declared, received))
        return status

    @staticmethod
    def check_common(frame: Frame, rid: int) -> None:
        """Rules shared by every frame of a response (§7 "Clients")."""
        if frame.type == bh.GOAWAY:
            last_id, code = bh.decode_goaway(frame.payload)
            raise ProtocolError("GOAWAY (last-id %d, code 0x%02x) before END" % (last_id, code))
        if frame.type == bh.REQUEST:
            raise ProtocolError("server sent a REQUEST")
        if frame.type == bh.RESPONSE and frame.rid == 0:
            raise ProtocolError("server reported a connection error (RESPONSE on ID 0)")
        if frame.rid != rid:
            raise ProtocolError("frame for id %d while waiting for id %d" % (frame.rid, rid))


def main(argv: List[str]) -> int:
    verbose = False
    args = list(argv)
    while args and args[0].startswith("-") and args[0] != "-":
        opt = args.pop(0)
        if opt == "--":
            break
        if opt != "-v":
            print("pybcurl: unknown option %s\nusage: pybcurl [-v] URL..." % opt, file=sys.stderr)
            return EXIT_USAGE
        verbose = True
    if not args:
        print("usage: pybcurl [-v] URL...", file=sys.stderr)
        return EXIT_USAGE
    try:
        urls = [parse_url(a) for a in args]
    except UsageError as exc:
        print("pybcurl: %s" % exc, file=sys.stderr)
        return EXIT_USAGE

    client = Client(verbose, sys.stdout.buffer)
    worst = EXIT_OK
    try:
        for url in urls:
            status = client.fetch(url)
            if verbose:
                sys.stderr.write("* %s: status %d\n" % (url.path.decode("utf-8", "replace"), status))
            if status >= 400:
                worst = EXIT_HTTP_ERROR
    except UsageError as exc:
        print("pybcurl: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    except ProtocolError as exc:
        print("pybcurl: protocol error: %s" % exc, file=sys.stderr)
        return EXIT_PROTOCOL
    except OSError as exc:
        print("pybcurl: connection failed: %s" % exc, file=sys.stderr)
        return EXIT_CONNECT
    finally:
        client.close()
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
