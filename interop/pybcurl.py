#!/usr/bin/env python3
"""pybcurl [-v] [-t seconds] URL...: a bhttp/1 client written from SPEC.md.

Follows the reference-client contract of SPEC.md §11.  URL is
[bhttp://]host[:port][path]; the port defaults to 9000; the host ends at the
first ':', '/', '?' or '#'; a #fragment is never sent; an empty path becomes
'/' and a path starting with '?' gets a '/' in front.  All URLs must name the
same host and port; they are fetched in order over one connection (IDs 1, 2,
3, ...), which is never reopened.  Bodies go to stdout, in order, and never
past what content-length announced.  -t (default 30) gives up on a request after
that long without a RESPONSE or DATA frame of it; unknown frames don't count.

Exit status (the worst wins, in the order 2, 5, 4, 0):
  0  every response was 2xx or 3xx
  4  the worst response was 4xx
  5  the worst response was 5xx
  2  connection or protocol error, or timeout (later URLs are not fetched)
  1  usage error
"""

import socket
import sys
import time
from typing import BinaryIO, List, NamedTuple, Optional

import pybhttp as bh
from pybhttp import Frame

DEFAULT_PORT = 9000
USER_AGENT = b"pybcurl/1"
DEFAULT_TIMEOUT = 30
USAGE = ("usage: pybcurl [-v] [-t seconds] URL...\n"
         "  URL: [bhttp://]host[:port][path]   (port defaults to 9000)\n"
         "  -t  give up after this long with no RESPONSE or DATA for a request (30)")

EXIT_OK, EXIT_USAGE, EXIT_FAILED, EXIT_4XX, EXIT_5XX = 0, 1, 2, 4, 5


class UsageError(Exception):
    pass


class Failure(Exception):
    """A connection or protocol error: exit 2, fetch nothing more."""


class Url(NamedTuple):
    host: str
    port: int
    authority: bytes  # sent as the `host` header
    path: bytes       # sent raw: nobody percent-decodes (§5.1)


# --- URLs (§11) ----------------------------------------------------------------

def split_scheme(text: str) -> str:
    """Drop an optional bhttp:// prefix; any other scheme is a usage error."""
    if text[:8].lower() == "bhttp://":
        return text[8:]
    marker = text.find("://")
    if marker >= 0 and "/" not in text[:marker]:
        raise UsageError("%s: only bhttp:// URLs are supported" % text)
    return text


def parse_url(text: str) -> Url:
    rest = split_scheme(text)
    bracketed = rest.startswith("[")
    if bracketed:  # [IPv6 literal]
        close = rest.find("]")
        if close < 0:
            raise UsageError("%s: unterminated [ in host" % text)
        host, rest = rest[1:close], rest[close + 1:]
    else:
        end = next((i for i, ch in enumerate(rest) if ch in ":/?#"), len(rest))
        host, rest = rest[:end], rest[end:]
    if not host:
        raise UsageError("%s: missing host" % text)
    port = DEFAULT_PORT
    port_text = ""
    if rest.startswith(":"):
        end = next((i for i, ch in enumerate(rest) if ch in "/?#"), len(rest))
        digits, rest = rest[1:end], rest[end:]
        if not (digits.isdigit() and len(digits) <= 5 and 0 < int(digits) <= 65535):
            raise UsageError("%s: invalid port" % text)
        port = int(digits)
        port_text = ":" + digits
    elif rest and rest[0] not in "/?#":
        raise UsageError("%s: unexpected character after host" % text)
    path = rest.split("#", 1)[0]  # a fragment is never sent
    if not path.startswith("/"):
        path = "/" + path  # "" -> "/", "?q" -> "/?q"
    authority = ("[%s]" % host if bracketed else host) + port_text
    # The path is otherwise sent as typed, `..` and all: judging it is the server's job.
    return Url(host, port, authority.encode("utf-8"), path.encode("utf-8"))


def request_frame(url: Url, rid: int) -> Frame:
    headers = [("host", url.authority), ("user-agent", USER_AGENT), ("accept", b"*/*")]
    payload = bh.encode_request(bh.METHOD_CODES["GET"], url.path, headers)
    if len(payload) > bh.MAX_PAYLOAD:
        raise UsageError("request for %s... does not fit in one frame"
                         % url.path[:40].decode("utf-8", "replace"))
    return Frame(bh.REQUEST, bh.FLAG_END, rid, payload)


# --- one connection --------------------------------------------------------------

class Client:
    def __init__(self, verbose: bool, out: BinaryIO, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.verbose = verbose
        self.out = out
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.reader: Optional[bh.FrameReader] = None
        self.next_id = 1

    def trace(self, arrow: str, frame: Frame) -> None:
        if self.verbose:
            sys.stderr.write("%s %s\n" % (arrow, bh.describe(frame)))

    def connect(self, url: Url) -> None:
        try:
            sock = socket.create_connection((url.host, url.port), timeout=self.timeout)
        except OSError as exc:
            raise Failure("cannot connect to %s port %d: %s" % (url.host, url.port, exc))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.verbose:
            sys.stderr.write("* connected to %s port %d\n" % (url.host, url.port))
        self.sock = sock
        self.reader = bh.FrameReader(sock, on_frame=lambda f: self.trace("<", f))

    def close(self) -> None:
        if self.sock:
            self.sock.close()
        self.sock = self.reader = None

    def fetch(self, url: Url) -> int:
        """Send one GET and copy its body to stdout; returns the status."""
        assert self.sock is not None
        if self.next_id > 1:
            self.check_between_requests()
        rid, self.next_id = self.next_id, self.next_id + 1
        frame = request_frame(url, rid)
        self.trace(">", frame)
        self.sock.sendall(bh.encode_frame(*frame))
        return self.read_response(rid)

    def check_between_requests(self) -> None:
        """§4: no REQUEST may follow a GOAWAY, so read what arrived since the last END."""
        assert self.reader is not None
        while self.reader.pending():
            frame = self.read_frame(time.monotonic() + self.timeout, skip_unknown=False)
            if frame is None:
                raise Failure("server closed the connection")
            if frame.type == bh.GOAWAY:
                last_id, code = bh.decode_goaway(frame.payload)
                raise Failure("server sent GOAWAY (last-id %d, %s); not sending more requests"
                              % (last_id, bh.GOAWAY_CODES[code]))
            if frame.known:
                raise Failure("protocol error: unexpected %s between responses"
                              % bh.KNOWN_TYPES[frame.type])

    def read_frame(self, deadline: float, skip_unknown: bool = True) -> Optional[Frame]:
        assert self.reader is not None
        try:
            return self.reader.read(deadline) if skip_unknown else self.reader.read_any(deadline)
        except (bh.FrameTooLarge, bh.TruncatedFrame) as exc:
            raise Failure("protocol error: %s" % exc)
        except bh.IdleTimeout:
            raise Failure("no RESPONSE or DATA from the server for %d s" % self.timeout)

    def next_frame(self, deadline: float) -> Frame:
        frame = self.read_frame(deadline)
        if frame is None:
            raise Failure("protocol error: connection closed before END")
        return frame

    def read_response(self, rid: int) -> int:
        # §11: only a RESPONSE or DATA of this request is progress; skipped unknown
        # frames share the deadline, and anything else ends the request anyway.
        frame = self.next_frame(time.monotonic() + self.timeout)
        self.check_common(frame, rid)
        if frame.type == bh.DATA:
            raise Failure("protocol error: DATA before RESPONSE")
        try:
            status, headers = bh.decode_response(frame.payload)
            declared = bh.content_length(headers)
        except bh.Malformed as exc:
            raise Failure("protocol error: malformed RESPONSE: %s" % exc)
        received = 0
        done = frame.end
        while not done:
            frame = self.next_frame(time.monotonic() + self.timeout)
            self.check_common(frame, rid)
            if frame.type == bh.RESPONSE:
                raise Failure("protocol error: second RESPONSE for id %d" % rid)
            if declared is not None and received + len(frame.payload) > declared:
                raise Failure("protocol error: body longer than content-length %d" % declared)
            self.out.write(frame.payload)
            received += len(frame.payload)
            done = frame.end
        self.out.flush()
        if declared is not None and declared != received:
            raise Failure("protocol error: content-length %d but body was %d bytes"
                          % (declared, received))
        return status

    @staticmethod
    def check_common(frame: Frame, rid: int) -> None:
        """Rules shared by every frame of a response (§7 "Clients")."""
        if frame.type == bh.GOAWAY:
            last_id, code = bh.decode_goaway(frame.payload)
            raise Failure("server sent GOAWAY (last-id %d, %s) before END: request %d was not "
                          "processed" % (last_id, bh.GOAWAY_CODES[code], rid))
        if frame.type == bh.REQUEST:
            raise Failure("protocol error: server sent a REQUEST")
        if frame.type == bh.RESPONSE and frame.rid == 0:
            raise Failure("protocol error: server reported a connection error (RESPONSE on ID 0)")
        if frame.rid != rid:
            raise Failure("protocol error: frame for id %d while waiting for id %d"
                          % (frame.rid, rid))


# --- command line ----------------------------------------------------------------

class Options(NamedTuple):
    verbose: bool
    timeout: int
    urls: List[Url]


def parse_timeout(text: str) -> int:
    if not (text.isdigit() and 1 <= int(text) <= 3600):
        raise UsageError("-t wants whole seconds from 1 to 3600, not %r" % text)
    return int(text)


def parse_args(argv: List[str]) -> Options:
    verbose, timeout = False, DEFAULT_TIMEOUT
    args = list(argv)
    while args and args[0].startswith("-") and args[0] != "-":
        opt = args.pop(0)
        if opt == "--":
            break
        if opt == "-v":
            verbose = True
        elif opt == "-t":
            if not args:
                raise UsageError("-t needs a value")
            timeout = parse_timeout(args.pop(0))
        elif opt.startswith("-t"):
            timeout = parse_timeout(opt[2:])
        else:
            raise UsageError("unknown option %s" % opt)
    if not args:
        raise UsageError("no URL")
    urls = [parse_url(a) for a in args]
    for url in urls[1:]:
        if (url.host, url.port) != (urls[0].host, urls[0].port):
            raise UsageError("every URL must use %s port %d (one connection)"
                             % (urls[0].host, urls[0].port))
    for url in urls:
        request_frame(url, 1)  # too long for one frame: refuse before connecting
    return Options(verbose, timeout, urls)


def exit_for(status: int) -> int:
    return EXIT_5XX if status >= 500 else EXIT_4XX if status >= 400 else EXIT_OK


def main(argv: List[str]) -> int:
    try:
        verbose, timeout, urls = parse_args(argv)
    except UsageError as exc:
        print("pybcurl: %s\n%s" % (exc, USAGE), file=sys.stderr)
        return EXIT_USAGE

    client = Client(verbose, sys.stdout.buffer, timeout)
    worst = EXIT_OK
    try:
        client.connect(urls[0])
        for url in urls:
            status = client.fetch(url)
            if verbose:
                sys.stderr.write("* %s: status %d\n" % (url.path.decode("utf-8", "replace"), status))
            worst = max(worst, exit_for(status))  # 5 beats 4 beats 0
    except Failure as exc:
        print("pybcurl: %s" % exc, file=sys.stderr)
        return EXIT_FAILED
    except OSError as exc:
        print("pybcurl: connection failed: %s" % exc, file=sys.stderr)
        return EXIT_FAILED
    finally:
        client.close()
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
