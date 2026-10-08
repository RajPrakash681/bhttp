"""bhttp/1 frame and payload codec, written from SPEC.md alone.

Everything here is pure encoding/decoding plus a small blocking frame reader.
Section numbers in comments refer to SPEC.md.
"""

import select
import socket
import struct
import time
from typing import Callable, List, NamedTuple, Optional, Tuple

# --- §3 frame header -------------------------------------------------------

HEADER_LEN = 8
MAX_PAYLOAD = 16384
HEADER = struct.Struct("!HBBI")  # Length 16, Type 8, Flags 8, Request ID 32

FLAG_END = 0x01

# --- §4 frame types --------------------------------------------------------

REQUEST = 0x01
RESPONSE = 0x02
DATA = 0x03
GOAWAY = 0x04
KNOWN_TYPES = {REQUEST: "REQUEST", RESPONSE: "RESPONSE", DATA: "DATA", GOAWAY: "GOAWAY"}

GOAWAY_NO_ERROR = 0x00
GOAWAY_PROTOCOL_ERROR = 0x01

# --- §5.1 methods ----------------------------------------------------------

METHODS = {0x01: "GET", 0x02: "HEAD", 0x03: "POST", 0x04: "PUT", 0x05: "DELETE"}
METHOD_CODES = {name: code for code, name in METHODS.items()}

# --- §5.3 static header table ----------------------------------------------

STATIC_TABLE = [
    None,  # index 0 introduces the literal form
    "host", "user-agent", "accept", "content-type", "content-length",
    "last-modified", "date", "server", "location", "allow",
]
STATIC_INDEX = {name: i for i, name in enumerate(STATIC_TABLE) if name}

NAME_CHARS = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_|~`")
BAD_VALUE_BYTES = frozenset(b"\x00\x0a\x0d")

Headers = List[Tuple[str, bytes]]


class BhttpError(Exception):
    """Base class for everything the codec can complain about."""


class Malformed(BhttpError):
    """A payload that breaks a §5 rule (a request error on the server side)."""


class FrameTooLarge(BhttpError):
    """Length above MAX_PAYLOAD: a connection error (§3, §7)."""


class TruncatedFrame(BhttpError):
    """The connection ended in the middle of a frame (§2)."""


class IdleTimeout(BhttpError):
    """No complete frame arrived within the idle limit (§2)."""


class Frame(NamedTuple):
    type: int
    flags: int
    rid: int
    payload: bytes

    @property
    def end(self) -> bool:
        return bool(self.flags & FLAG_END)

    @property
    def known(self) -> bool:
        return self.type in KNOWN_TYPES


# --- frames ----------------------------------------------------------------

def encode_frame(ftype: int, flags: int, rid: int, payload: bytes = b"") -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload of %d bytes exceeds MAX_PAYLOAD" % len(payload))
    return HEADER.pack(len(payload), ftype, flags, rid) + payload


def decode_header(raw: bytes) -> Tuple[int, int, int, int]:
    """Return (length, type, flags, rid) from 8 header bytes."""
    return HEADER.unpack(raw)


class FrameReader:
    """Reads whole frames from a socket, one at a time.

    read() returns the next frame of a type this implementation knows, after
    discarding unknown types by exactly Length bytes (§4 MUST-skip).  It returns
    None on a clean EOF at a frame boundary.  `on_frame` is called for every
    frame read, known or not, which is what -v dumps hook into.
    """

    def __init__(self, sock: socket.socket,
                 on_frame: Optional[Callable[[Frame], None]] = None) -> None:
        self.sock = sock
        self.on_frame = on_frame
        self._buf = bytearray()

    def _fill(self, want: int, deadline: Optional[float]) -> bool:
        """Buffer at least `want` bytes; False if EOF came first."""
        while len(self._buf) < want:
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise IdleTimeout()
                self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                raise IdleTimeout()
            if not chunk:
                return False
            self._buf += chunk
        return True

    def _take(self, n: int) -> bytes:
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def pending(self) -> bool:
        """True if bytes are already buffered or waiting on the socket."""
        if self._buf:
            return True
        readable, _, _ = select.select([self.sock], [], [], 0)
        return bool(readable)

    def read_any(self, idle: Optional[float] = None) -> Optional[Frame]:
        """Read one frame of any type.  `idle` bounds the wait for the whole frame."""
        if idle is None:
            return self._read_any(None)
        saved = self.sock.gettimeout()  # sends must not inherit a short read timeout
        try:
            return self._read_any(time.monotonic() + idle)
        finally:
            self.sock.settimeout(saved)

    def _read_any(self, deadline: Optional[float]) -> Optional[Frame]:
        if not self._fill(HEADER_LEN, deadline):
            if self._buf:
                raise TruncatedFrame("EOF inside a frame header")
            return None
        length, ftype, flags, rid = decode_header(bytes(self._buf[:HEADER_LEN]))
        if length > MAX_PAYLOAD:
            raise FrameTooLarge("Length %d > %d" % (length, MAX_PAYLOAD))
        if not self._fill(HEADER_LEN + length, deadline):
            raise TruncatedFrame("EOF inside a frame payload")
        self._take(HEADER_LEN)
        frame = Frame(ftype, flags, rid, self._take(length))
        if self.on_frame:
            self.on_frame(frame)
        return frame

    def read(self, idle: Optional[float] = None) -> Optional[Frame]:
        """Read the next frame whose type is known, skipping unknown ones."""
        while True:
            frame = self.read_any(idle)
            if frame is None or frame.known:
                return frame


# --- §5.3 header block -----------------------------------------------------

def check_name(name: bytes) -> None:
    if not name:
        raise Malformed("empty header name")
    if any(b not in NAME_CHARS for b in name):
        raise Malformed("bad byte in header name %r" % name)


def check_value(value: bytes) -> None:
    if any(b in BAD_VALUE_BYTES for b in value):
        raise Malformed("NUL, LF or CR in header value")


def encode_headers(headers: Headers) -> bytes:
    out = bytearray()
    for name, value in headers:
        check_value(value)
        if len(value) > 0xFFFF:
            raise ValueError("header value too long")
        index = STATIC_INDEX.get(name)
        if index:
            out += struct.pack("!BH", index, len(value))
        else:
            raw = name.encode("ascii")
            check_name(raw)
            if len(raw) > 0xFF:
                raise ValueError("header name too long")
            out += struct.pack("!BB", 0, len(raw)) + raw + struct.pack("!H", len(value))
        out += value
    return bytes(out)


def _need(buf: bytes, pos: int, n: int) -> None:
    if pos + n > len(buf):
        raise Malformed("header entry runs past the end of the payload")


def decode_headers(buf: bytes) -> Headers:
    headers: Headers = []
    pos = 0
    while pos < len(buf):
        index = buf[pos]
        pos += 1
        if index == 0:
            _need(buf, pos, 1)
            nlen = buf[pos]
            pos += 1
            _need(buf, pos, nlen)
            raw = buf[pos:pos + nlen]
            pos += nlen
            check_name(raw)
            name = raw.decode("ascii")
        elif index < len(STATIC_TABLE):
            name = STATIC_TABLE[index]
        else:
            raise Malformed("header index %d out of range" % index)
        _need(buf, pos, 2)
        (vlen,) = struct.unpack_from("!H", buf, pos)
        pos += 2
        _need(buf, pos, vlen)
        value = buf[pos:pos + vlen]
        pos += vlen
        check_value(value)
        headers.append((name, value))
    return headers


def header_values(headers: Headers, name: str) -> List[bytes]:
    return [v for n, v in headers if n == name]


def content_length(headers: Headers) -> Optional[int]:
    """The declared body length, None if absent; Malformed if not usable (§6)."""
    values = header_values(headers, "content-length")
    if not values:
        return None
    if len(set(values)) != 1 or not values[0].isdigit():
        raise Malformed("bad content-length %r" % values)
    return int(values[0])


# --- §5.1 REQUEST ----------------------------------------------------------

def check_path(path: bytes) -> None:
    if any(b < 0x20 or b == 0x7F for b in path):
        raise Malformed("control byte in path")
    before_query = path.split(b"?", 1)[0]
    if not before_query.startswith(b"/"):
        raise Malformed("path does not start with /")
    if any(seg in (b".", b"..") for seg in before_query.split(b"/")):
        raise Malformed("path has a . or .. segment")


def encode_request(method: int, path: bytes, headers: Headers) -> bytes:
    return struct.pack("!BH", method, len(path)) + path + encode_headers(headers)


def decode_request(payload: bytes) -> Tuple[int, bytes, Headers]:
    if len(payload) < 3:
        raise Malformed("REQUEST payload under 3 bytes")
    method, plen = struct.unpack_from("!BH", payload, 0)
    if method not in METHODS:
        raise Malformed("unknown method 0x%02x" % method)
    if plen == 0 or 3 + plen > len(payload):
        raise Malformed("Path Length %d is 0 or past the payload" % plen)
    path = payload[3:3 + plen]
    check_path(path)
    return method, path, decode_headers(payload[3 + plen:])


# --- §5.2 RESPONSE ---------------------------------------------------------

def encode_response(status: int, headers: Headers) -> bytes:
    return struct.pack("!H", status) + encode_headers(headers)


def decode_response(payload: bytes) -> Tuple[int, Headers]:
    if len(payload) < 2:
        raise Malformed("RESPONSE payload under 2 bytes")
    (status,) = struct.unpack_from("!H", payload, 0)
    if not 200 <= status <= 599:
        raise Malformed("status %d outside 200-599" % status)
    return status, decode_headers(payload[2:])


# --- §4 GOAWAY -------------------------------------------------------------

def encode_goaway(last_id: int, code: int) -> bytes:
    return struct.pack("!IB", last_id, code)


def decode_goaway(payload: bytes) -> Tuple[int, int]:
    """(Last-ID, Code); a short payload reads as (0, PROTOCOL_ERROR)."""
    if len(payload) < 5:
        return 0, GOAWAY_PROTOCOL_ERROR
    last_id, code = struct.unpack_from("!IB", payload, 0)
    if code not in (GOAWAY_NO_ERROR, GOAWAY_PROTOCOL_ERROR):
        code = GOAWAY_PROTOCOL_ERROR
    return last_id, code


# --- human-readable dumps (for -v) -----------------------------------------

def _hex(data: bytes, limit: int = 32) -> str:
    text = data[:limit].hex(" ")
    return text + (" ..." if len(data) > limit else "")


def _fmt_headers(headers: Headers) -> str:
    return ", ".join("%s: %s" % (n, v.decode("latin-1")) for n, v in headers)


def describe(frame: Frame) -> str:
    """One line describing a frame: header fields, then the decoded payload."""
    name = KNOWN_TYPES.get(frame.type, "UNKNOWN(0x%02x)" % frame.type)
    flags = "END" if frame.end else "-"
    if frame.flags & ~FLAG_END:
        flags += "|0x%02x" % (frame.flags & ~FLAG_END)
    head = "%s id=%d flags=%s len=%d" % (name, frame.rid, flags, len(frame.payload))
    try:
        if frame.type == REQUEST:
            method, path, hdrs = decode_request(frame.payload)
            detail = "%s %s [%s]" % (METHODS[method], path.decode("latin-1"), _fmt_headers(hdrs))
        elif frame.type == RESPONSE:
            status, hdrs = decode_response(frame.payload)
            detail = "%d [%s]" % (status, _fmt_headers(hdrs))
        elif frame.type == GOAWAY:
            last_id, code = decode_goaway(frame.payload)
            detail = "last-id=%d code=0x%02x" % (last_id, code)
        elif frame.type == DATA:
            detail = _hex(frame.payload, 16)
        else:
            detail = "skipped: " + _hex(frame.payload, 16)
    except Malformed as exc:
        detail = "MALFORMED (%s): %s" % (exc, _hex(frame.payload))
    header_hex = HEADER.pack(len(frame.payload), frame.type, frame.flags, frame.rid).hex(" ")
    return "%-60s  %s  %s" % (head, header_hex, detail)
