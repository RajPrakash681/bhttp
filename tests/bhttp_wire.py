"""bhttp/1 on the wire, written from SPEC.md alone.

This module is the second, independent implementation the conformance tests
use to talk to bserve and to check bcurl. It shares no code with src/: every
constant and layout below is taken from the spec, with the section noted.
"""
import collections
import socket
import struct

# SPEC 3: Length 16 | Type 8 | Flags 8 | Request ID 32, big-endian.
HEADER = struct.Struct(">HBBI")
HEADER_LEN = HEADER.size  # 8
MAX_PAYLOAD = 16384

# SPEC 4: frame types and flags.
REQUEST, RESPONSE, DATA, GOAWAY = 0x01, 0x02, 0x03, 0x04
KNOWN_TYPES = (REQUEST, RESPONSE, DATA, GOAWAY)
END = 0x01
NO_ERROR, PROTOCOL_ERROR = 0x00, 0x01

# SPEC 5.1: method codes.
GET, HEAD, POST, PUT, DELETE = 0x01, 0x02, 0x03, 0x04, 0x05

# SPEC 5.3: the static table, indices 1..10.
STATIC_TABLE = (
    "host", "user-agent", "accept", "content-type", "content-length",
    "last-modified", "date", "server", "location", "allow",
)
TOKEN_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~")


class ProtocolError(Exception):
    """The peer broke the spec."""


Frame = collections.namedtuple("Frame", "type flags id payload")


def _b(s):
    return s.encode("utf-8") if isinstance(s, str) else bytes(s)


# ---- encoding ---------------------------------------------------------------

def frame(ftype, flags, rid, payload=b""):
    """One frame: the 8-byte header then the payload (no length check)."""
    return HEADER.pack(len(payload), ftype, flags, rid) + payload


def field(name, value, literal=False):
    """One header block entry, indexed when the name is in the table."""
    n, v = _b(name), _b(value)
    if not literal and n.decode("latin-1") in STATIC_TABLE:
        head = bytes([STATIC_TABLE.index(n.decode("latin-1")) + 1])
    else:
        head = bytes([0, len(n)]) + n
    return head + struct.pack(">H", len(v)) + v


def header_block(fields):
    return b"".join(field(n, v) for n, v in fields)


def request_payload(method, path, fields=()):
    p = _b(path)
    return bytes([method]) + struct.pack(">H", len(p)) + p + header_block(fields)


DEFAULT_FIELDS = (("host", "conformance"), ("user-agent", "bhttp-conformance/1"))


def request(rid, path, method=GET, fields=DEFAULT_FIELDS, flags=END):
    return frame(REQUEST, flags, rid, request_payload(method, path, fields))


def goaway(last_id=0, code=NO_ERROR):
    return frame(GOAWAY, 0, 0, struct.pack(">IB", last_id, code))


# ---- decoding ---------------------------------------------------------------

def parse_header_block(data):
    """[(name, value bytes)] in order; ProtocolError if malformed (SPEC 5.3)."""
    out, off, n = [], 0, len(data)
    while off < n:
        index = data[off]
        off += 1
        if index > len(STATIC_TABLE):
            raise ProtocolError("header index %d out of range" % index)
        if index == 0:
            if off >= n:
                raise ProtocolError("truncated before name length")
            nlen = data[off]
            off += 1
            name = data[off:off + nlen]
            if nlen == 0 or len(name) != nlen:
                raise ProtocolError("empty or truncated name")
            if any(c not in TOKEN_BYTES for c in name):
                raise ProtocolError("bad byte in name %r" % name)
            off += nlen
            name = name.decode("ascii")
        else:
            name = STATIC_TABLE[index - 1]
        if n - off < 2:
            raise ProtocolError("truncated before value length")
        (vlen,) = struct.unpack_from(">H", data, off)
        off += 2
        value = data[off:off + vlen]
        if len(value) != vlen:
            raise ProtocolError("value runs past the payload")
        if any(c in (0x00, 0x0A, 0x0D) for c in value):
            raise ProtocolError("NUL/CR/LF in value")
        off += vlen
        out.append((name, value))
    return out


def raw_entry_indices(data):
    """The Index byte of every entry in a well-formed block, in order."""
    indices, off = [], 0
    while off < len(data):
        index = data[off]
        indices.append(index)
        off += 1
        if index == 0:
            off += 1 + data[off]
        (vlen,) = struct.unpack_from(">H", data, off)
        off += 2 + vlen
    return indices


def parse_request(payload):
    """(method, path bytes, fields) of a REQUEST payload (SPEC 5.1)."""
    if len(payload) < 3:
        raise ProtocolError("REQUEST payload under 3 bytes")
    method = payload[0]
    (plen,) = struct.unpack_from(">H", payload, 1)
    if plen == 0 or plen > len(payload) - 3:
        raise ProtocolError("bad path length")
    return method, payload[3:3 + plen], parse_header_block(payload[3 + plen:])


def parse_response(payload):
    """(status, fields) of a RESPONSE payload (SPEC 5.2)."""
    if len(payload) < 2:
        raise ProtocolError("RESPONSE payload under 2 bytes")
    (status,) = struct.unpack_from(">H", payload, 0)
    if not 200 <= status <= 599:
        raise ProtocolError("status %d outside 200-599" % status)
    return status, parse_header_block(payload[2:])


def parse_goaway(payload):
    """(last_id, code); a short payload reads as (0, PROTOCOL_ERROR) (SPEC 4)."""
    if len(payload) < 5:
        return 0, PROTOCOL_ERROR
    return struct.unpack_from(">IB", payload, 0)


def parse_frames(data):
    """Splits a byte string into frames; raises if anything is left over."""
    frames, off = [], 0
    while off < len(data):
        if len(data) - off < HEADER_LEN:
            raise ProtocolError("trailing partial header")
        length, ftype, flags, rid = HEADER.unpack_from(data, off)
        off += HEADER_LEN
        if length > MAX_PAYLOAD or len(data) - off < length:
            raise ProtocolError("bad length")
        frames.append(Frame(ftype, flags, rid, data[off:off + length]))
        off += length
    return frames


# ---- socket helpers ---------------------------------------------------------

def recv_exact(sock, n):
    """n bytes, or fewer only if the peer closed (b'' if it closed at once)."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except ConnectionResetError:
            chunk = b""
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def read_frame(sock):
    """The next frame, or None on a clean EOF. Enforces the Length limit."""
    head = recv_exact(sock, HEADER_LEN)
    if not head:
        return None
    if len(head) < HEADER_LEN:
        raise ProtocolError("EOF inside a frame header")
    length, ftype, flags, rid = HEADER.unpack(head)
    if length > MAX_PAYLOAD:
        raise ProtocolError("frame length %d > %d" % (length, MAX_PAYLOAD))
    payload = recv_exact(sock, length)
    if len(payload) < length:
        raise ProtocolError("EOF inside a frame payload")
    return Frame(ftype, flags, rid, payload)


class Response(object):
    def __init__(self, rid):
        self.id = rid
        self.status = None
        self.fields = []
        self.raw_block = b""
        self.body = b""
        self.frames = []          # RESPONSE and DATA frames, in order
        self.skipped = []         # unknown-type frames seen in between

    def header(self, name):
        for n, v in self.fields:
            if n == name:
                return v.decode("latin-1")
        return None


def read_response(sock, rid):
    """Reads one complete response for request `rid`, checking SPEC 6 and 7."""
    resp = Response(rid)
    while True:
        f = read_frame(sock)
        if f is None:
            raise ProtocolError("EOF before END")
        if f.type not in KNOWN_TYPES:
            resp.skipped.append(f)
            continue
        if f.type == GOAWAY:
            raise ProtocolError("GOAWAY before END: %r" % (parse_goaway(f.payload),))
        if f.type == REQUEST:
            raise ProtocolError("server sent a REQUEST")
        if f.id != rid:
            raise ProtocolError("frame for id %d, expected %d" % (f.id, rid))
        resp.frames.append(f)
        if f.type == RESPONSE:
            if resp.status is not None:
                raise ProtocolError("second RESPONSE")
            resp.status, resp.fields = parse_response(f.payload)
            resp.raw_block = f.payload[2:]
        elif resp.status is None:
            raise ProtocolError("DATA before RESPONSE")
        else:
            resp.body += f.payload
        if f.flags & END:
            return resp


def connect(port, timeout=15.0):
    """A client socket; the timeout is generous for sanitizer builds on busy machines."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s
