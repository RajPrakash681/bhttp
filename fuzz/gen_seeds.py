#!/usr/bin/env python3
"""Writes seed corpora for the libFuzzer harnesses into fuzz/seeds/<target>/.

The frames are the ones in SPEC.md section 10 and HEXDUMP.md, plus a few edge
cases (length boundaries, unknown types, GOAWAY, bodies)."""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "seeds")

STATIC = ["host", "user-agent", "accept", "content-type", "content-length",
          "last-modified", "date", "server", "location", "allow"]


def frame(t, flags, rid, payload=b""):
    return struct.pack(">HBBI", len(payload), t, flags, rid) + payload


def field(name, value, literal=False):
    v = value.encode() if isinstance(value, str) else value
    if name in STATIC and not literal:
        return bytes([STATIC.index(name) + 1]) + struct.pack(">H", len(v)) + v
    n = name.encode()
    return b"\x00" + bytes([len(n)]) + n + struct.pack(">H", len(v)) + v


def req_payload(path, method=1, fields=b""):
    p = path.encode() if isinstance(path, str) else path
    return bytes([method]) + struct.pack(">H", len(p)) + p + fields


def resp_payload(status, fields=b""):
    return struct.pack(">H", status) + fields


CLIENT_FIELDS = (field("host", "localhost:9000") + field("user-agent", "bcurl/1.0")
                 + field("accept", "*/*"))
SERVER_FIELDS = (field("content-type", "text/plain; charset=utf-8")
                 + field("content-length", "14")
                 + field("last-modified", "Thu, 08 Oct 2026 12:01:37 GMT")
                 + field("date", "Thu, 08 Oct 2026 12:08:46 GMT")
                 + field("server", "bserve/1.0"))

REQUESTS = [
    req_payload("/"),                                     # SPEC 10
    req_payload("/hello.txt", 1, CLIENT_FIELDS),          # HEXDUMP.md
    req_payload("/d/", 2),
    req_payload("/a?x=1", 3, field("x-a", "1", True)),
    req_payload("/x/../y"),
    req_payload("/%2e%2e/a", 5, field("content-length", "0")),
]
RESPONSES = [
    resp_payload(404),                                    # SPEC 10
    resp_payload(200, SERVER_FIELDS),                     # HEXDUMP.md
    resp_payload(301, field("location", "/d/")),
    resp_payload(405, field("allow", "GET, HEAD")),
    resp_payload(200, field("content-length", "5") + field("content-length", "005", True)),
]
BLOCKS = [CLIENT_FIELDS, SERVER_FIELDS, field("x-a", "1", True),
          field("content-length", "0000000000000000001"), b""]


def write(target, items):
    d = os.path.join(OUT, target)
    os.makedirs(d, exist_ok=True)
    for i, data in enumerate(items):
        with open(os.path.join(d, "seed%02d" % i), "wb") as f:
            f.write(data)


def main():
    frames = ([frame(1, 1, 1, r) for r in REQUESTS] +
              [frame(2, 1, 1, r) for r in RESPONSES] +
              [frame(3, 1, 1, b"Hello, bhttp!\n"), frame(4, 0, 0, struct.pack(">IB", 2, 0)),
               frame(0x42, 0xff, 0, b"junk"), frame(4, 0, 0, b"\x00"),
               frame(3, 0, 7, b"x" * 16384)])
    write("frame", frames)
    write("fields", BLOCKS)
    write("request", REQUESTS)
    write("url", [b"localhost:9000/hello.txt", b"bhttp://[::1]:9000/a?b#c", b"h?x",
                  b"h:65535", b"BHTTP://host/" + b"a" * 300, b"http://x/"])
    write("mappath", [p.encode() for p in [
        "/", "/a.txt", "/out", "/outx/secret", "/etc/passwd", "/d", "/d/", "/e/", "/in",
        "/loop", "/fifo", "/.hidden", "/a.txt?x", "/d/index.html"]])
    big = frame(1, 0, 3, req_payload("/a.txt")) + frame(3, 0, 3, b"b" * 16384) + \
        frame(0x42, 0, 0, b"") + frame(3, 1, 3, b"c")
    write("server", [
        frame(1, 1, 1, req_payload("/")),
        frame(1, 1, 1, req_payload("/b.bin", 1, CLIENT_FIELDS)) + frame(0x42, 0, 0, b"zz") +
        frame(1, 1, 2, req_payload("/x/../y")) + frame(1, 1, 3, req_payload("/d")),
        frame(1, 1, 1, req_payload("/a.txt", 2)) + frame(1, 1, 2, req_payload("/o")) +
        frame(1, 1, 3, req_payload("/e.txt")) + frame(1, 1, 4, req_payload("/x")),
        big,
        frame(3, 1, 9, b"") + frame(2, 1, 9, b"\x00\xc8") + frame(1, 1, 0, b""),
        frame(4, 0, 0, b"\x00\x00\x00\x00\x00"),
        b"GET / HTTP/1.1\r\n\r\n",
    ])
    ok = frame(2, 0, 1, resp_payload(200, SERVER_FIELDS)) + frame(3, 1, 1, b"Hello, bhttp!\n")
    ok2 = frame(2, 1, 2, resp_payload(404))
    ok3 = frame(2, 0, 3, resp_payload(200)) + frame(3, 0, 3, b"x" * 100) + frame(3, 1, 3, b"")
    write("client", [
        b"\x01" + ok + ok2 + ok3,
        b"\x00" + ok + frame(0x99, 0x80, 5, b"skip") + ok2 + ok3,
        b"\x01" + ok + frame(4, 0, 0, struct.pack(">IB", 1, 0)),
        b"\x01" + frame(2, 1, 0, resp_payload(400)),
        b"\x01" + frame(2, 0, 1, resp_payload(200, field("content-length", "3"))) +
        frame(3, 1, 1, b"abcd"),
    ])
    return 0


if __name__ == "__main__":
    sys.exit(main())
