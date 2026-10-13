"""Shows bserve skipping an unknown frame and closing an idle connection with GOAWAY.

    ./bserve -t 1 ./www 9000 &
    python3 tools/wire_demo.py localhost 9000

Sends an unknown frame (type 0x42) and then GET /hello.txt, and waits. The
server ignores the unknown frame, answers the request, and once its idle
timeout passes sends GOAWAY and closes. Every frame, in both directions, is
hexdumped in the same format as bcurl -v. Frames are built and parsed with
tests/bhttp_wire.py, the Python implementation written from SPEC.md.
"""
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"))
import bhttp_wire as w  # noqa: E402

NAMES = {w.REQUEST: "REQUEST", w.RESPONSE: "RESPONSE", w.DATA: "DATA", w.GOAWAY: "GOAWAY"}


def dump(direction, raw):
    length, ftype, flags, rid = w.HEADER.unpack_from(raw)
    name = NAMES.get(ftype, "type 0x%02x" % ftype)
    end = " (END)" if flags & w.END else ""
    print("%s %s id=%d length=%d flags=0x%02x%s" % (direction, name, rid, length, flags, end))
    for off in range(0, len(raw), 16):
        row = raw[off:off + 16]
        hexes = " ".join("%02x" % b for b in row[:8])
        if len(row) > 8:
            hexes += "  " + " ".join("%02x" % b for b in row[8:])
        text = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in row)
        print("%s   %04x  %-49s |%s|" % (direction, off, hexes, text))


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: wire_demo.py HOST PORT")
    host, port = sys.argv[1], int(sys.argv[2])
    sock = socket.create_connection((host, port), timeout=60)
    sent = [w.frame(0x42, 0, 0, b"v2 hello"),
            w.request(1, "/hello.txt", fields=[("host", "%s:%d" % (host, port))])]
    for raw in sent:
        dump(">", raw)
    sock.sendall(b"".join(sent))
    start = time.time()
    while True:
        f = w.read_frame(sock)
        if f is None:
            print("* server closed the connection after %.1f s" % (time.time() - start))
            break
        dump("<", w.frame(f.type, f.flags, f.id, f.payload))
    sock.close()


if __name__ == "__main__":
    main()
