#!/usr/bin/env python3
"""Connection-flood regression check for bserve (one process per connection).

Starts its own bserve on 127.0.0.1 with a short idle timeout, opens --conns
connections and keeps each alive by sending an unknown frame (type 0x42, which
SPEC 4 says must be skipped) every second for --hold seconds, i.e. well past
the idle timeout. It records how many connection processes bserve forks, then
checks that a fresh client still gets an answer, and that everything drains
once the flood stops.

    python3 fuzz/conn_flood.py [--conns 200] [--hold 10] [--cap 128]

BSERVE overrides the binary (default: the release build ./bserve, since 200
ASan processes would need several GB). PASS needs: the listener survives, the
peak number of connection processes stays <= --cap, a request made after the
flood is answered, and no connection processes are left behind.
"""
import argparse
import os
import shutil
import socket
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netfuzz as nf  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conns", type=int, default=200)
    ap.add_argument("--hold", type=float, default=10.0)
    ap.add_argument("--idle", type=int, default=3)
    ap.add_argument("--cap", type=int, default=128)
    a = ap.parse_args()
    nf.BSERVE = os.path.abspath(os.environ.get("BSERVE", os.path.join(nf.REPO, "bserve")))

    base = tempfile.mkdtemp(prefix="flood-")
    root = os.path.join(base, "root")
    os.mkdir(root)
    with open(os.path.join(root, "hello.txt"), "w") as f:
        f.write("Hello, bhttp!\n")
    srv = nf.Bserve(root, idle=a.idle)
    socks, refused, peak, during = [], 0, 0, None
    findings = []
    try:
        for _ in range(a.conns):
            try:
                s = socket.create_connection(("127.0.0.1", srv.port), timeout=2)
                socks.append(s)
            except OSError:
                refused += 1
        t_end = time.time() + a.hold
        while time.time() < t_end:
            alive = []
            for s in socks:
                try:
                    s.sendall(nf.frame(0x42, 0, 0, b""))
                    alive.append(s)
                except OSError:
                    s.close()
            socks = alive
            peak = max(peak, len(srv.children()))
            time.sleep(1)
        open_after_hold = len(socks)
        # a well-behaved client during the flood
        try:
            r, why = nf.get(srv, "/hello.txt", ctx="during flood")
            during = r[0] if r else why
        except OSError as e:
            during = "connect failed: %s" % e
        for s in socks:
            s.close()
        socks = []
        time.sleep(a.idle + 1)
        r, why = nf.get(srv, "/hello.txt", ctx="after flood")
        after = r[0] if r else why
        time.sleep(1)
        left = len(srv.children())
        print("conns opened %d (refused %d), still open after %.0fs of unknown-frame keepalive "
              "with idle timeout %ds: %d" % (a.conns - refused, refused, a.hold, a.idle,
                                              open_after_hold))
        print("peak connection processes %d (cap %d); request during flood -> %s; "
              "after flood -> %s; processes left %d" % (peak, a.cap, during, after, left))
        if srv.p.poll() is not None:
            findings.append("listener exited with %r" % srv.p.returncode)
        if peak > a.cap:
            findings.append("peak connection processes %d > cap %d (no limit on forks)"
                            % (peak, a.cap))
        if after != 200:
            findings.append("request after the flood: %s" % after)
        if left:
            findings.append("%d connection processes left after the flood" % left)
        san = srv.sanitizer()
        if san:
            findings.append("sanitizer output: %s" % san[:3])
    finally:
        for s in socks:
            s.close()
        srv.stop()
        shutil.rmtree(base, ignore_errors=True)
    for f in findings:
        print("FAIL " + f)
    print("PASS" if not findings else "%d finding(s)" % len(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
