"""Tests for bcurl: against bserve, and against scripted fake servers that are
written from SPEC.md (tests/bhttp_wire.py), not from the C code."""
import re
import socket
import struct
import time
import unittest

import harness
import bhttp_wire as w

EXPECTED_FIELDS = lambda port: (("host", "127.0.0.1:%d" % port), ("user-agent", "bcurl/1.0"),
                                ("accept", "*/*"))


def dumped_frames(stderr, direction):
    """Reassembles the frames from bcurl -v hexdump lines that start with `direction`."""
    frames, current = [], None
    for line in stderr.splitlines():
        m = re.match(r"^([<>])   ([0-9a-f]{4})  ", line)
        if not m or m.group(1) != direction:
            continue
        if m.group(2) == "0000":
            current = bytearray()
            frames.append(current)
        current += bytes.fromhex(line[10:line.index("|", 10)])
    return [bytes(f) for f in frames]


class TestAgainstBserve(harness.SiteServerCase, unittest.TestCase):

    def url(self, path):
        return "127.0.0.1:%d%s" % (self.server.port, path)

    def connects(self):
        return len(re.findall(r" connect$", self.server.log(), re.M))

    def closes(self):
        return len(re.findall(r" close \(", self.server.log(), re.M))

    def test_body_to_stdout(self):
        rc, out, err = harness.run_bcurl(self.url("/hello.txt"))
        self.assertEqual((rc, out, err), (0, self.file_bytes("hello.txt"), ""))

    def test_default_path_and_scheme_prefix(self):
        rc, out, _ = harness.run_bcurl("bhttp://127.0.0.1:%d" % self.server.port)
        self.assertEqual((rc, out), (0, self.file_bytes("index.html")))

    def test_large_body_is_reassembled(self):
        rc, out, _ = harness.run_bcurl(self.url("/big.bin"))
        self.assertEqual(rc, 0)
        self.assertEqual(out, self.file_bytes("big.bin"))

    def test_404_exits_4(self):
        rc, out, err = harness.run_bcurl(self.url("/missing"))
        self.assertEqual(rc, 4)
        self.assertEqual(out, b"404 Not Found\n")
        self.assertIn("404 Not Found", err)

    def test_400_exits_4(self):
        rc, out, _ = harness.run_bcurl(self.url("/../secret.txt"))
        self.assertEqual(rc, 4)
        self.assertNotIn(b"outside the root", out)

    def test_verbose_hexdumps_every_frame(self):
        rc, out, err = harness.run_bcurl("-v", self.url("/hello.txt"))
        self.assertEqual(rc, 0)
        self.assertEqual(out, self.file_bytes("hello.txt"))
        sent = dumped_frames(err, ">")
        self.assertEqual(sent, [w.request(1, "/hello.txt", fields=EXPECTED_FIELDS(self.server.port))])
        received = [w.parse_frames(f)[0] for f in dumped_frames(err, "<")]
        self.assertEqual([f.type for f in received], [w.RESPONSE, w.DATA])
        self.assertEqual(received[1].payload, self.file_bytes("hello.txt"))
        for summary in ("> REQUEST id=1 ", "< RESPONSE id=1 ", "< DATA id=1 "):
            self.assertIn(summary, err)

    def test_multiple_urls_share_one_connection(self):
        before_c, before_x = self.connects(), self.closes()
        paths = ("/hello.txt", "/style.css", "/index.html")
        rc, out, err = harness.run_bcurl("-v", *[self.url(p) for p in paths])
        self.assertEqual(rc, 0)
        self.assertEqual(out, b"".join(self.file_bytes(p[1:]) for p in paths))
        self.server.wait_for(r" close \(", count=before_x + 1)
        self.assertEqual(self.connects() - before_c, 1)
        self.assertIn("(peer closed, 3 requests)", self.server.log())
        self.assertEqual(err.count("* connected to"), 1)
        ids = [w.parse_frames(f)[0].id for f in dumped_frames(err, ">")]
        self.assertEqual(ids, [1, 2, 3])

    def test_worst_status_wins(self):
        rc, _, _ = harness.run_bcurl(self.url("/hello.txt"), self.url("/nope"),
                                     self.url("/hello.txt"))
        self.assertEqual(rc, 4)

    def test_different_origins_refused_before_connecting(self):
        before = self.connects()
        rc, out, err = harness.run_bcurl(self.url("/a"), "localhost:%d/b" % self.server.port)
        self.assertEqual((rc, out), (1, b""))
        self.assertIn("one connection", err)
        time.sleep(0.2)
        self.assertEqual(self.connects(), before)

    def test_usage_errors_exit_1(self):
        self.assertEqual(harness.run_bcurl()[0], 1)
        self.assertEqual(harness.run_bcurl("http://127.0.0.1:9/")[0], 1)
        self.assertEqual(harness.run_bcurl("127.0.0.1:99999/")[0], 1)
        self.assertEqual(harness.run_bcurl("127.0.0.1:x/")[0], 1)
        self.assertEqual(harness.run_bcurl("-h")[0], 0)


def reply(status, body=b"", fields=(), rid_override=None, end_on_response=None):
    """A response script step: RESPONSE (+ one DATA frame if there is a body)."""
    def build(rid):
        rid2 = rid if rid_override is None else rid_override
        block = w.header_block(list(fields) + [("content-length", str(len(body)))])
        end = (not body) if end_on_response is None else end_on_response
        out = w.frame(w.RESPONSE, w.END if end else 0, rid2, struct.pack(">H", status) + block)
        if body:
            out += w.frame(w.DATA, w.END, rid2, body)
        return out
    return build


def scripted(steps, seen=None):
    """Fake-server handler: for each request, send the next step's bytes."""
    def handler(conn):
        for step in steps:
            f = w.read_frame(conn)
            if f is None:
                return
            if seen is not None:
                seen.append(f)
            data = step(f.id) if callable(step) else step
            if data is None:   # close now
                return
            conn.sendall(data)
        while w.read_frame(conn) is not None:
            pass
    return handler


class TestAgainstFakeServer(unittest.TestCase):

    def fetch(self, fake, *paths):
        return harness.run_bcurl(*["127.0.0.1:%d%s" % (fake.port, p) for p in paths])

    def test_request_frames_follow_the_spec(self):
        seen = []
        steps = [reply(200, b"a"), reply(200, b"b"), reply(200, b"c")]
        with harness.FakeServer(scripted(steps, seen)) as fake:
            rc, out, _ = self.fetch(fake, "/x", "/y?q=1#frag", "#top")
        self.assertEqual((rc, out), (0, b"abc"))
        fields = EXPECTED_FIELDS(fake.port)
        self.assertEqual(seen[0], w.parse_frames(w.request(1, "/x", fields=fields))[0])
        self.assertEqual(seen[1], w.parse_frames(w.request(2, "/y?q=1", fields=fields))[0])
        self.assertEqual(seen[2], w.parse_frames(w.request(3, "/", fields=fields))[0])
        self.assertEqual(w.raw_entry_indices(seen[0].payload[5:]), [1, 2, 3])

    def test_url_forms(self):
        seen = []
        steps = [reply(200, b"a"), reply(200, b"b"), reply(200, b"c")]
        with harness.FakeServer(scripted(steps, seen)) as fake:
            rc, out, _ = harness.run_bcurl("127.0.0.1:%d?x=1" % fake.port,
                                           "bhttp://127.0.0.1:%d#frag" % fake.port,
                                           "127.0.0.1:%d/a?b#c" % fake.port)
        self.assertEqual((rc, out), (0, b"abc"))
        paths = [w.parse_request(f.payload)[1] for f in seen]
        self.assertEqual(paths, [b"/?x=1", b"/", b"/a?b"])

    def test_identical_content_length_copies_are_fine(self):
        step = reply(200, b"ok", fields=[("content-length", "02")])
        with harness.FakeServer(scripted([step])) as fake:
            self.assertEqual(self.fetch(fake, "/"), (0, b"ok", ""))

    def test_unknown_frames_are_skipped(self):
        def step(rid):
            return (w.frame(0x42, 0, 0, b"hello from v2") +
                    w.frame(0x99, 0xFF, rid, b"") +
                    w.frame(w.RESPONSE, 0, rid, b"\x00\xc8" + w.header_block([("content-length", "4")])) +
                    w.frame(0x7F, w.END, rid, b"\x00" * w.MAX_PAYLOAD) +
                    w.frame(w.DATA, 0, rid, b"ok") +
                    w.frame(0x80, 0, 0, b"x") +
                    w.frame(w.DATA, w.END, rid, b"!\n"))
        with harness.FakeServer(scripted([step])) as fake:
            rc, out, err = self.fetch(fake, "/")
        self.assertEqual((rc, out, err), (0, b"ok!\n", ""))
        self.assertEqual(fake.accepted, 1)

    def test_5xx_exits_5(self):
        with harness.FakeServer(scripted([reply(500, b"boom\n")])) as fake:
            self.assertEqual(self.fetch(fake, "/")[0], 5)
        with harness.FakeServer(scripted([reply(404), reply(503), reply(200)])) as fake:
            self.assertEqual(self.fetch(fake, "/a", "/b", "/c")[0], 5)
        with harness.FakeServer(scripted([reply(503), reply(404)])) as fake:
            self.assertEqual(self.fetch(fake, "/a", "/b")[0], 5)

    def test_3xx_exits_0(self):
        with harness.FakeServer(scripted([reply(301, fields=[("location", "/x/")])])) as fake:
            self.assertEqual(self.fetch(fake, "/x")[0], 0)

    BROKEN = [
        ("oversized frame", lambda rid: struct.pack(">HBBI", 20000, w.RESPONSE, 0, rid)),
        ("GOAWAY first", lambda rid: w.goaway(0, w.NO_ERROR)),
        ("wrong id", reply(200, b"x", rid_override=77)),
        ("connection error id 0", reply(400, b"x", rid_override=0)),
        ("DATA before RESPONSE", lambda rid: w.frame(w.DATA, w.END, rid, b"x")),
        ("EOF mid-body", lambda rid: w.frame(w.RESPONSE, 0, rid, b"\x00\xc8") +
            w.frame(w.DATA, 0, rid, b"partial")),
        ("EOF before RESPONSE", None),
        ("content-length mismatch", lambda rid: w.frame(w.RESPONSE, 0, rid, b"\x00\xc8" +
            w.header_block([("content-length", "9")])) + w.frame(w.DATA, w.END, rid, b"abc")),
        ("status 100", lambda rid: w.frame(w.RESPONSE, w.END, rid, b"\x00\x64")),
        ("status 600", lambda rid: w.frame(w.RESPONSE, w.END, rid, b"\x02\x58")),
        ("bad header index", lambda rid: w.frame(w.RESPONSE, w.END, rid, b"\x00\xc8\x0b\x00\x00")),
        ("second RESPONSE", lambda rid: w.frame(w.RESPONSE, 0, rid, b"\x00\xc8") * 2),
        ("conflicting content-length", lambda rid: w.frame(w.RESPONSE, 0, rid, b"\x00\xc8" +
            w.header_block([("content-length", "2"), ("content-length", "3")])) +
            w.frame(w.DATA, w.END, rid, b"ab")),
        ("content-length not digits", lambda rid: w.frame(w.RESPONSE, w.END, rid, b"\x00\xc8" +
            w.header_block([("content-length", "+0")]))),
        ("server sends REQUEST", lambda rid: w.request(rid, "/")),
    ]

    def test_protocol_errors_exit_2(self):
        for what, step in self.BROKEN:
            with self.subTest(what):
                with harness.FakeServer(scripted([step])) as fake:
                    rc, _, err = self.fetch(fake, "/")
                self.assertEqual(rc, 2, err)
                self.assertTrue(err.startswith("bcurl: "), err)

    def test_never_opens_a_second_connection(self):
        with harness.FakeServer(scripted([reply(200, b"one"), None])) as fake:
            rc, out, err = self.fetch(fake, "/1", "/2", "/3")
            time.sleep(0.3)
            self.assertEqual(fake.accepted, 1)
        self.assertEqual((rc, out), (2, b"one"))
        self.assertIn("not fetching the remaining", err)

    def test_no_request_after_goaway(self):
        seen = []
        first = lambda rid: reply(200, b"one")(rid) + w.goaway(rid, w.NO_ERROR)
        with harness.FakeServer(scripted([first, reply(200, b"two")], seen)) as fake:
            rc, out, err = self.fetch(fake, "/1", "/2")
        self.assertEqual((rc, out), (2, b"one"))
        self.assertIn("not sending more requests", err)
        self.assertEqual([f.type for f in seen], [w.REQUEST])

    def test_unknown_frames_between_responses_are_skipped(self):
        first = lambda rid: reply(200, b"one")(rid) + w.frame(0x55, 0, 0, b"ping?")
        with harness.FakeServer(scripted([first, reply(200, b"two")])) as fake:
            rc, out, _ = self.fetch(fake, "/1", "/2")
        self.assertEqual((rc, out), (0, b"onetwo"))

    def test_connection_refused_exits_2(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        rc, _, err = harness.run_bcurl("127.0.0.1:%d/" % port)
        self.assertEqual(rc, 2)
        self.assertIn("cannot connect", err)


if __name__ == "__main__":
    unittest.main()
