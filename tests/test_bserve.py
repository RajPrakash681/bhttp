"""Conformance tests for bserve, speaking raw bytes built from SPEC.md."""
import os
import random
import socket
import struct
import sys
import time
import unittest

import harness
import bhttp_wire as w


class ServerCase(harness.SiteServerCase, unittest.TestCase):

    def setUp(self):
        self.sock = w.connect(self.server.port)

    def tearDown(self):
        self.sock.close()

    # -- helpers ------------------------------------------------------------

    def get(self, path, rid=1, method=w.GET, fields=w.DEFAULT_FIELDS, sock=None):
        sock = sock or self.sock
        sock.sendall(w.request(rid, path, method, fields))
        return w.read_response(sock, rid)

    def assert_alive(self, rid=99):
        """The connection still serves requests."""
        r = self.get("/hello.txt", rid)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, self.file_bytes("hello.txt"))

    def assert_400_and_close(self, sock):
        """SPEC 7, connection error: 400 with ID 0, GOAWAY 0x01, then EOF."""
        r = w.read_response(sock, 0)
        self.assertEqual(r.status, 400)
        f = w.read_frame(sock)
        self.assertIsNotNone(f, "expected GOAWAY before close")
        self.assertEqual(f.type, w.GOAWAY)
        self.assertEqual(f.id, 0)
        self.assertEqual(w.parse_goaway(f.payload)[1], w.PROTOCOL_ERROR)
        self.assertIsNone(w.read_frame(sock), "expected the server to close")


class TestBasics(ServerCase):

    def test_get_index_200(self):
        r = self.get("/index.html", rid=7)
        body = self.file_bytes("index.html")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, body)
        self.assertEqual(r.header("content-type"), "text/html; charset=utf-8")
        self.assertEqual(r.header("content-length"), str(len(body)))
        for name in ("date", "server", "last-modified"):
            self.assertIsNotNone(r.header(name), name)
        self.assertTrue(all(f.id == 7 for f in r.frames))
        self.assertEqual(r.frames[0].type, w.RESPONSE)
        self.assertFalse(r.frames[0].flags & w.END)
        self.assertTrue(r.frames[-1].flags & w.END)
        self.assertTrue(all(f.flags & ~w.END == 0 for f in r.frames), "reserved flag bits sent")

    def test_static_table_names_sent_indexed(self):
        r = self.get("/index.html")
        indices = w.raw_entry_indices(r.raw_block)
        self.assertTrue(indices and all(1 <= i <= 10 for i in indices), indices)

    def test_root_maps_to_index_html(self):
        self.assertEqual(self.get("/").body, self.file_bytes("index.html"))

    def test_content_types(self):
        for path, ctype in (("/style.css", "text/css; charset=utf-8"),
                            ("/logo.png", "image/png"),
                            ("/hello.txt", "text/plain; charset=utf-8"),
                            ("/big.bin", "application/octet-stream")):
            r = self.get(path)
            self.assertEqual(r.header("content-type"), ctype, path)

    def test_head_has_headers_and_no_body(self):
        r = self.get("/index.html", rid=3, method=w.HEAD)
        self.assertEqual(r.status, 200)
        self.assertEqual(len(r.frames), 1)
        self.assertTrue(r.frames[0].flags & w.END)
        self.assertEqual(r.header("content-length"), str(len(self.file_bytes("index.html"))))
        self.assert_alive(4)  # and no stray DATA frames follow

    def test_404(self):
        r = self.get("/missing.html")
        self.assertEqual(r.status, 404)
        self.assertEqual(r.header("content-type"), "text/plain; charset=utf-8")
        self.assertEqual(r.header("content-length"), str(len(r.body)))
        self.assert_alive()

    def test_empty_file(self):
        r = self.get("/empty.txt")
        self.assertEqual((r.status, r.body, r.header("content-length")), (200, b"", "0"))

    def test_query_is_ignored(self):
        self.assertEqual(self.get("/hello.txt?x=1&y=/../z").body, self.file_bytes("hello.txt"))

    def test_raw_bytes_no_percent_decoding(self):
        self.assertEqual(self.get("/with space.txt").body, self.file_bytes("with space.txt"))
        self.assertEqual(self.get("/%2e%2e").body, self.file_bytes("%2e%2e"))

    def test_literal_and_unknown_request_headers(self):
        fields = w.field("host", "x", literal=True) + w.field("x-trace-id", "abc") + \
            w.field("accept", "")
        payload = bytes([w.GET]) + struct.pack(">H", 10) + b"/hello.txt" + fields
        self.sock.sendall(w.frame(w.REQUEST, w.END, 5, payload))
        self.assertEqual(w.read_response(self.sock, 5).status, 200)

    def test_no_headers_at_all(self):
        # SPEC 10 worked example: GET / with no headers.
        self.sock.sendall(bytes.fromhex("00040101 00000001 0100012f"))
        self.assertEqual(w.read_response(self.sock, 1).status, 200)

    def test_reserved_flag_bits_ignored(self):
        self.sock.sendall(w.request(2, "/hello.txt", flags=w.END | 0xFE))
        self.assertEqual(w.read_response(self.sock, 2).status, 200)

    def test_directory_redirect(self):
        r = self.get("/sub")
        self.assertEqual(r.status, 301)
        self.assertEqual(r.header("location"), "/sub/")
        self.assertEqual(self.get("/sub/").body, self.file_bytes("sub/index.html"))
        self.assertEqual(self.get("/sub?x=1").header("location"), "/sub/")
        self.assertEqual(self.get("/no-index").status, 301)
        self.assertEqual(self.get("/no-index/").status, 404)   # no listing, no loop

    def test_405_for_unimplemented_methods(self):
        for i, method in enumerate((w.POST, w.PUT, w.DELETE)):
            r = self.get("/hello.txt", rid=10 + i, method=method)
            self.assertEqual(r.status, 405)
            self.assertEqual(r.header("allow"), "GET, HEAD")
        self.assert_alive()


class TestPersistence(ServerCase):

    def test_three_requests_one_connection(self):
        for rid, path in ((1, "/index.html"), (2, "/style.css"), (3, "/hello.txt")):
            r = self.get(path, rid)
            self.assertEqual(r.status, 200)
            self.assertEqual(r.body, self.file_bytes(path[1:]))
        peer = self.sock.getsockname()[1]
        self.sock.close()
        self.server.wait_for(r"127\.0\.0\.1:%d close" % peer)
        lines = self.server.peer_lines(peer)
        self.assertEqual(sum(l.endswith(" connect") for l in lines), 1, lines)
        self.assertEqual(sum(" GET /" in l for l in lines), 3, lines)
        self.assertIn("3 requests", lines[-1])

    def test_pipelined_requests_answered_in_order(self):
        self.sock.sendall(w.request(1, "/hello.txt") + w.request(2, "/style.css"))
        self.assertEqual(w.read_response(self.sock, 1).body, self.file_bytes("hello.txt"))
        self.assertEqual(w.read_response(self.sock, 2).body, self.file_bytes("style.css"))

    def test_many_requests_one_connection(self):
        for rid in range(1, 101):
            self.assertEqual(self.get("/hello.txt", rid).status, 200)

    def test_client_goaway_closes(self):
        self.sock.sendall(w.goaway())
        self.assertIsNone(w.read_frame(self.sock))

    def test_goaway_id_and_extra_bytes_are_ignored(self):
        self.sock.sendall(w.frame(w.GOAWAY, w.END, 77, b"\x00\x00\x00\x00\x00debug"))
        self.assertIsNone(w.read_frame(self.sock))


class TestBodies(ServerCase):

    def check_multi_frame(self, name, size):
        r = self.get("/" + name, rid=21)
        data = r.frames[1:]
        self.assertEqual(r.status, 200)
        self.assertEqual(r.header("content-length"), str(size))
        self.assertGreater(len(data), 1)
        self.assertTrue(all(f.type == w.DATA and f.id == 21 for f in data))
        self.assertTrue(all(len(f.payload) <= w.MAX_PAYLOAD for f in data))
        self.assertTrue(all(not f.flags & w.END for f in data[:-1]))
        self.assertTrue(data[-1].flags & w.END)
        self.assertEqual(r.body, self.file_bytes(name))

    def test_large_file_multiple_data_frames(self):
        self.check_multi_frame("big.bin", harness.BIG_SIZE)

    def test_exact_multiple_of_max_payload(self):
        self.check_multi_frame("exact.bin", harness.EXACT_SIZE)

    def test_request_body_is_read_then_405(self):
        self.sock.sendall(
            w.request(4, "/hello.txt", method=w.POST, flags=0) +
            w.frame(w.DATA, 0, 4, b"x" * 1000) +
            w.frame(0x66, 0, 4, b"unknown inside a body") +
            w.frame(w.DATA, 0, 4, b"y" * w.MAX_PAYLOAD) +
            w.frame(w.DATA, w.END, 4, b""))
        r = w.read_response(self.sock, 4)
        self.assertEqual(r.status, 405)
        self.assert_alive()

    def test_get_with_body_is_served(self):
        self.sock.sendall(w.request(6, "/hello.txt", flags=0) + w.frame(w.DATA, w.END, 6, b"ab"))
        self.assertEqual(w.read_response(self.sock, 6).body, self.file_bytes("hello.txt"))

    def test_malformed_request_with_body_still_drains_body(self):
        bad = w.frame(w.REQUEST, 0, 8, bytes([w.GET]) + b"\x00\x09/x")  # path past end
        self.sock.sendall(bad + w.frame(w.DATA, w.END, 8, b"body"))
        self.assertEqual(w.read_response(self.sock, 8).status, 400)
        self.assert_alive()

    def test_other_request_inside_body_is_connection_error(self):
        self.sock.sendall(w.request(5, "/hello.txt", flags=0) + w.request(6, "/hello.txt"))
        self.assert_400_and_close(self.sock)


class TestUnknownFrames(ServerCase):

    def test_unknown_types_before_request_are_skipped(self):
        junk = (w.frame(0x00, 0, 0, b"") +
                w.frame(0x05, 0, 1, b"abc") +
                w.frame(0x7F, 0xFF, 0, os.urandom(100)) +
                w.frame(0x80, w.END, 7, os.urandom(w.MAX_PAYLOAD)) +
                w.frame(0xFF, 0, 0xFFFFFFFF, b"\x00" * 9))
        self.sock.sendall(junk + w.request(11, "/hello.txt"))
        f = w.read_frame(self.sock)   # nothing may precede the RESPONSE
        self.assertEqual((f.type, f.id), (w.RESPONSE, 11))
        self.assertEqual(w.parse_response(f.payload)[0], 200)

    def test_unknown_types_between_requests(self):
        for rid in range(1, 6):
            self.sock.sendall(w.frame(0x10 + rid, 0, rid, b"v2 stuff") + w.request(rid, "/"))
            self.assertEqual(w.read_response(self.sock, rid).status, 200)


class TestErrors(ServerCase):

    MALFORMED = [
        ("empty payload", b""),
        ("2-byte payload", b"\x01\x00"),
        ("3-byte payload", b"\x01\x00\x00"),
        ("method 0", b"\x00\x00\x01/"),
        ("method 6", b"\x06\x00\x01/"),
        ("method 0xff", b"\xff\x00\x01/"),
        ("empty path", b"\x01\x00\x00"),
        ("path past end", b"\x01\x00\x09/x"),
        ("path length 0xffff", b"\x01\xff\xff/"),
        ("no leading slash", b"\x01\x00\x09hello.txt"),
        ("dot-dot", b"\x01\x00\x0e/../secret.txt"),
        ("nested dot-dot", b"\x01\x00\x12/sub/../../secret"),
        ("dot segment", b"\x01\x00\x0c/./hello.txt"),
        ("NUL in path", b"\x01\x00\x0e/hello.txt\x00.png"),
        ("tab in path", b"\x01\x00\x03/\ta"),
        ("DEL in path", b"\x01\x00\x03/a\x7f"),
        ("header index 11", b"\x01\x00\x01/\x0b\x00\x00"),
        ("header index 255", b"\x01\x00\x01/\xff\x00\x00"),
        ("truncated entry", b"\x01\x00\x01/\x01\x00"),
        ("value past end", b"\x01\x00\x01/\x01\x00\x05ab"),
        ("empty literal name", b"\x01\x00\x01/\x00\x00\x00\x00"),
        ("uppercase name", b"\x01\x00\x01/\x00\x04Host\x00\x00"),
        ("colon in name", b"\x01\x00\x01/\x00\x02a:\x00\x00"),
        ("CR in value", b"\x01\x00\x01/\x01\x00\x03a\rb"),
        ("LF in value", b"\x01\x00\x01/\x01\x00\x01\n"),
        ("NUL in value", b"\x01\x00\x01/\x01\x00\x01\x00"),
    ]

    def test_malformed_payload_400_keeps_connection(self):
        for i, (what, payload) in enumerate(self.MALFORMED):
            with self.subTest(what):
                rid = 100 + i
                self.sock.sendall(w.frame(w.REQUEST, w.END, rid, payload))
                r = w.read_response(self.sock, rid)
                self.assertEqual(r.status, 400, what)
                self.assert_alive(rid + 1000)

    def test_id_0_frames_are_connection_errors(self):
        for data in (w.request(0, "/hello.txt"),
                     w.request(0, "/hello.txt", flags=0),
                     w.frame(w.DATA, w.END, 0, b"x"),
                     w.frame(w.RESPONSE, w.END, 0, b"\x00\xc8")):
            with self.subTest(data=data[:8].hex()):
                s = w.connect(self.server.port)
                s.sendall(data)
                self.assert_400_and_close(s)
                s.close()

    def test_request_content_length_is_checked(self):
        cases = [
            (w.request(1, "/hello.txt", fields=[("content-length", "5")]), 400),
            (w.request(2, "/hello.txt", fields=[("content-length", "x")]), 400),
            (w.request(3, "/hello.txt", fields=[("content-length", "")]), 400),
            (w.request(4, "/hello.txt", fields=[("content-length", "1" * 20)]), 400),
            (w.request(5, "/hello.txt", fields=[("content-length", "0"),
                                                ("content-length", "1")]), 400),
            (w.request(6, "/hello.txt", fields=[("content-length", "0"),
                                                ("content-length", "000")]), 200),
            (w.request(7, "/hello.txt", flags=0, fields=[("content-length", "3")]) +
             w.frame(w.DATA, 0, 7, b"ab") + w.frame(w.DATA, w.END, 7, b"c"), 200),
            (w.request(8, "/hello.txt", flags=0, fields=[("content-length", "4")]) +
             w.frame(w.DATA, w.END, 8, b"abc"), 400),
        ]
        for data, status in cases:
            rid = w.parse_frames(data[:8 + w.HEADER.unpack_from(data)[0]])[0].id
            with self.subTest(rid=rid):
                self.sock.sendall(data)
                self.assertEqual(w.read_response(self.sock, rid).status, status)
        self.assert_alive()

    def test_stray_data_and_response_frames_are_400(self):
        self.sock.sendall(w.frame(w.DATA, w.END, 9, b"stray"))
        self.assertEqual(w.read_response(self.sock, 9).status, 400)
        self.sock.sendall(w.frame(w.RESPONSE, w.END, 10, b"\x00\xc8"))
        self.assertEqual(w.read_response(self.sock, 10).status, 400)
        self.assert_alive()

    def test_oversized_length_is_400_and_close(self):
        self.sock.sendall(struct.pack(">HBBI", w.MAX_PAYLOAD + 1, w.REQUEST, w.END, 1))
        self.assert_400_and_close(self.sock)

    def test_max_length_unknown_frame_is_fine(self):
        self.sock.sendall(w.frame(0x99, 0, 0, b"\x00" * w.MAX_PAYLOAD))
        self.assert_alive()

    def test_http1_text_is_400_and_close(self):
        self.sock.sendall(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assert_400_and_close(self.sock)

    def test_oversized_after_good_request_reports_last_id(self):
        self.assertEqual(self.get("/hello.txt", rid=41).status, 200)
        self.sock.sendall(b"\xff\xff\x01\x01\x00\x00\x00\x2a")
        self.assertEqual(w.read_response(self.sock, 0).status, 400)
        f = w.read_frame(self.sock)
        self.assertEqual(w.parse_goaway(f.payload), (41, w.PROTOCOL_ERROR))


class TestPaths(ServerCase):

    def test_traversal_and_bad_syntax_are_400(self):
        for path in ("/../secret.txt", "/sub/../../secret.txt", "/./hello.txt", "hello.txt",
                     "/hello.txt/..", "/..", b"/hello.txt\x00.png"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status, 400)

    def test_escapes_and_hidden_files_are_404(self):
        for path in ("/link-out", "/.hidden", "/sub/.hidden", "/fifo", "//etc/passwd",
                     "/hello.txt/x", "/" + "a" * 5000, "/%2e%2e/secret.txt"):
            with self.subTest(path=path[:40]):
                self.assertEqual(self.get(path).status, 404)

    def test_symlink_inside_root_is_served(self):
        self.assertEqual(self.get("/link-in").body, self.file_bytes("hello.txt"))

    @unittest.skipIf(os.geteuid() == 0, "root can read anything")
    def test_unreadable_file_is_403(self):
        self.assertEqual(self.get("/noread.txt").status, 403)

    def test_secret_never_appears(self):
        for path in ("/../secret.txt", "/link-out", "//../secret.txt"):
            self.sock.sendall(w.request(1, path))
            self.assertNotIn(b"outside the root", w.read_response(self.sock, 1).body)


class TestRobustness(ServerCase):

    def fresh(self):
        return w.connect(self.server.port)

    def test_empty_and_partial_frames(self):
        for data in (b"", b"\x00", b"\x00\x05\x01", b"\x00\x0a\x01\x01\x00\x00\x00\x01abcd",
                     w.request(1, "/hello.txt", flags=0),
                     w.request(1, "/hello.txt", flags=0) + w.frame(w.DATA, 0, 1, b"x")[:10]):
            s = self.fresh()
            s.sendall(data)
            s.close()
        self.assert_alive()

    def test_half_close_mid_frame_gets_no_reply(self):
        s = self.fresh()
        s.sendall(b"\x00\x0a\x01\x01\x00\x00\x00\x01abc")
        s.shutdown(socket.SHUT_WR)
        self.assertIsNone(w.read_frame(s))
        s.close()

    def with_seed(self, body):
        """Runs body(rng); on any failure, reports the seed that reproduces it."""
        seed = int(os.environ.get("FUZZ_SEED", time.time()))
        try:
            body(random.Random(seed))
        except BaseException:
            sys.stderr.write("\nreproduce with FUZZ_SEED=%d\n" % seed)
            raise

    def test_fuzz_random_bytes_many_connections(self):
        def body(rng):
            for _ in range(200):
                kind = rng.randrange(3)
                if kind == 0:
                    data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 80)))
                elif kind == 1:
                    payload = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 60)))
                    data = w.frame(rng.choice((1, 2, 3, 4, rng.randrange(256))),
                                   rng.getrandbits(8), rng.getrandbits(32), payload)
                else:
                    payload = bytearray(w.request_payload(w.GET, "/hello.txt", w.DEFAULT_FIELDS))
                    for _ in range(rng.randrange(1, 4)):
                        payload[rng.randrange(len(payload))] = rng.getrandbits(8)
                    data = w.frame(w.REQUEST, w.END, rng.getrandbits(32), bytes(payload))
                # Half-close and wait for the server to finish with us: whatever
                # the bytes were, it must answer or not, then close (no hang).
                s = self.fresh()
                try:
                    s.sendall(data)
                    s.shutdown(socket.SHUT_WR)
                    while s.recv(65536):
                        pass
                except (ConnectionResetError, BrokenPipeError):
                    pass
                finally:
                    s.close()
            self.assert_alive()
            self.assertEqual(harness.sanitizer_lines(self.server.log()), [])
        self.with_seed(body)

    def test_fuzz_request_payloads_one_connection(self):
        """Any REQUEST whose framing is intact gets exactly one response with its ID."""
        def body(rng):
            base = w.request_payload(w.GET, "/hello.txt", w.DEFAULT_FIELDS)
            for rid in range(1, 501):
                if rng.random() < 0.5:
                    payload = bytearray(base)
                    for _ in range(rng.randrange(1, 5)):
                        payload[rng.randrange(len(payload))] = rng.getrandbits(8)
                    payload = bytes(payload[:rng.randrange(len(payload) + 1)])
                else:
                    payload = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 40)))
                self.sock.sendall(w.frame(w.REQUEST, w.END, rid, payload))
                r = w.read_response(self.sock, rid)
                self.assertIn(r.status, (200, 301, 400, 404, 405), "rid %d" % rid)
            self.assert_alive(1000)
        self.with_seed(body)


class TestIdleTimeout(harness.SiteServerCase, unittest.TestCase):
    idle = 1

    def test_idle_connection_gets_goaway_then_close(self):
        s = w.connect(self.server.port)
        s.sendall(w.request(1, "/hello.txt"))
        self.assertEqual(w.read_response(s, 1).status, 200)
        start = time.time()
        f = w.read_frame(s)
        self.assertEqual((f.type, f.id), (w.GOAWAY, 0))
        self.assertEqual(w.parse_goaway(f.payload), (1, w.NO_ERROR))
        self.assertGreaterEqual(time.time() - start, 0.8)
        self.assertIsNone(w.read_frame(s))
        s.close()

    def test_slow_frame_hits_the_deadline(self):
        s = w.connect(self.server.port)
        req = w.request(1, "/hello.txt")
        for b in req[:5]:   # dribble part of a frame, slower than the timeout
            s.sendall(bytes([b]))
            time.sleep(0.3)
        f = w.read_frame(s)
        self.assertEqual(f.type, w.GOAWAY)
        s.close()


if __name__ == "__main__":
    unittest.main()
