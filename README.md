# bhttp: HTTP, in binary

[![CI](https://github.com/RajPrakash681/bhttp/actions/workflows/ci.yml/badge.svg)](https://github.com/RajPrakash681/bhttp/actions/workflows/ci.yml)

Two tracks, one protocol. `bserve` is a file server and `bcurl` is a client for
**bhttp/1**, a binary request/response protocol with HTTP semantics: fixed 8-byte frame
headers, a ten-name static header table, length-prefixed everything else, and one
persistent TCP connection per client. The two programs share one C codec (`src/bhttp.c`).
That the two-page spec alone is enough to interoperate is shown by [interop/](interop/): a
second client and server written in Python from SPEC.md only, cross-tested against both C
programs in every pairing.

- **Author:** Raj Prakash

## Hand-in

| # | The brief asks for | Here |
|---|---|---|
| 1 | The spec: two pages, enough for a stranger | [SPEC.pdf](SPEC.pdf), exactly two A4 pages (source: [SPEC.md](SPEC.md)) |
| 2 | Your program | [src/](src/): `make` builds `./bserve` (track 1, the server) and `./bcurl` (track 2, the client) |
| 3 | An annotated hexdump of one complete request and response | [HEXDUMP.md](HEXDUMP.md): every byte labelled, plus an appendix with a skipped unknown frame and a GOAWAY |

**Solo submission.** The brief is set for pairs; I wrote both tracks. Because `bserve` and
`bcurl` share one C codec, a C-to-C test alone cannot tell a protocol from an
implementation. So [interop/](interop/) adds a second client and server, written in Python
from SPEC.md only, and cross-tests all four pairings (C↔C, C↔Python, Python↔C,
Python↔Python): 298 of 298 checks pass, and CI runs them on every push.

### The brief, line by line

| The brief says | Spec | Checked by (in [tests/](tests/)) |
|---|---|---|
| accept a TCP connection, read one binary request frame | §2, §3, §5 | `test_get_index_200` |
| map the path to a file under a root | §8 | `test_root_maps_to_index_html`, `test_traversal_and_bad_syntax_are_400`, `test_escapes_and_hidden_files_are_404`, `test_symlink_swap_never_escapes_the_root` |
| reply: status, headers, the bytes | §5, §6 | `test_static_table_names_sent_indexed`, `test_large_file_multiple_data_frames` |
| 404 if it is not there | §7 | `test_404` |
| 400 if the frame is malformed | §7 | `test_malformed_payload_400_keeps_connection`, `test_oversized_length_is_400_and_close`, `test_http1_text_is_400_and_close` |
| and keep the connection open | §2 | `test_three_requests_one_connection`, `test_many_requests_one_connection`, `test_pipelined_requests_answered_in_order` |
| build the binary request frame | §5, §11 | `test_request_frames_follow_the_spec` |
| read the response, body to stdout | §6, §11 | `test_body_to_stdout`, `test_large_body_is_reassembled` |
| `-v` hexdumps every frame | §11 | `test_verbose_hexdumps_every_frame` |
| exit non-zero on 4xx / 5xx | §11 | `test_404_exits_4`, `test_5xx_exits_5`, `test_worst_status_wins` |
| and never open a second connection | §2, §11 | `test_multiple_urls_share_one_connection`, `test_never_opens_a_second_connection` |
| a fixed-size frame header, widths defended; HTTP/2 chose 24 / 8 / 8 / 31, why? | §3 | `tests/unit_test.c` |
| number the ten names you send, length-prefix the rest | §5 | `test_static_table_names_sent_indexed`, `test_literal_and_unknown_request_headers` |
| a receiver meeting an unknown frame type MUST skip it | §4, §9 | `test_unknown_types_before_request_are_skipped`, `test_unknown_types_between_requests`, `test_unknown_frames_are_skipped`, `test_unknown_frames_between_responses_are_skipped` |

### Evidence

- `make test`: C unit tests for the codec and 77 conformance tests, run against
  AddressSanitizer + UndefinedBehaviorSanitizer builds, on macOS (clang) and Linux (gcc).
- `make interop`: the 298-check cross-implementation matrix ([interop/README.md](interop/README.md)).
- [fuzz/](fuzz/): libFuzzer harnesses for every parser plus network fuzzers for both
  programs; about 400 million executions with no crash, sanitizer report or leak
  ([fuzz/README.md](fuzz/README.md)).
- CI: `make`, `make test` and `make interop` on Ubuntu (gcc and clang) and macOS (clang),
  plus a check that SPEC.pdf is at most two pages.

Written in C11 with POSIX sockets only, no third-party libraries. Builds warning-free with
`-Wall -Wextra -Werror` (plus `-Wpedantic -Wconversion -Wshadow` and friends) on Apple
clang and on gcc, and is tested under AddressSanitizer and UndefinedBehaviorSanitizer on
macOS and Linux.

## Build and run

```console
$ make                                   # builds ./bserve and ./bcurl
$ ./bserve ./www 9000                    # track 1: the server
$ ./bcurl -v localhost:9000/index.html   # track 2: the client, hexdumping every frame
```

Output from a real run (the server's log goes to its stderr):

```console
$ ./bcurl localhost:9000/hello.txt; echo "exit $?"
Hello, bhttp!
exit 0
$ ./bcurl localhost:9000/ localhost:9000/missing.html localhost:9000/style.css > /dev/null; echo "exit $?"
bcurl: localhost:9000/missing.html: 404 Not Found
exit 4
```

```text
2026-10-13T06:11:56Z bserve: listening on 0.0.0.0:9000, root ./www, idle timeout 30s, max 64 connections
2026-10-13T06:11:56Z 127.0.0.1:61667 connect
2026-10-13T06:11:56Z 127.0.0.1:61667 GET /hello.txt 200 14
2026-10-13T06:11:56Z 127.0.0.1:61667 close (peer closed, 1 request)
2026-10-13T06:11:56Z 127.0.0.1:61669 connect
2026-10-13T06:11:56Z 127.0.0.1:61669 GET / 200 542
2026-10-13T06:11:56Z 127.0.0.1:61669 GET /missing.html 404 14
2026-10-13T06:11:56Z 127.0.0.1:61669 GET /style.css 200 269
2026-10-13T06:11:56Z 127.0.0.1:61669 close (peer closed, 3 requests)
```

The second command fetched three URLs over one connection: one `connect`, three requests,
one `close`. For the `-v` output, see [HEXDUMP.md](HEXDUMP.md).

## Design summary

```
 byte  0     1     2     3     4     5     6     7
     +-----+-----+-----+-----+-----+-----+-----+-----+
     |  Length   |Type |Flags|      Request ID       |
     +-----+-----+-----+-----+-----+-----+-----+-----+
          16        8     8            32           (bits, big-endian)
```

The spec is the reference; this is the map.

- **Frame header** ([SPEC §3](SPEC.md#3-frame-header)): 8 bytes, Length 16 / Type 8 /
  Flags 8 / Request ID 32, against HTTP/2's 24 / 8 / 8 / 1+31. §3 gives HTTP/2's reason
  for each width and why bhttp keeps or changes it.
- **Frames** ([§4](SPEC.md#4-frame-types)): REQUEST, RESPONSE, DATA (END marks the last),
  GOAWAY. A receiver skips any type it does not know, by exactly Length bytes; that rule
  and the reserved type ranges are the whole version story ([§9](SPEC.md#9-versions)).
- **Headers** ([§5.3](SPEC.md#5-payloads)): Index 1-10 names one of the ten names the
  programs actually send; Index 0 introduces a length-prefixed literal name. Values are
  length-prefixed.
- **Errors** ([§7](SPEC.md#7-errors)): a bad frame header (Length above 16384) or a frame
  on ID 0 is a connection error: 400 on ID 0, GOAWAY, close. A malformed payload with
  intact framing is a request error: 400 on that request's ID, and the connection stays
  open.

## bserve

```
bserve [-t idle_seconds] [-c max_connections] ROOT PORT
```

- Listens on `0.0.0.0:PORT` with `SO_REUSEADDR`. `PORT` 0 picks a free port and the
  first log line says which one (the tests use this).
- **One process per connection (`fork`).** A connection's state (two 16 KiB frame
  buffers and a file descriptor) lives in its own address space, so one connection cannot
  corrupt or crash another or the listener, and nothing needs a lock. A process per client
  is an acceptable cost for this server.
- **At most 64 connections at once** (`-c` changes this). Beyond that, or if `fork` fails,
  the listener sends GOAWAY with code `0x02` BUSY and Last-ID 0, half-closes, and lingers
  up to 2 s draining the client's input (without ever blocking on it) so that a REQUEST
  already on its way cannot turn the close into a reset. It reaps exited children on
  every accept, so the count is exact. The cap is global: there is no per-peer fairness,
  so one client opening 64 connections can hold every slot.
- Reads frames until the client closes, the framing breaks, or 30 s pass without a
  complete request (`-t` changes this; the server then sends GOAWAY). Only requests count
  as activity, so a peer that trickles unknown frames cannot hold a connection open.
- Maps `/` to `/index.html` (any path ending in `/` gets `index.html`), refuses `..`, `.`,
  a missing leading `/` and control bytes (400), hides dot-files (404), and redirects a
  directory without a trailing slash (301). It resolves the path with `realpath`, refuses
  anything outside ROOT (404), and then walks the resolved name one component at a time
  from a descriptor for ROOT, never following a link: directories are opened for search
  only (`O_SEARCH`, or `O_PATH` on Linux), so a search-only (0311) directory still serves
  its files, and the last component is checked with `fstatat` before a regular file is
  opened with `O_NOFOLLOW`. Swapping a directory for a symlink in the middle of a request
  therefore cannot leak a file from outside ROOT. Status codes: 200, 301, 400, 403, 404,
  405, 500. Error bodies are short `text/plain`, and a response to HEAD never has one.
- Streams files of any size as DATA frames of up to 16384 bytes, every one full but the
  last.
- Logs one line per request to stderr: peer, method, path, status, body bytes.

`content-type` follows the file extension:

| Extension | `content-type` |
|---|---|
| `html`, `htm` | `text/html; charset=utf-8` |
| `css` | `text/css; charset=utf-8` |
| `js` | `text/javascript; charset=utf-8` |
| `txt` | `text/plain; charset=utf-8` |
| `md` | `text/markdown; charset=utf-8` |
| `json` | `application/json` |
| `pdf` | `application/pdf` |
| `png`, `gif`, `jpg`, `jpeg` | `image/png`, `image/gif`, `image/jpeg` |
| `svg`, `ico` | `image/svg+xml`, `image/x-icon` |
| anything else | `application/octet-stream` |

## bcurl

```
bcurl [-v] [-t seconds] URL [URL...]     URL = [bhttp://]host[:port][path]
```

The host is a name, an IPv4 address or a bracketed IPv6 address (`[::1]:9000`); the port
defaults to 9000. The host ends at the first `:`, `/`, `?` or `#`; a `#fragment` is never
sent, an empty path becomes `/`, and `host?q` asks for `/?q`. All URLs must name the same
host and port. They are fetched in order over **one** TCP connection, which is never
reopened: if it fails, or the server sends GOAWAY, the remaining URLs are not fetched.
Bodies go to stdout, and never a byte past the `content-length` the server announced.
bcurl gives up after 30 s (`-t`) without a RESPONSE or DATA frame for the current
request; unknown frames do not extend the wait. `-v` prints each frame sent (`>`) and
received (`<`) to stderr: a summary line, the decoded header fields, and a hexdump of the
whole frame. [SPEC §11](SPEC.md#11-reference-client-informative) is the same contract.

| Exit status | Meaning |
|---|---|
| 0 | every response was 2xx or 3xx |
| 4 | the worst response was 4xx |
| 5 | the worst response was 5xx |
| 2 | connection or protocol error (worst of all) |
| 1 | usage error (bad URL or option, URLs on different hosts, a REQUEST too big for one frame); nothing was sent |

With several URLs the worst outcome wins, in the order 2 > 5 > 4 > 0.

## Tests

```console
$ make test
```

builds the sanitizer binaries in `build/debug/` (`-fsanitize=address,undefined`), runs the
C unit tests for the codec, then the conformance suite in `tests/`. The suite is Python 3
standard library only (3.9 or later) and is a second, independent implementation of the
protocol written from SPEC.md: `tests/bhttp_wire.py` builds and parses frames itself and
never calls the C code. It covers:

- **bserve:** 200 with correct headers and bytes; 404, 301, 403, 405; HEAD; query strings;
  raw-byte paths; 400 for 26 kinds of malformed payload, each followed by a valid request
  on the same socket to prove the connection stayed open; request `content-length`
  checked against the body; 400 + GOAWAY + close for an oversized Length, for HTTP/1 text
  and for frames on ID 0; unknown frame types skipped before, between and
  inside requests; three requests on one connection, checked against the server log;
  pipelined requests; 100 KiB and exactly-32 KiB files as multiple DATA frames that
  reassemble exactly (generated at test time); request bodies read through END; path
  traversal, symlink escapes, FIFOs and dot-files refused; search-only (0311) directories
  and ROOT served; idle timeout with GOAWAY; empty and partial frames; a symlink-swap race
  (a directory atomically exchanged with a link out of ROOT for 4 s) that must never leak
  a file; the connection cap (extra connections get GOAWAY BUSY even when they send a
  REQUEST at once, and a freed slot takes a new client); unknown frames that must not keep
  a connection alive; a random-bytes fuzz loop over 200 connections (each half-closed, and
  the server must then close it too) and 500 fuzzed REQUESTs on one connection, after
  which the server must still answer and its log must be free of sanitizer reports.
- **bcurl:** body to stdout; exit codes 0, 1, 2, 4, 5; `-v` hexdumps that reassemble to
  exactly the frames the spec prescribes; several URLs over one connection, checked by
  counting `connect` lines in the server log; the request bytes checked by a fake server;
  unknown frames skipped (a fake server injects them before, inside and between
  responses); no REQUEST after a GOAWAY; URL forms (`?`, `#`); nothing written past
  `content-length`; unknown frames that must not stall it past `-t`; and 16 kinds of
  misbehaving server, each of which must give exit status 2.

The fuzz tests take their seed from `FUZZ_SEED` if set, and print it on failure.

```console
$ make interop
```

runs the partner implementation's matrix in [interop/](interop/): every pairing of the C
and Python clients and servers, plus raw-frame conformance checks against both servers and
both clients. [fuzz/](fuzz/) holds libFuzzer harnesses and network fuzzers (see
fuzz/README.md). GitHub Actions runs `make`, `make test` and `make interop` on Ubuntu (gcc
and clang) and macOS (clang), and checks that SPEC.pdf is at most two pages.

## Layout

```
SPEC.md, SPEC.pdf     the protocol (two pages)
HEXDUMP.md            one real exchange, annotated byte by byte
Makefile              make, make debug, make test, make interop, make clean
src/bhttp.[ch]        wire format: frame header, payloads, header block codec
src/netio.[ch]        socket I/O with deadlines; whole-frame reads and writes
src/dump.[ch]         hexdump and frame summaries for bcurl -v
src/bserve.c          the server
src/bcurl.c           the client
www/                  sample site: index.html, style.css, logo.png, hello.txt
tests/unit_test.c     C unit tests for the codec
tests/bhttp_wire.py   independent Python implementation of the wire format
tests/test_*.py       conformance tests for bserve and bcurl
tests/run_tests.py    test runner used by make test
tools/                renders SPEC.md to SPEC.pdf and checks its page count;
                      wire_demo.py makes the HEXDUMP.md appendix capture
interop/              a second client and server in Python, written from SPEC.md alone,
                      and a matrix that cross-tests all four pairings (interop/README.md)
fuzz/                 libFuzzer harnesses and network fuzzers (fuzz/README.md)
```

To regenerate SPEC.pdf after editing SPEC.md (needs Node and Playwright's Chromium):

```console
$ cd tools && npm install && node render-spec.mjs
```
