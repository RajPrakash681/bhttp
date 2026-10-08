# bhttp: HTTP, in binary

Two tracks, one protocol. `bserve` is a file server and `bcurl` is a client; they share
nothing but a two-page spec for **bhttp/1**, a binary request/response protocol with HTTP
semantics: fixed 8-byte frame headers, a ten-name static header table, length-prefixed
everything else, and one persistent TCP connection per client.

- **Author:** Raj Prakash
- **Spec:** [SPEC.md](SPEC.md) (rendered: [SPEC.pdf](SPEC.pdf), two A4 pages)
- **Annotated hexdump** of one real request and response: [HEXDUMP.md](HEXDUMP.md)

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
2026-10-08T12:10:39Z bserve: listening on 0.0.0.0:9000, root /Users/rajprakash/devops-work/bhttp/www, idle timeout 30s
2026-10-08T12:10:40Z 127.0.0.1:49383 connect
2026-10-08T12:10:40Z 127.0.0.1:49383 GET /hello.txt 200 14
2026-10-08T12:10:40Z 127.0.0.1:49383 close (peer closed, 1 request)
2026-10-08T12:10:40Z 127.0.0.1:49385 connect
2026-10-08T12:10:40Z 127.0.0.1:49385 GET / 200 542
2026-10-08T12:10:40Z 127.0.0.1:49385 GET /missing.html 404 14
2026-10-08T12:10:40Z 127.0.0.1:49385 GET /style.css 200 269
2026-10-08T12:10:40Z 127.0.0.1:49385 close (peer closed, 3 requests)
```

The second command fetched three URLs over one connection: one `connect`, three requests,
one `close`. For the `-v` output, see [HEXDUMP.md](HEXDUMP.md).

## Design in one page

### The frame header

```
 byte  0     1     2     3     4     5     6     7
     +-----+-----+-----+-----+-----+-----+-----+-----+
     |  Length   |Type |Flags|      Request ID       |
     +-----+-----+-----+-----+-----+-----+-----+-----+
          16        8     8            32           (bits, big-endian)
```

HTTP/2 uses 24 / 8 / 8 / 1+31 (9 bytes). bhttp/1 uses 16 / 8 / 8 / 32 (8 bytes):

- **Length, 16 bits.** Payloads are capped at 16384 bytes (HTTP/2's default limit too),
  which needs 15 bits; the 16th leaves room for a later version to negotiate frames up to
  64 KiB. HTTP/2 needs 24 bits only because SETTINGS can raise its limit to 16 MiB; at
  16 KiB the header is already 0.05 % overhead. A side effect: text such as `GET /` reads
  as Length ≥ 16640, so an HTTP/1 client is rejected on its first two bytes.
- **Type, 8 bits.** As in HTTP/2. v1 uses four values; the other 252 are the room for
  version 2.
- **Flags, 8 bits.** As in HTTP/2. v1 uses one bit, END.
- **Request ID, 32 bits.** v1 does not multiplex, so order alone would match responses
  to requests. The ID is kept because it lets a client detect a desynchronised connection,
  and because the header is the one thing no later version can change (every receiver
  must find Length in the same place to skip unknown frames), so room for multiplexing has
  to be reserved now. No reserved bit: HTTP/2's is a SPDY leftover.

### Frames

| Type | Name | Payload |
|---|---|---|
| `0x01` | REQUEST | Method (8), Path Length (16), Path, header block |
| `0x02` | RESPONSE | Status (16), header block |
| `0x03` | DATA | body bytes; END marks the last one |
| `0x04` | GOAWAY | Last-ID (32), Code (8) |

A receiver that meets a frame type it does not know MUST skip exactly Length bytes and
carry on. Types `0x05`-`0x7f` are reserved for later versions, `0x80`-`0xff` for
experiments; that, plus unknown flag bits being ignored, is the whole version story.

### Headers

Each entry is an Index byte, then a length-prefixed value. Index 1-10 names a static
table entry; Index 0 means a length-prefixed literal name follows. These are the ten
names bcurl and bserve actually send:

| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|
| `host` | `user-agent` | `accept` | `content-type` | `content-length` | `last-modified` | `date` | `server` | `location` | `allow` |

### Errors

If a frame header is bad (Length above 16384), the byte stream cannot be resynchronised:
the server answers 400 with Request ID 0, sends GOAWAY, and closes. The same happens for a
REQUEST, RESPONSE or DATA frame that uses ID 0 (which names the connection, so a 400 on ID 0
always means "connection error") and for a stray frame inside a request body. If the
framing is intact but the payload is malformed (bad path, bad header entry, unknown method,
bad `content-length`, and so on), the server answers 400 with that request's ID and keeps
the connection open.

## bserve

```
bserve [-t idle_seconds] ROOT PORT
```

- Listens on `0.0.0.0:PORT` with `SO_REUSEADDR`. `PORT` 0 picks a free port and the
  first log line says which one (the tests use this).
- **One process per connection (`fork`).** A connection's state (two 16 KiB frame
  buffers and a file descriptor) lives in its own address space, so one connection cannot
  corrupt or crash another or the listener, and nothing needs a lock. A process per client
  is an acceptable cost for this server. Children are reaped automatically
  (`SIGCHLD` ignored).
- Reads frames until the client closes, the connection is idle for 30 s (`-t` changes
  this; the server then sends GOAWAY), or the framing breaks.
- Maps `/` to `/index.html` (any path ending in `/` gets `index.html`), resolves the path
  with `realpath` and refuses anything outside ROOT (404), refuses `..`, `.`, missing
  leading `/` and control bytes (400), hides dot-files (404), and redirects a directory
  without a trailing slash (301). Status codes: 200, 301, 400, 403, 404, 405, 500.
- Streams files of any size as DATA frames of up to 16384 bytes.
- Logs one line per request to stderr: peer, method, path, status, body bytes.

## bcurl

```
bcurl [-v] URL [URL...]       URL = [bhttp://]host[:port][/path], port 9000 by default
```

The host ends at the first `:`, `/`, `?` or `#`; a `#fragment` is never sent, an empty
path becomes `/`, and `host?q` asks for `/?q`. All URLs must name the same host and port.
They are fetched in order over **one** TCP connection, which is never reopened: if it
fails, or the server sends GOAWAY, the remaining URLs are not fetched.
Bodies go to stdout. `-v` prints each frame sent (`>`) and received (`<`) to stderr: a
summary line, the decoded header fields, and a hexdump of the whole frame.

| Exit status | Meaning |
|---|---|
| 0 | every response was 2xx or 3xx |
| 4 | the worst response was 4xx |
| 5 | the worst response was 5xx |
| 2 | connection or protocol error (worst of all) |
| 1 | usage error (bad URL, URLs on different hosts); nothing was sent |

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
  traversal, symlink escapes, FIFOs and dot-files refused; idle timeout with GOAWAY; empty
  and partial frames; a random-bytes fuzz loop over 200 connections (each half-closed, and
  the server must then close it too) and 500 fuzzed REQUESTs on one connection, after which the server must still answer and its log must be
  free of sanitizer reports.
- **bcurl:** body to stdout; exit codes 0, 1, 2, 4, 5; `-v` hexdumps that reassemble to
  exactly the frames the spec prescribes; several URLs over one connection, checked by
  counting `connect` lines in the server log; the request bytes checked by a fake server;
  unknown frames skipped (a fake server injects them before, inside and between
  responses); no REQUEST after a GOAWAY; URL forms (`?`, `#`); and 15 kinds of
  misbehaving server, each of which must give exit status 2.

The fuzz tests take their seed from `FUZZ_SEED` if set, and print it on failure.
GitHub Actions runs `make` and `make test` on Ubuntu (gcc and clang) and macOS (clang), and
checks that SPEC.pdf is at most two pages.

## Layout

```
SPEC.md, SPEC.pdf     the protocol (two pages)
HEXDUMP.md            one real exchange, annotated byte by byte
Makefile              make, make debug, make test, make clean
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
tools/                renders SPEC.md to SPEC.pdf; checks its page count
```

To regenerate SPEC.pdf after editing SPEC.md (needs Node and Playwright's Chromium):

```console
$ cd tools && npm install && node render-spec.mjs
```
