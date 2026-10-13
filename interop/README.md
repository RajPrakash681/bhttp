# interop: a second, independent bhttp/1 implementation

> "A client that only works against your own server is an implementation, not a protocol."

This directory holds a second client and server for bhttp/1, written in Python **from
`SPEC.md` alone**, plus a test matrix that runs every client against every server. If the
C `bcurl` and the Python `pybserve` get along (and the Python `pybcurl` and the C `bserve`
do too), then the spec carries enough information to build a working peer. Where it doesn't,
the questions are collected in [Spec questions](#spec-questions) below.

## Clean-room rule

The Python side was first written while the only file read from the rest of the repository
was `SPEC.md` (and `SPEC.pdf`, which is rendered from it). `src/`, `Makefile`, `tests/`,
`HEXDUMP.md` and `README.md` were not opened until the Python code was finished and the
first full cross-test had run. From the C programs, only their usage text was used: how to
invoke them and bcurl's exit codes, which the matrix needs to know what to expect. The first
full cross-test passed every check. After that, the C sources were read only to confirm
divergences.

The spec has since been revised twice in answer to the questions below: `3290045`, then
`2867662` and `6fdab1a`. Each time, the Python code was brought in line with the new text,
including §11's reference-client contract (URL grammar and exit codes), and every newly
specified rule became a row in the matrix.

## Files

| File | What it is |
|---|---|
| `pybhttp.py` | Frame and payload codec: 8-byte header, the four frame types, header block with the 10-name static table and literal form, the `content-length` rules of §6, GOAWAY, a frame reader that skips unknown types by exactly Length bytes, one-line frame dumps for `-v`. |
| `pybserve.py` | `pybserve ROOT PORT [--idle SECONDS]`: file server. Path mapping and the content-type table (§8), 200/301/400/403/404/405/500, keep-alive, request bodies read through END, request errors (400, connection kept) vs connection errors (400 on ID 0, GOAWAY 0x01, close), idle close with GOAWAY 0x00, one thread per connection. |
| `pybcurl.py` | `pybcurl [-v] URL...`: client following §11: one origin, one connection (never reopened), IDs 1, 2, 3, ..., bodies to stdout, every §7 "Clients" check, no new REQUEST after a GOAWAY that has already arrived, `-v` frame dumps on stderr, exit 0/4/5/2/1 with the worst winning. |
| `run_interop.py` | The matrix. Builds the C programs with `make`, generates the test files (including a 21-frame random file) in a temp dir, uses free ports, kills every server it starts. |

Everything is Python 3.9+ standard library only.

## Running it

```sh
python3 interop/run_interop.py           # full matrix, about 15 s
python3 interop/run_interop.py --slow    # also the 30 s idle-timeout test (about 75 s)
python3 interop/run_interop.py --only Py # one implementation against itself
python3 interop/run_interop.py --keep    # keep the temp tree and both server logs
```

It exits 0 only if every check passed. To try the Python pair by hand:

```sh
python3 interop/pybserve.py www 9000 &
python3 interop/pybcurl.py -v localhost:9000/hello.txt localhost:9000/style.css
./bcurl localhost:9000/          # C client, Python server
```

## What the matrix checks

0. **Reference bytes.** The §10 worked example and the full HEXDUMP.md capture are decoded
   and re-encoded by `pybhttp` and must come out byte for byte the same.
1. **Pairing matrix**, for C->C, C->Py, Py->C and Py->Py. The client talks to the server
   through a frame-aware proxy that counts TCP connections and frames, and can inject
   unknown frames or corrupt one frame:
   - 200 with a byte-exact body; 404 with §11's exit 4;
   - a 328 914-byte random file: byte-exact, at least 21 DATA frames, each at most 16384
     bytes and all but the last full; a body of exactly 2 x 16384 bytes;
   - 7 URLs in one run: exactly **one** TCP connection, IDs 1..7, byte-exact output;
   - the same 7 URLs with an **unknown frame injected before every frame in both
     directions** (types 0x00, 0x05, 0x42, 0x7f, 0x80, 0xff; END and other flags set; IDs
     0, the current ID and 0xffffffff; payloads of 0 to 16384 bytes, some of which look like
     real frames);
   - delivery in 1-7 byte TCP segments;
   - the proxy turns request 1 into an unknown method: 400 on ID 1, **no GOAWAY, same
     connection**, then request 2 gets 200;
   - the proxy rewrites the RESPONSE ID: the client must exit 2 and must not print the page;
   - connection refused (exit 2); `-v` writes to stderr and leaves stdout byte-exact.
2. **Server conformance.** Hand-built frames sent straight to each server:
   - **Connection errors** (400 on ID 0, GOAWAY 0x01 with the right Last-ID, orderly
     close): HTTP/1.1 text, Length 16385, an unknown type with Length 65535, a REQUEST,
     RESPONSE or DATA on ID 0 (with or without END), and any frame other than DATA for
     the open ID while a request body is open.
   - A GOAWAY while a body is open just ends the connection.
   - **Request errors**, which must each get 400 and leave the connection usable:
     payloads of 2 and 3 bytes, bad methods, path lengths and paths, bad header blocks,
     a RESPONSE (which opens no body, so its DATA is stray too), stray DATA, and a bad
     request `content-length` (wrong length, not digits, empty, 20 digits, copies that
     differ).
   - Matching `content-length` values, including `007` and repeated copies, are accepted.
   - Frame handling: unknown frames before a request and inside a request body; IDs
     0xffffffff, 5, 3 copied back.
   - HEAD gets END and no DATA, also for 404 and 301. `date` and `last-modified` are
     IMF-fixdate, and `content-type` follows the §8 table.
   - POST with a body gets 405 plus `allow`.
   - Path mapping: 301 without the query; `index.html`, and 404 when it is a directory;
     `%2e%2e` is a literal name; hidden files, symlinks out of the root, a FIFO and an
     unreadable file.
   - Connection lifecycle: a truncated frame; client GOAWAY, also with a nonzero ID; a
     partial frame trickled in does not extend the idle timer (own server with T = 3 s);
     with `--slow`, idle close with GOAWAY 0x00 after the default T.
3. **Client conformance.** Each client against a scripted server:
   - Tolerance: unknown frames and unused flag bits everywhere, literal header names,
     fragmented or uneven DATA.
   - A GOAWAY that arrives with the first response: the second URL must not be requested,
     and the client exits 2.
   - Each §7 "Clients" error in turn (exit 2): wrong ID, DATA before RESPONSE, RESPONSE
     on ID 0, status 199 and 600, a bad `content-length` (mismatch, non-digits, empty, 20
     digits, copies that differ), EOF before END or inside a frame, GOAWAY before END,
     Length 16385, a second RESPONSE, a REQUEST, a malformed header block.
   - The §11 contract:
     - exit codes 0/4/5/2, with the worst winning, including "2 beats 4";
     - a connection the server closed is never reopened;
     - the URL grammar (fragment never sent, `host:port?q` becomes `/?q`, an empty path
       becomes `/`, the path is otherwise unchanged);
     - usage errors (two origins, `http://`, a bad port, an unknown option, no URL) exit 1
       without connecting.
4. **Observations.** No verdict, just what each side does where the spec is still silent
   or ambiguous. These rows are the evidence for the open questions below.

The harness was itself checked against deliberately broken copies of the Python code: a
receiver that doesn't skip unknown types, a server that closes after a request error, a
client that ignores the response ID, a client that sends its next REQUEST past a pending
GOAWAY, and the previous Python pair written to the older spec text (38 rows failed). Each
one turned the expected rows red.

## Results

Final run (macOS, Apple Silicon, Python 3.9.6, C programs built from `95426fb`):

```text
$ python3 interop/run_interop.py --slow
building C implementation with make ...

0. Reference bytes (SPEC.md §10, HEXDUMP.md) through the Python codec
---------------------------------------------------------------------
test                           Py
SPEC.md §10 example            PASS
HEXDUMP.md decodes+re-encodes  PASS

1. Pairing matrix (client -> server)
------------------------------------
test                        C->C    C->Py   Py->C   Py->Py
200 small file, byte-exact  PASS    PASS    PASS    PASS
404 -> §11 exit 4           PASS    PASS    PASS    PASS
large file, >1 DATA frame   PASS    PASS    PASS    PASS
body of exactly 2x16384     PASS    PASS    PASS    PASS
7 URLs over one connection  PASS    PASS    PASS    PASS
unknown frames injected     PASS    PASS    PASS    PASS
1-7 byte TCP segments       PASS    PASS    PASS    PASS
malformed req -> 400, kept  PASS    PASS    PASS    PASS
wrong response ID -> error  PASS    PASS    PASS    PASS
connection refused exit     PASS    PASS    PASS    PASS
-v keeps stdout clean       PASS    PASS    PASS    PASS

2. Server conformance (raw frames)
----------------------------------
test                             C       Py
HTTP/1.1 text -> conn error      PASS    PASS
Length 16385 -> 400/0, GOAWAY    PASS    PASS
unknown type, Length 65535       PASS    PASS
DATA other ID in body            PASS    PASS
REQUEST while body open          PASS    PASS
RESPONSE same ID in body         PASS    PASS
REQUEST same ID in body          PASS    PASS
GOAWAY in body: close            PASS    PASS
REQUEST with ID 0                PASS    PASS
REQUEST ID 0 without END         PASS    PASS
RESPONSE with ID 0               PASS    PASS
DATA with ID 0                   PASS    PASS
payload of 2 bytes               PASS    PASS
payload of 3 bytes               PASS    PASS
unknown method 0x06              PASS    PASS
Path Length 0                    PASS    PASS
Path Length past payload         PASS    PASS
path without leading /           PASS    PASS
path with .. segment             PASS    PASS
path with . segment              PASS    PASS
path ending in /..               PASS    PASS
path with NUL                    PASS    PASS
path with 0x7f                   PASS    PASS
query only (?x)                  PASS    PASS
header index 11                  PASS    PASS
header runs past payload         PASS    PASS
literal name empty               PASS    PASS
literal name uppercase           PASS    PASS
header value with CR             PASS    PASS
RESPONSE sent to server          PASS    PASS
RESPONSE opens no body           PASS    PASS
DATA with no open body           PASS    PASS
bad REQUEST w/ body -> 1x400     PASS    PASS
req c-l 5, no body -> 400        PASS    PASS
req c-l 'x' -> 400               PASS    PASS
req c-l empty -> 400             PASS    PASS
req c-l 20 digits -> 400         PASS    PASS
req c-l copies 0,1 -> 400        PASS    PASS
req c-l 5, body 3 -> 400         PASS    PASS
req c-l 3 = body -> 200          PASS    PASS
req c-l 007 = body -> 200        PASS    PASS
req c-l 3,3 = body -> 200        PASS    PASS
unknown frames skipped           PASS    PASS
IDs copied (0xffffffff,5,3)      PASS    PASS
unused flag bits ignored         PASS    PASS
literal form of table names      PASS    PASS
empty header block               PASS    PASS
HEAD: END, no DATA, c-l          PASS    PASS
HEAD 404: END, no DATA           PASS    PASS
HEAD 301: END, no DATA           PASS    PASS
date, last-modified IMF-fixdate  PASS    PASS
content-type per §8 table        PASS    PASS
POST + body -> 405, allow        PASS    PASS
/sub -> 301 location /sub/       PASS    PASS
/sub/ -> index.html              PASS    PASS
301 location drops query         PASS    PASS
dir/ whose index is a dir: 404   PASS    PASS
query dropped                    PASS    PASS
%2e%2e is a literal name         PASS    PASS
/.hidden -> 404                  PASS    PASS
/sub/.secret -> 404              PASS    PASS
missing file -> 404              PASS    PASS
symlink inside root -> 200       PASS    PASS
symlink outside root -> 404      PASS    PASS
dir symlink outside -> 404       PASS    PASS
FIFO (not regular) -> 404        PASS    PASS
unreadable file -> 403           PASS    PASS
empty file                       PASS    PASS
truncated frame -> close         PASS    PASS
client GOAWAY -> close           PASS    PASS
GOAWAY ID 7 ignored -> close     PASS    PASS
partial frame doesn't extend T   PASS    PASS
idle close with GOAWAY 0x00      PASS    PASS

3. Client conformance (scripted server)
---------------------------------------
test                            C       Py
IDs 1,2,3, one conn, host       PASS    PASS
unknown frames + flag bits      PASS    PASS
1-3 byte TCP segments           PASS    PASS
uneven + empty DATA frames      PASS    PASS
GOAWAY after END is fine        PASS    PASS
pending GOAWAY: no 2nd REQUEST  PASS    PASS
wrong RESPONSE ID               PASS    PASS
DATA before RESPONSE            PASS    PASS
RESPONSE on ID 0                PASS    PASS
status 199                      PASS    PASS
status 600                      PASS    PASS
content-length mismatch         PASS    PASS
content-length not digits       PASS    PASS
EOF before END                  PASS    PASS
EOF inside a frame              PASS    PASS
GOAWAY before END -> 2          PASS    PASS
Length 16385                    PASS    PASS
second RESPONSE                 PASS    PASS
REQUEST from server             PASS    PASS
malformed header block          PASS    PASS
c-l copies 2,3 -> 2             PASS    PASS
c-l 20 digits -> 2              PASS    PASS
c-l empty -> 2                  PASS    PASS
c-l 007 = 7 bytes -> 0          PASS    PASS
c-l 2,2 = 2 bytes -> 0          PASS    PASS
§11 exit: 301 -> 0              PASS    PASS
§11 exit: 500 -> 5              PASS    PASS
§11 exit: 200,404 -> 4          PASS    PASS
§11 exit: 404,500 -> 5          PASS    PASS
§11 exit: 500,404 -> 5          PASS    PASS
§11 exit: 2 beats 4 (404, bad)  PASS    PASS
§11: closed, never reopened     PASS    PASS
§11 URL: #fragment not sent     PASS    PASS
§11 URL: host:port?q -> /?q     PASS    PASS
§11 URL: host:port -> /         PASS    PASS
§11 URL: host:port#f -> /       PASS    PASS
§11 URL: path sent unchanged    PASS    PASS
§11 usage: two origins -> 1     PASS    PASS
§11 usage: http:// -> 1         PASS    PASS
§11 usage: bad port -> 1        PASS    PASS
§11 usage: unknown option -> 1  PASS    PASS
§11 usage: no URL -> 1          PASS    PASS

4. Observed behaviour where SPEC.md is silent or ambiguous (not graded)
-----------------------------------------------------------------------
probe                       C server          Py server
HEAD /a/../b (bad path)     400 + 37 B DATA   400 END, no DATA
HEAD with c-l 5, no body    400 + 56 B DATA   400 END, no DATA
req c-l copies 3, 03 (3 B)  200               400

probe                        C client   Py client
URL too long for one frame   exit 2     exit 1
resp c-l copies 2, 02 (2 B)  exit 0     exit 2

276 checks: 276 passed, 0 failed, 0 skipped
```

Beyond the matrix, about 70 one-off probes were run against both servers and both
clients: pipelined requests, 1000 requests on one connection, a half-close after the
request, a stalled reader next to a fresh connection, ENOTDIR and ENAMETOOLONG paths, PUT
and DELETE, short and odd GOAWAYs, and `localhost` resolving to both address families.
Apart from the rows in section 4, both servers gave the same status, frame sequence and
GOAWAY Last-ID, and both clients the same exit code and Path.

**Verdict: the spec is a protocol.** Two implementations written independently from it
interoperate in every pairing and on all 276 checks. What remains is in section 4: three
small questions the revised text still leaves open.

## Spec questions

Every question raised in earlier rounds, and where the spec now answers it.

### Resolved

| # | Question | Resolved by | Where |
|---|---|---|---|
| 1 | Should a server check a request's `content-length`, and how does it report a bad one? | `2867662` (bserve: `6e966cc`) | §6, §7: a bad `content-length` is a request error (400, connection kept) |
| 2 | Client CLI: exit codes, URL grammar, default port, multiple URLs | `2867662` (bcurl: `9f74822`, `3918ebb`) | §11 Reference client; pybcurl adopted it |
| 3 | Repeated `content-length` with differing values | `2867662` (bcurl: `3918ebb`) | §6: every copy MUST be identical (but see open question A) |
| 4 | Request errors on ID 0 looked like connection errors | `2867662` (bserve: `6e966cc`) | §3, §7: a REQUEST, RESPONSE or DATA on ID 0 is a connection error |
| 5 | Same-ID frames or GOAWAY while a request body is open | `2867662` | §7: anything but DATA for that ID, an unknown type, or GOAWAY (which ends the connection) |
| 6 | Does a RESPONSE sent to a server open a body? | `2867662` | §6, §7: only a REQUEST opens a body |
| 7 | GOAWAY racing the next request | `2867662` (bcurl: `a6f08af`) | §7 "Clients": GOAWAY before END means "not processed", MAY retry |
| 8 | `content-length` grammar | `2867662` | §6: 1 to 19 ASCII digits, leading zeros allowed |
| 9 | What the idle timer measures | `2867662` | §2: T from when the server starts waiting; partial frames don't extend it |
| 10 | HEAD on error statuses | `2867662`, `6fdab1a` | §6: every response to HEAD, whatever its status (but see open question B) |
| 11 | Is ROOT itself resolved? | `2867662` | §8: "resolved the same way" |
| 12 | Date and media-type formats | `2867662` | §5.3: IMF-fixdate; §8: content-type table |
| 13 | "Payload under 3 bytes" (the real minimum is 4) | `2867662` | §7: "under 4 bytes" |
| 14 | 301 `location` and the query | `3290045` | §7: path without the query, plus `/` |
| 15 | `dir/` whose `index.html` is a directory | `3290045` | §8: 404 if the path already ended in `/` |
| 16 | GOAWAY with a nonzero Request ID | `3290045` | §4: ignored on receipt |

### Still open

A. **§6: "every copy MUST be identical": the same bytes, or the same value?** With copies
   `3` and `03` and a 3-byte body:
   - bserve accepts the request (200) and bcurl accepts the response (exit 0), so they
     compare values.
   - pybserve (400) and pybcurl (exit 2) compare bytes.

   Leading zeros are allowed, so the two readings really do differ. **Fix:** say
   "identical byte strings", or "the same value".

B. **§6: is a request error on a HEAD-coded REQUEST "a response to HEAD"?** §6 says every
   response to HEAD, whatever its status, sets END and has no DATA.
   - For `HEAD /a/../b` (bad path) and for HEAD with `content-length: 5` and no body,
     bserve answers 400 with a text body in DATA.
   - pybserve answers 400 with END and no DATA.

   In the `content-length` case the request names HEAD unambiguously, so the literal text
   favours no DATA. It does no harm in practice, since bcurl and pybcurl only send GET.
   **Fix:** either "including request errors" (then bserve changes), or "a request error
   is answered as if to GET" (then pybserve changes).

C. **§11: a URL whose REQUEST doesn't fit in one frame.** A path of 16400 bytes:
   - bcurl exits 2 (connection or protocol error).
   - pybcurl exits 1 (usage error), before connecting.

   **Fix:** say which. Usage error seems natural, since nothing was sent.

## C findings

There are no outstanding C bugs against the current text, apart from open question B,
where bserve may or may not be wrong. Everything reported earlier has been fixed upstream
and is now a passing row in the matrix:

| Was | Fixed in |
|---|---|
| bcurl sent a URL `#fragment` as part of the Path | `9f74822` |
| bcurl sent the next REQUEST past a GOAWAY that had already arrived | `a6f08af` |
| bcurl accepted conflicting `content-length` copies (it used only the first) | `3918ebb` |
| bcurl rejected `host:port?q` ("invalid port") | `3918ebb` |
| bserve ignored a request's `content-length` | `6e966cc` |
| bserve answered ID-0 frames with a request error instead of a connection error | `6e966cc` (rule changed in `2867662`) |

## Python changes over the review

- **To the revised spec:**
  - pybcurl now follows §11:
    - exit codes 0/4/5/2/1, with the worst winning;
    - one origin and one connection, never reopened;
    - only `bhttp://`;
    - the host ends at `:`, `/`, `?` or `#`, and a port after `:` must be present;
    - a REQUEST too big for a frame is a usage error.
  - pybserve now treats ID-0 frames as connection errors.
  - The codec enforces the 1-19-digit `content-length`, and the minimum REQUEST payload
    is now 4 bytes.
  - pybserve sends no DATA in any response to a HEAD request, uses the §8 content-type
    table, sends the 301 `location` without the query, and gives 404 for `dir/` when
    `index.html` is a directory.
- **Bugs found and fixed in my own code:**
  - pybcurl had the same `host:port?q` bug as bcurl.
  - pybcurl sent the next REQUEST past a pending GOAWAY.
  - The frame reader left a short socket timeout behind after an idle-limited read, so a
    large response to a slow reader could have failed. This one was found before the first
    cross-test.
