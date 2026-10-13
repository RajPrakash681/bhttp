# interop: a second bhttp/1 implementation, written from SPEC.md

> "A client that only works against your own server is an implementation, not a protocol."

This directory holds a Python client and server for bhttp/1, written from `SPEC.md`, plus a
test matrix that runs every client against every server and checks each one against the
spec's rules. If the C `bcurl` works with the Python `pybserve`, and the Python `pybcurl`
with the C `bserve`, then the spec carries enough to build a working peer. Where it didn't,
the questions it raised are listed in [Spec questions](#spec-questions), with how each was
settled.

## How it was written

- **The first version.** The Python pair was written against `SPEC.md` only (and
  `SPEC.pdf`, which is rendered from it), without consulting `src/`, the `Makefile`,
  `tests/` or `HEXDUMP.md`. The one thing used from the C side was the usage text the two
  programs print: how to invoke them, and bcurl's exit codes, which SPEC.md did not define
  yet.
- **After the first cross-test.** That run passed every check it had. From then on, `src/`
  was consulted to find where the two sides differed.
- **Each spec revision.** The spec was revised several times in answer to the questions
  below (`3290045`, `2867662`, `6fdab1a`, `633e106`, `2f6c21e`, `cd6f0d2`, `b059295`).
  Each time, the Python pair was changed to the new text, and the new rules were added to
  the matrix as graded rows.

This describes the process; nothing in the repository can prove it. What the matrix does
show is how the two pairs behave today: every client against every server, and each side
against the rules in the spec.

## Files

| File | What it is |
|---|---|
| `pybhttp.py` | Frame and payload codec: 8-byte header, the four frame types, header block with the 10-name static table and literal form, the `content-length` rules of §6, GOAWAY with its three codes, a frame reader that skips unknown types by exactly Length bytes (sharing one deadline across them), one-line frame dumps for `-v`. |
| `pybserve.py` | `pybserve [--idle T] [-c MAX] ROOT PORT`: file server. Path mapping (§8) with bserve's content-type table (top-level README), 200/301/400/403/404/405/500, keep-alive, request bodies read through END, request errors (400, connection kept) vs connection errors (400 on ID 0, GOAWAY 0x01, close), the §2 idle rule (only a complete REQUEST, or a DATA frame of an open body, resets T), and at most MAX connections at once: the rest get GOAWAY BUSY. |
| `pybcurl.py` | `pybcurl [-v] [-t seconds] URL...`: client following §11: one origin, one connection (never reopened), IDs 1, 2, 3, ..., bodies to stdout and never past `content-length`, every §7 "Clients" check, no new REQUEST after a GOAWAY that has already arrived, `-t` (default 30) counting only RESPONSE and DATA frames as progress, exit 0/4/5/2/1 with the worst winning. |
| `run_interop.py` | The matrix. Builds the C programs with `make`, generates the test files (including a 21-frame random file) in a temp dir, uses free ports, kills every server it starts. `make interop` runs it, and CI runs that. |

Everything is Python 3.9+ standard library only.

## Running it

```sh
python3 interop/run_interop.py           # full matrix, about 60 s
python3 interop/run_interop.py --slow    # also the 30 s default idle timeout (about 120 s)
python3 interop/run_interop.py --only Py # one implementation against itself
python3 interop/run_interop.py --keep    # keep the temp tree and the server logs
make interop                             # same as the first line, after building
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
   - connection refused (exit 2);
   - a server at its connection cap (`-c 1`, one connection held): the client gets GOAWAY
     BUSY, exits 2 and prints nothing;
   - `-v` writes to stderr and leaves stdout byte-exact.
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
     differ, `3` next to `03`).
   - Matching `content-length` values, including `007` and repeated copies, are accepted.
   - Frame handling: unknown frames before a request and inside a request body; IDs
     0xffffffff, 5, 3 copied back.
   - HEAD gets END and no DATA, for 200, 404, 301, and a 400 to a malformed HEAD.
   - `date` and `last-modified` are IMF-fixdate, and `content-type` follows the file
     extension (bserve's table, which pybserve shares, is in the top-level README).
   - POST with a body gets 405 plus `allow`.
   - Path mapping: 301 without the query; `index.html`, and 404 when it is a directory;
     `%2e%2e` is a literal name; hidden files, symlinks out of the root, a FIFO and an
     unreadable file.
   - Connection lifecycle:
     - a truncated frame; client GOAWAY, also with a nonzero ID;
     - the §2 idle rule, on a server started with T = 2-3 s: a partial frame trickled in
       and unknown frames every 0.4 s do **not** extend T, while four REQUESTs 1 s apart
       and a request body trickled over 3 s **do** (each idle GOAWAY carries the right
       Last-ID);
     - with `--slow`, the default T;
   - **BUSY**: with `-c 2` and two connections held, a third gets GOAWAY Last-ID 0, code
     0x02, then a close. When one held connection closes, a new one is served, and the
     other held connection keeps working.
3. **Client conformance.** Each client against a scripted server:
   - Tolerance: unknown frames and unused flag bits everywhere, literal header names,
     fragmented or uneven DATA.
   - GOAWAY handling: one that arrives with the first response (the second URL must not
     be requested), and GOAWAY BUSY; both exit 2.
   - Each §7 "Clients" error in turn (exit 2): wrong ID, DATA before RESPONSE, RESPONSE
     on ID 0, status 199 and 600, a bad `content-length` (mismatch, non-digits, empty, 20
     digits, copies `2`/`3` and `2`/`02`), EOF before END or inside a frame, GOAWAY before
     END, Length 16385, a second RESPONSE, a REQUEST, a malformed header block.
   - The §11 contract:
     - exit codes 0/4/5/2, with the worst winning, including "2 beats 4";
     - a connection the server closed is never reopened;
     - bcurl's URL grammar, documented in the top-level README (fragment never sent,
       `host:port?q` becomes `/?q`, an empty path becomes `/`, the path is otherwise
       unchanged);
     - usage errors exit 1 without connecting: two origins, `http://`, a bad port, an
       unknown option, no URL, a URL whose REQUEST would not fit in one frame, and
       `-t 0` or `-t x`;
     - `-t 2`: a silent server, and one that sends only unknown frames, both end in exit
       2 after about 2 s, while a DATA frame every second keeps a 4-second response
       alive.

The harness was itself checked against deliberately broken or outdated copies of the
Python code:
- a receiver that doesn't skip unknown types;
- a server that closes after a request error;
- a client that ignores the response ID;
- a client that sends its next REQUEST past a pending GOAWAY;
- the Python pair as it was before each spec revision (38 rows failed after `2867662`; the
  BUSY and unknown-frame idle rows failed after `2f6c21e`).

Each one turned the expected rows red.

## Results

Final runs (macOS, Apple Silicon, Python 3.9.6, against main at `a9a4dfa`): **308 checks without `--slow`, 310 with it, all passing.** CI runs the 308 on every push (`make interop`, Ubuntu with gcc and clang, and macOS).

```text
$ python3 interop/run_interop.py
...
308 checks: 308 passed, 0 failed, 0 skipped
```

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
server BUSY -> exit 2       PASS    PASS    PASS    PASS
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
req c-l copies 3,03 -> 400       PASS    PASS
unknown frames skipped           PASS    PASS
IDs copied (0xffffffff,5,3)      PASS    PASS
unused flag bits ignored         PASS    PASS
literal form of table names      PASS    PASS
empty header block               PASS    PASS
HEAD: END, no DATA, c-l          PASS    PASS
HEAD 404: END, no DATA           PASS    PASS
HEAD 301: END, no DATA           PASS    PASS
HEAD bad path: 400, no DATA      PASS    PASS
HEAD bad c-l: 400, no DATA       PASS    PASS
date, last-modified IMF-fixdate  PASS    PASS
content-type by extension        PASS    PASS
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
unknown frames don't extend T    PASS    PASS
each REQUEST resets T            PASS    PASS
each body DATA resets T          PASS    PASS
cap 2: 3rd gets GOAWAY BUSY      PASS    PASS
idle close with GOAWAY 0x00      PASS    PASS

3. Client conformance (scripted server)
---------------------------------------
test                                  C       Py
IDs 1,2,3, one conn, host             PASS    PASS
unknown frames + flag bits            PASS    PASS
1-3 byte TCP segments                 PASS    PASS
uneven + empty DATA frames            PASS    PASS
GOAWAY after END is fine              PASS    PASS
pending GOAWAY: no 2nd REQUEST        PASS    PASS
wrong RESPONSE ID                     PASS    PASS
DATA before RESPONSE                  PASS    PASS
RESPONSE on ID 0                      PASS    PASS
status 199                            PASS    PASS
status 600                            PASS    PASS
content-length mismatch               PASS    PASS
content-length not digits             PASS    PASS
EOF before END                        PASS    PASS
EOF inside a frame                    PASS    PASS
GOAWAY before END -> 2                PASS    PASS
Length 16385                          PASS    PASS
second RESPONSE                       PASS    PASS
REQUEST from server                   PASS    PASS
malformed header block                PASS    PASS
c-l copies 2,3 -> 2                   PASS    PASS
c-l 20 digits -> 2                    PASS    PASS
c-l empty -> 2                        PASS    PASS
c-l 007 = 7 bytes -> 0                PASS    PASS
c-l 2,2 = 2 bytes -> 0                PASS    PASS
c-l copies 2,02 -> 2                  PASS    PASS
GOAWAY BUSY -> 2, no output           PASS    PASS
§11 exit: 301 -> 0                    PASS    PASS
§11 exit: 500 -> 5                    PASS    PASS
§11 exit: 200,404 -> 4                PASS    PASS
§11 exit: 404,500 -> 5                PASS    PASS
§11 exit: 500,404 -> 5                PASS    PASS
§11 exit: 2 beats 4 (404, bad)        PASS    PASS
§11: closed, never reopened           PASS    PASS
URL: #fragment not sent               PASS    PASS
URL: host:port?q -> /?q               PASS    PASS
URL: host:port -> /                   PASS    PASS
URL: host:port#f -> /                 PASS    PASS
URL: path sent unchanged              PASS    PASS
§11 usage: two origins -> 1           PASS    PASS
§11 usage: http:// -> 1               PASS    PASS
§11 usage: bad port -> 1              PASS    PASS
§11 usage: unknown option -> 1        PASS    PASS
§11 usage: no URL -> 1                PASS    PASS
§11 usage: URL too big -> 1           PASS    PASS
§11 usage: -t 0 -> 1                  PASS    PASS
§11 usage: -t x -> 1                  PASS    PASS
§11 -t 2: silent server -> 2          PASS    PASS
§11 -t 2: unknown frames != progress  PASS    PASS
§11 -t 2: DATA every 1 s is progress  PASS    PASS

310 checks: 310 passed, 0 failed, 0 skipped
```

Beyond the matrix, about 70 one-off probes were run against both servers and both clients
during the review: pipelined requests, 1000 requests on one connection, a half-close after
the request, a stalled reader next to a fresh connection, ENOTDIR and ENAMETOOLONG paths,
PUT and DELETE, short and odd GOAWAYs, and `localhost` resolving to both address families.
Every divergence they found became a spec question below, and then a graded row above.

## Spec questions

Every question raised during the review, and where the spec now answers it.

### Resolved

| # | Question | Resolved by | Where |
|---|---|---|---|
| 1 | Should a server check a request's `content-length`, and how does it report a bad one? | `2867662` (bserve: `6e966cc`) | §6, §7: a bad `content-length` is a request error (400, connection kept) |
| 2 | Client CLI: exit codes, URL grammar, default port, multiple URLs | `2867662` (bcurl: `9f74822`, `3918ebb`) | §11 Reference client; the URL grammar is in the top-level README |
| 3 | Repeated `content-length` with differing values | `2867662` (bcurl: `3918ebb`) | §6: further copies MUST be identical |
| 4 | Request errors on ID 0 looked like connection errors | `2867662` (bserve: `6e966cc`) | §3, §7: a REQUEST, RESPONSE or DATA on ID 0 is a connection error |
| 5 | Same-ID frames or GOAWAY while a request body is open | `2867662`, `cd6f0d2` | §7: "any *known* frame type other than DATA for that ID (unknown types are still skipped, §4; a GOAWAY just ends the connection)" |
| 6 | Does a RESPONSE sent to a server open a body? | `2867662` | §6, §7: only a REQUEST opens a body |
| 7 | GOAWAY racing the next request | `2867662` (bcurl: `a6f08af`) | §7 "Clients": GOAWAY before END means "not processed", MAY retry |
| 8 | `content-length` grammar | `2867662` | §6: 1 to 19 ASCII digits, leading zeros allowed |
| 9 | What the idle timer measures | `2867662`, `2f6c21e`, `b059295` | §2: a complete REQUEST (in a body: a DATA frame of it) is needed within T; "other and partial frames do not extend T" |
| 10 | HEAD on error statuses | `2867662`, `6fdab1a` | §6: every response to HEAD, whatever its status |
| 11 | Is ROOT itself resolved? | `2867662` | §8: "resolved the same way" |
| 12 | Date and media-type formats | `2867662`, `cd6f0d2` | §5.3: IMF-fixdate. §8 says `content-type` SHOULD follow the extension; bserve's table is in the top-level README |
| 13 | "Payload under 3 bytes" (the real minimum is 4) | `2867662` | §7: "under 4 bytes" |
| 14 | 301 `location` and the query | `3290045` | §7: path without the query, plus `/` |
| 15 | `dir/` whose `index.html` is a directory | `3290045` | §8: 404 if the path already ended in `/` |
| 16 | GOAWAY with a nonzero Request ID | `3290045` | §4: ignored on receipt |
| 17 | Are `content-length` copies compared as bytes or as values (`3` vs `03`)? | `633e106` (bserve, bcurl: `e8964fe`) | §6: byte-for-byte identical; `3` and `03` are not |
| 18 | Is a 400 to a malformed HEAD request "a response to HEAD"? | `633e106` (bserve: `15e7fc3`) | §6: every response to a REQUEST whose Method byte is HEAD, "whatever its status": END, no DATA |
| 19 | Exit code for a URL whose REQUEST can't fit in one frame | `633e106` (bcurl: `f78d831`) | §11: a usage error (exit 1) |
| 20 | When does T restart after a REQUEST: on its arrival, or once it is answered? | `b059295` | §2: "within T seconds of accepting the connection or finishing the previous response" |

### Still open

None. The last open point (when T restarts) was settled by `b059295`; it is row 20 above.

## C findings

No outstanding C bugs. Everything reported during the review was fixed upstream and is
now a passing row in the matrix:

| Was | Fixed in |
|---|---|
| bcurl sent a URL `#fragment` as part of the Path | `9f74822` |
| bcurl sent the next REQUEST past a GOAWAY that had already arrived | `a6f08af` |
| bcurl accepted conflicting `content-length` copies (it used only the first) | `3918ebb` |
| bcurl rejected `host:port?q` ("invalid port") | `3918ebb` |
| bserve ignored a request's `content-length` | `6e966cc` |
| bserve answered ID-0 frames with a request error | `6e966cc` (rule changed in `2867662`) |
| bserve/bcurl compared `content-length` copies by value (`3` = `03`) | `e8964fe` (rule settled in `633e106`) |
| bserve sent a text body with a 400 to a malformed HEAD | `15e7fc3` |
| bcurl connected before refusing a REQUEST too big for one frame, and exited 2 | `f78d831` |

## Python changes over the review

- **To follow the spec revisions:**
  - pybcurl adopted §11:
    - exit codes 0/4/5/2/1, with the worst winning;
    - one origin and one connection, never reopened;
    - `bhttp://` only;
    - the host ends at `:`, `/`, `?` or `#`;
    - a REQUEST too big for a frame is a usage error;
    - `-t seconds` (default 30): give up when no RESPONSE or DATA of the current request
      arrives in time, unknown frames not counting;
    - never write body bytes past `content-length`.
  - pybserve treats ID-0 frames as connection errors.
  - The codec enforces the 1-19-digit, byte-identical `content-length` rule, and the
    minimum REQUEST payload is now 4 bytes.
  - pybserve:
    - sends no DATA in any response to a HEAD request;
    - uses bserve's content-type table;
    - sends the 301 `location` without the query, and gives 404 for `dir/` when
      `index.html` is a directory;
    - follows the request-only idle rule;
    - caps connections (`-c`), with GOAWAY BUSY beyond the cap.
  - pybcurl's GOAWAY messages name the code, BUSY included.
- **Bugs found and fixed in my own code:**
  - pybcurl had the same `host:port?q` bug as bcurl.
  - pybcurl sent the next REQUEST past a pending GOAWAY.
  - The frame reader left a short socket timeout behind after an idle-limited read. Found
    before the first cross-test.
  - The frame reader gave each skipped unknown frame a fresh idle deadline. Found when the
    idle rule was tightened.
