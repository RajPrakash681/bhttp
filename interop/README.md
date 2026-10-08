# interop: a second, independent bhttp/1 implementation

> "A client that only works against your own server is an implementation, not a protocol."

This directory holds a second client and server for bhttp/1, written in Python **from
`SPEC.md` alone**, plus a test matrix that runs every client against every server. If the
C `bcurl` and the Python `pybserve` get along (and the Python `pybcurl` and the C `bserve`
do too), then the spec carries enough information to build a working peer. Where it doesn't,
the questions are collected in [Spec questions](#spec-questions) below.

## Clean-room rule

The Python side was written while the only file read from the rest of the repository was
`SPEC.md` (and `SPEC.pdf`, which is rendered from it). `src/`, `Makefile`, `tests/`,
`HEXDUMP.md` and `README.md` were not opened until the Python code was finished and the
first full cross-test had run. Two things that the spec doesn't define were taken from the
running C programs' usage text, never their source: how to invoke them (`bserve ROOT PORT`,
`bcurl [-v] URL...`) and bcurl's documented exit codes, which the matrix needs to know
what to expect. The first full cross-test passed every check. After that the C sources
were read only to confirm the divergences listed below. SPEC.md was revised in `3290045`
(after that first run) to settle three of the questions below. The Python code was then
brought in line with it, and the new rules were added to the matrix.

## Files

| File | What it is |
|---|---|
| `pybhttp.py` | Frame and payload codec: 8-byte header, the four frame types, header block with the 10-name static table and literal form, GOAWAY, a frame reader that skips unknown types by exactly Length bytes, one-line frame dumps for `-v`. |
| `pybserve.py` | `pybserve ROOT PORT [--idle SECONDS]`: file server. Path mapping (§8), 200/301/400/403/404/405/500, keep-alive, request bodies read through END, request errors (400, connection kept) vs connection errors (400 on ID 0, GOAWAY 0x01, close), idle close with GOAWAY 0x00, one thread per connection. |
| `pybcurl.py` | `pybcurl [-v] URL...`: client. One connection for consecutive URLs to the same host:port, IDs 1, 2, 3, ..., bodies to stdout, every §7 "Clients" check, no new REQUEST after a GOAWAY that is already waiting on the socket, `-v` frame dumps on stderr. |
| `run_interop.py` | The matrix. Builds the C programs with `make`, generates the test files (including a 21-frame random file) in a temp dir, uses free ports, kills every server it starts. |

Everything is Python 3.9+ standard library only.

## Running it

```sh
python3 interop/run_interop.py           # full matrix, about 5 s
python3 interop/run_interop.py --slow    # also the 30 s idle-timeout test (about 70 s)
python3 interop/run_interop.py --only Py # one implementation against itself
python3 interop/run_interop.py --keep    # keep the temp tree and both server logs
```

It exits 0 only if every check passed. To try the Python pair by hand:

```sh
python3 interop/pybserve.py www 9000 &
python3 interop/pybcurl.py -v localhost:9000/hello.txt localhost:9000/style.css
./bcurl localhost:9000/          # C client, Python server
```

`pybcurl` takes the same URL forms as `bcurl` (`[bhttp://]host[:port][/path]`, port 9000 by
default). SPEC.md defines no exit codes, so pybcurl uses its own: 0 all responses were
2xx/3xx; 1 at least one was 4xx/5xx; 2 usage error; 3 could not connect, or the server
ended the connection (GOAWAY or close) before every URL was sent; 4 protocol error.

## What the matrix checks

0. **Reference bytes.** The §10 worked example and the full HEXDUMP.md capture are decoded
   and re-encoded by `pybhttp` and must come out byte for byte the same.
1. **Pairing matrix**, for C->C, C->Py, Py->C and Py->Py. The client talks to the server
   through a frame-aware proxy that counts TCP connections and frames, and can inject
   unknown frames or corrupt one frame:
   - 200 with a byte-exact body; 404 and the client's documented exit code;
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
   - the proxy rewrites the RESPONSE ID: the client must fail and must not print the page;
   - connection refused; `-v` writes to stderr and leaves stdout byte-exact.
2. **Server conformance.** Hand-built frames sent straight to each server: HTTP/1.1 text,
   Length 16385, unknown type with Length 65535, foreign frames while a body is open (all
   connection errors: 400 on ID 0, GOAWAY 0x01 with the right Last-ID, orderly close); 19
   request errors that must each get 400 and leave the connection usable; unknown frames
   before a request and inside a request body; IDs 0xffffffff, 5, 3 copied back; HEAD;
   POST with a body gets 405 plus `allow`; 301, and its `location` without the query;
   index.html, and 404 when `dir/index.html` is itself a directory; query dropped;
   `%2e%2e` is a literal name; hidden files, symlinks out of the root, a FIFO and an
   unreadable file; a truncated frame; client GOAWAY, also with a nonzero ID; with
   `--slow`, idle close with GOAWAY 0x00.
3. **Client conformance.** Each client against a scripted server that sends unknown frames
   and unused flag bits everywhere, literal header names, fragmented or uneven DATA, a
   GOAWAY that arrives with the first response (the second URL must not be requested),
   and then each §7 "Clients" protocol error in turn: wrong ID, DATA before RESPONSE, RESPONSE
   on ID 0, status 199 and 600, content-length mismatch or non-digits, EOF before END or
   inside a frame, GOAWAY before END, Length 16385, a second RESPONSE, a REQUEST, a
   malformed header block. Each must give that client's protocol-error exit code.
4. **Observations.** No verdict, just what each side does where the spec is silent or
   ambiguous. These rows are the evidence for the questions below.

The harness was itself checked by running it against deliberately broken copies of the
Python code: a receiver that doesn't skip unknown types, a server that closes after a
request error, a client that ignores the response ID, and a client that sends its next
REQUEST past a pending GOAWAY. Each one turned the expected rows red.

## Results

Final run (macOS, Apple Silicon, Python 3.9.6, C programs built from `a6f08af`):

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
404 + documented exit code  PASS    PASS    PASS    PASS
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
test                            C       Py
HTTP/1.1 text -> conn error     PASS    PASS
Length 16385 -> 400/0, GOAWAY   PASS    PASS
unknown type, Length 65535      PASS    PASS
DATA other ID in body           PASS    PASS
REQUEST while body open         PASS    PASS
REQUEST with ID 0               PASS    PASS
payload under 3 bytes           PASS    PASS
unknown method 0x06             PASS    PASS
Path Length 0                   PASS    PASS
Path Length past payload        PASS    PASS
path without leading /          PASS    PASS
path with .. segment            PASS    PASS
path with . segment             PASS    PASS
path ending in /..              PASS    PASS
path with NUL                   PASS    PASS
path with 0x7f                  PASS    PASS
query only (?x)                 PASS    PASS
header index 11                 PASS    PASS
header runs past payload        PASS    PASS
literal name empty              PASS    PASS
literal name uppercase          PASS    PASS
header value with CR            PASS    PASS
RESPONSE sent to server         PASS    PASS
DATA with no open body          PASS    PASS
bad REQUEST w/ body -> 1x400    PASS    PASS
unknown frames skipped          PASS    PASS
IDs copied (0xffffffff,5,3)     PASS    PASS
unused flag bits ignored        PASS    PASS
literal form of table names     PASS    PASS
empty header block              PASS    PASS
HEAD: END, no DATA, c-l         PASS    PASS
POST + body -> 405, allow       PASS    PASS
/sub -> 301 location /sub/      PASS    PASS
/sub/ -> index.html             PASS    PASS
301 location drops query        PASS    PASS
dir/ whose index is a dir: 404  PASS    PASS
query dropped                   PASS    PASS
%2e%2e is a literal name        PASS    PASS
/.hidden -> 404                 PASS    PASS
/sub/.secret -> 404             PASS    PASS
missing file -> 404             PASS    PASS
symlink inside root -> 200      PASS    PASS
symlink outside root -> 404     PASS    PASS
dir symlink outside -> 404      PASS    PASS
FIFO (not regular) -> 404       PASS    PASS
unreadable file -> 403          PASS    PASS
empty file                      PASS    PASS
truncated frame -> close        PASS    PASS
client GOAWAY -> close          PASS    PASS
GOAWAY ID 7 ignored -> close    PASS    PASS
idle close with GOAWAY 0x00     PASS    PASS

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
GOAWAY before END               PASS    PASS
Length 16385                    PASS    PASS
second RESPONSE                 PASS    PASS
REQUEST from server             PASS    PASS
malformed header block          PASS    PASS

4. Observed behaviour where SPEC.md is silent or ambiguous (not graded)
-----------------------------------------------------------------------
probe                   C server   Py server
REQUEST c-l 5, no body  200        400
REQUEST c-l 'x'         200        400

probe                       C client           Py client
exit code for a 404         exit 4             exit 1
exit code for a 500         exit 5             exit 1
exit code, protocol error   exit 2             exit 4
exit code, refused          exit 2             exit 3
two content-lengths 2,3     exit 0             exit 4
URL /x#frag sends path      '/x'               '/x'
URL host:port?q sends path  not sent (exit 1)  '/?q=1'
URL /a/../b sends path      '/a/../b'          '/a/../b'

188 checks: 188 passed, 0 failed, 0 skipped
```

Beyond the matrix, about 70 one-off probes were run against both servers and both
clients: pipelined requests, 1000 requests on one connection, a half-close after the
request, a stalled reader next to a fresh connection, partial frames left to hit the
idle timer, a maximum-size REQUEST, ENOTDIR and ENAMETOOLONG paths, HEAD on 301/404, PUT
and DELETE, short and odd GOAWAYs, `localhost` resolving to both address families, and
more. The two servers gave the same status, the same frame sequence and the same GOAWAY
Last-ID in every probe except the two server rows above (and, before `3290045`, the 301
`location` for a path with a query). Only the error-body text and the
`content-type` charset differed. The two clients agreed on everything except the client
rows above and two CLI choices: pybcurl also accepts `http://` and opens a new connection
when the host:port changes, while bcurl refuses both.

**Verdict: the spec is a protocol.** Two implementations written independently from it
interoperate in every pairing and on every check. The differences that remain are in places
the spec does not define (client CLI, URL handling) or defines loosely (request
`content-length`, duplicate `content-length`).

## Spec questions

Each entry gives the section, what is ambiguous, what each side does, and a proposed fix.
Questions 1-3 are where the two implementations still behave differently. The last three
were settled by the spec revision in `3290045` and are kept for the record.

### Open

1. **§6/§7/§11: request `content-length` on the server.** §6 says `content-length` MUST equal
   the body length and §11 says "Both: ... `content-length` checked against the body", but
   §7's list of request errors doesn't mention a wrong or non-numeric `content-length`, so
   it's unclear what a server should do. *bserve* ignores it (200). *pybserve* treats it
   as a request error (400 after reading the body, connection kept). **Fix:** add "a
   `content-length` that is not ASCII digits or differs from the body length" to the §7
   request-error list. Otherwise, say servers ignore it and change §11 to "Client".
2. **No client CLI in the spec: exit codes, URL syntax, default port, multiple URLs.** The
   course brief asks for "exit codes as the spec says", but SPEC.md has none. bcurl's
   contract (0 for 2xx/3xx, 4 for 4xx, 5 for 5xx, 2 for connection or protocol error, 1 for
   usage; worst status wins; `[bhttp://]host[:port][/path]`, port 9000; one origin per run)
   lives only in bcurl's usage text and the top-level README. From the spec alone pybcurl
   chose 0/1/2/3/4, so exit 4 means "4xx" for one client and "protocol error" for the other.
   The spec also doesn't say how a URL becomes a Path: bcurl can't parse `host:port?q`, and
   until `9f74822` it sent the `#fragment` on the wire. **Fix:** add a short "Reference
   client" section with the URL grammar (fragment stripped, authority ends at `/`, `?` or
   `#`, empty path is `/`), the default port and the exit codes. pybcurl will adopt it.
3. **§5.3/§6: repeated `content-length`.** "Repeated names are allowed, with HTTP meaning",
   and in HTTP differing values make the message invalid. *bcurl* uses the first value
   and accepts `content-length: 2` + `content-length: 3` with a 2-byte body (exit 0).
   *pybcurl* rejects it as a protocol error. **Fix:** "If `content-length` appears more than
   once, all values MUST be identical, or the message is malformed."
4. **§7: request errors on ID 0 look like connection errors.** A REQUEST with ID 0 (or a
   stray DATA or RESPONSE with ID 0) is a request error answered "with the offending
   frame's ID", which means a 400 on ID 0 with the connection kept open. But a connection
   error is also a 400 on ID 0, and §7 "Clients" says a RESPONSE on ID 0 "reports a
   connection error". A peer can only tell them apart by waiting for a GOAWAY that may
   never come. Both servers follow the letter (400 on ID 0, connection kept). **Fix:** make
   any REQUEST, DATA or RESPONSE with ID 0 a connection error, which is simpler and needs
   no new rule. Or say that ID-0 request errors are answered on ID 0 and that only a
   following GOAWAY means the connection is gone.
5. **§7: same-ID frames while a request body is open.** Only frames "for another ID" are
   listed as connection errors. A second REQUEST, or a RESPONSE, with the *same* ID while
   the body is open isn't covered, and neither is a GOAWAY. Both servers treat a same-ID
   REQUEST/RESPONSE as a connection error, and both close silently on GOAWAY. **Fix:** "while
   a request body is open, any frame other than DATA for that ID, GOAWAY or an unknown
   type is a connection error; a GOAWAY ends the connection".
6. **§7: a RESPONSE sent to a server without END.** Does it open a body, so that its DATA
   frames get read and dropped? Or is each following DATA a separate "DATA with no open
   request body"? Both servers answer 400 for the RESPONSE and another 400 for each DATA.
   **Fix:** say "only a REQUEST opens a body".
7. **§2/§4/§7: GOAWAY racing the next request.** A server that times out between requests
   sends GOAWAY(Last-ID = n). Both clients now check for a GOAWAY that has already arrived
   before sending request n+1 (bcurl since `a6f08af`), and the matrix tests this. But if
   the GOAWAY lands just *after* request n+1 is sent, the client reads a GOAWAY "before
   END", which §7 calls a protocol error. Meanwhile §4 says requests above Last-ID "were
   not processed and MAY be retried on a new connection". **Fix:** "A GOAWAY whose Last-ID
   is below the outstanding request's ID is not a protocol error: the request was not
   processed, and the client MAY retry it on a new connection."
8. **§6: `content-length` value grammar.** "ASCII decimal digits" has no length limit.
   bcurl rejects a 20-digit value as malformed. pybcurl accepts it and then reports a
   length mismatch. Both fail, but for different reasons. Leading zeros (`007`) are
   accepted by both. **Fix:** "1 to 19 ASCII digits; leading zeros allowed".
9. **§2: what the idle timer measures.** "No complete frame has arrived for T seconds while
   it waits for one" leaves open whether T starts when the server begins waiting (after
   its last response) or at the last byte received, and whether a partial frame resets
   it. Both servers use one deadline per frame, starting when they begin waiting. A
   trickle of one byte every 0.8 s still gets GOAWAY at T, which was checked with T = 3 s
   on both. **Fix:** say exactly that.
10. **§6: HEAD on error responses.** "A response to HEAD ... sets END on the RESPONSE and
    has no DATA". It's implied but not stated that this also covers 301/404/405 to HEAD
    (both servers send END and no body, with the error body's `content-length`). **Fix:**
    "every response to HEAD, whatever its status".
11. **§8: ROOT itself and symlinks.** "If the result is not inside ROOT" only works if ROOT
    is resolved too (on macOS, `/tmp` is really `/private/tmp`). Both servers resolve ROOT
    once at startup. **Fix:** "ROOT is resolved the same way".
12. **§5.3: date and media-type formats.** `date` and `last-modified` have "HTTP meaning",
    and both servers send IMF-fixdate. `content-type` "SHOULD follow the file extension"
    with no table: bserve sends `text/plain; charset=utf-8` and pybserve `text/plain`.
    Harmless, but one line each would pin them down (IMF-fixdate per RFC 9110 §5.6.7, and
    a short extension table or "as in the IANA registry").
13. **§7 (cosmetic): "a payload under 3 bytes".** A 3-byte REQUEST payload is always
    malformed anyway (Path Length 0 or past the payload), so the real minimum is 4. No
    behaviour change; the wording could say "under 4 bytes".

### Settled by `3290045`

- **§7: the 301 `location` was "path + `/`".** In §5.1 the Path includes the query, so
  `/dir?x=1` read literally gave `/dir?x=1/`. bserve dropped the query and pybserve kept
  it (`/dir/?x=1`). Now: "path (without the query) + `/`". pybserve follows it, and the
  matrix tests it.
- **§8: a directory reached through a trailing `/`.** "A directory gets 301" said nothing
  about `/dir/` when `dir/index.html` is itself a directory. pybserve would have answered
  301 to `/dir//`. Now: "or 404 if the path already ended in `/`". pybserve follows it,
  and the matrix tests it.
- **§4: GOAWAY with a nonzero Request ID.** There was no rule for it. Now: "Its Request ID
  is 0 and is ignored on receipt". Both servers already behaved this way, and the matrix
  tests it.

## C findings

No protocol bug was found in bserve or bcurl: every wire-level check above passes in every
pairing. These are the small issues found, with reproduction steps:

- **bcurl accepts conflicting `content-length` values** (`src/bcurl.c` looks only at the
  first one, via `bh_fields_find`). Repro: a server that answers
  `RESPONSE 200 [content-length: 2, content-length: 3]` + `DATA END "ab"` gets exit 0.
  The fix depends on spec question 3.
- **bcurl rejects a URL with a query and no path.** `./bcurl 'localhost:9000?x=1'` exits 1
  with "invalid port", and `./bcurl 'localhost?x=1'` with "unexpected character after
  host". The authority should end at `?` (RFC 3986 §3.2), and the Path should be `/?x=1`.
  `parse_url` ends the host only at `:`, `/` or `#`.
- **bserve never checks a request's `content-length`.** A GET with `content-length: 5` and
  no body, or `content-length: x`, gets 200. §6/§11 suggest it should be checked. See spec
  question 1.
- *Fixed upstream while this was being written:* bcurl sent a URL `#fragment` as part of
  the Path (`9f74822`), and it sent the next REQUEST even when a GOAWAY was already waiting
  on the socket (`a6f08af`). Both are now covered by the matrix and pass.

## Python bugs found and fixed

- **`pybcurl` URL parsing** had the same `host:port?q` bug as bcurl ("bad port"). Found by
  the probes and fixed: the authority now ends at `/` or `?`, and an empty path becomes `/`.
- **`pybcurl` sent the next REQUEST past a pending GOAWAY.** It now reads anything the
  server sent since the last END before reusing the connection. Unknown frames are
  skipped. A GOAWAY or EOF stops it with exit 3. Any other known frame is a protocol error.
- **`pybserve` 301 `location` and `dir/` with a directory `index.html`** were changed to the
  revised §7/§8 (see "Settled" above).
- Found during development, before the first cross-test: the frame reader left a short
  socket timeout behind after an idle-limited read, so a large response to a slow reader
  could have failed. Fixed: the reader restores the socket's previous timeout.
