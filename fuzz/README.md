# Fuzzing and robustness checks

Everything here tests the code in `src/` without changing it. Nothing in this
directory is part of the build or of `make test`.

| File | What it does |
|---|---|
| `fuzz_frame.c` | One frame: header decode/encode round trip, the payload decoder for its type (REQUEST, RESPONSE, GOAWAY), then `bh_dump_frame` (bcurl `-v`) on the same bytes |
| `fuzz_fields.c` | Header block (SPEC 5.3): `bh_fields_next` bounds and value rules, agreement with `bh_fields_check`, re-encode with `bh_put_field` and decode again, `bh_content_length`, `bh_parse_decimal` against a reference |
| `fuzz_request.c` | REQUEST payload (SPEC 5.1): an accepted path must pass an independent implementation of the path rules; `bh_path_check` must agree with it on every input |
| `fuzz_url.c` | bcurl's `parse_url` (SPEC 11) and the REQUEST it builds (`send_request` to `/dev/null`, dumped as with `-v`) |
| `fuzz_mappath.c` | bserve's `open_path` (SPEC 8) on a real tree with symlinks out of ROOT, to a sibling sharing ROOT's prefix, to `/etc`, a loop, a FIFO, a hidden file. Whatever it accepts must be a regular file inside ROOT, and the open descriptor must be the inode `realpath` named; no descriptor may leak on an error path |
| `fuzz_server.c` | A whole bserve connection: the input is everything a client sends, fed through a socketpair to the real `handle_connection` |
| `fuzz_client.c` | bcurl against a hostile server: the input is everything the server sends; the real `fetch` loop runs three URLs on one connection, `-v` on or off |
| `run_fuzz.sh` | Builds all of the above with `-fsanitize=fuzzer,address,undefined` and runs them in parallel (in Docker when the local clang has no libFuzzer, as with Apple clang) |
| `gen_seeds.py` | Seed corpora: the frames of SPEC.md §10 and HEXDUMP.md plus length and type edge cases |
| `netfuzz.py` | Network fuzzer and targeted checks (Python 3 stdlib only), see below |
| `conn_flood.py` | Connection-flood regression check for the per-connection process cap |

## How to run

```sh
make debug                      # sanitized build/debug/bserve and bcurl
make                            # release ./bserve (used by conn_flood.py)

fuzz/run_fuzz.sh 240            # every libFuzzer target for 240 s each
fuzz/run_fuzz.sh 60 server      # one target
python3 fuzz/netfuzz.py server --cases 640 --seed 4242
python3 fuzz/netfuzz.py client --cases 400 --seed 4242
python3 fuzz/netfuzz.py checks
python3 fuzz/netfuzz.py slow    # bcurl timeouts, about 75 s
python3 fuzz/conn_flood.py      # --conns 200 --hold 10 --cap 128
```

`run_fuzz.sh` writes binaries and logs to `fuzz/out/`, corpora to `fuzz/work/`,
crash inputs to `fuzz/out/crash-<target>-*` (all ignored by git). Override the
Docker image with `FUZZ_IMAGE`. `BSERVE` and `BCURL` override the binaries
the Python scripts use.

### netfuzz.py

Every frame bserve sends is checked against the spec: Length ≤ 16384, only
RESPONSE/DATA/GOAWAY, no reserved flag bits, status 200–599, a well-formed
header block, identical `content-length` copies equal to the body, DATA frames
filled but the last, and for a REQUEST whose Method byte is HEAD: END on the
RESPONSE and no DATA (worked out from the bytes actually sent, so mutated
streams are judged correctly).

- `server`: against a sanitized bserve (`-t 2`) over a tree with 0, 16383,
  16384, 16385, 65535 and 1 MiB files, symlinks out of ROOT, an unreadable file
  and directory, a FIFO. Eight kinds of connection in rotation: random bytes;
  mutated pipelined streams (bit flips, inserts, deletes, Length set to 0,
  16383, 16384, 16385, 65535), sent in random-sized pieces; valid pipelines
  whose answers must arrive complete and in order; truncated streams; a 1 MiB
  download reset part-way (SO_LINGER 0); oversized Length; 20–200 GET/HEAD on
  one connection. Every 50 cases, and at the end, a fresh `GET /hello.txt`
  must succeed; bserve's stderr must have no sanitizer line.
- `client`: a scripted server against a sanitized bcurl: lying and conflicting
  `content-length` (including `5` vs `05`), 20-digit values, Length 16385 and
  65535, RESPONSE with ID 0 or another ID, DATA before RESPONSE, a second
  RESPONSE, a REQUEST, statuses 199/600/65535, malformed header blocks, GOAWAY
  before END and between requests, EOF in the header, payload and body, unknown
  types with every flag and ID between and inside messages, a 20 MiB body;
  then random and mutated server streams. bcurl must exit with the right code
  (2 for every protocol error) and print no sanitizer report.
- `checks`: path traversal and escape variants, length boundaries, a 16384-byte
  REQUEST and a 16385 Length, 2285 header entries, malformed blocks, request
  bodies, slowloris (one byte per 0.4 s against a 2 s idle timeout), file
  descriptors and RSS over 3000 requests on one connection and 1000
  connections, ROOT and a subdirectory with search-only permission (0311),
  and ROOT made unreadable after startup.
- `slow`: bcurl against a server that sends one byte every 3 s, and one that
  sends an unknown frame every 5 s for 70 s.

### conn_flood.py

Starts its own release bserve with `-t 3`, opens 200 connections and keeps
each alive with an unknown frame every second for 10 s (past the idle
timeout). PASS needs: the listener survives, at most `--cap` connection
processes, a request after the flood is answered, no processes left.

## Results

All runs on macOS 26 (Apple Silicon); libFuzzer in Docker `silkeh/clang:18`
(clang 18.1.8, Linux aarch64, 15 CPUs).

### libFuzzer

No crash, no sanitizer report, no timeout and no leak in any run. Exec counts
are from `stat::number_of_executed_units`; `cov` is libFuzzer's edge count at
the end.

| Target | 633e106, 240 s | 7ce6503, 180 s (corpus carried over) | Total execs |
|---|---|---|---|
| frame | 8,171,457 (cov 182) | 9,336,145 (cov 183) | 17.5 M |
| fields | 58,482,120 (cov 131) | 47,550,060 (cov 131) | 106.0 M |
| request | 90,510,735 (cov 101) | 72,039,864 (cov 101) | 162.6 M |
| url | 1,613,127 (cov 172) | 975,997 (cov 172) | 2.6 M |
| mappath | 69,223,074 (cov 59) | 45,108,285 (cov 71) | 114.3 M |
| server | 635,992 (cov 266) | 541,442 (cov 279) | 1.18 M |
| client | 608,516 (cov 246) | 490,373 (cov 252) | 1.10 M |

633e106 is the main branch before the connection cap and the race-free open;
7ce6503 is after them (`fuzz_mappath.c` and `fuzz_server.c` follow the new
`open_path` and `root_fd`).

An earlier review of f7d96de, with separate harnesses, reported about 1.7 M
frame, 1.3 M server, 1.5 M client, 36 M header-block, 146 M payload and 174 M
URL executions, also without a crash.

Regression inputs: none. No harness produced a crash, so there is nothing to
keep beyond the seeds `gen_seeds.py` writes.

### Network

| Run | Build | Result |
|---|---|---|
| `netfuzz.py server --cases 640 --seed 4242` | 633e106 debug | 640 connections in 143.5 s; 0 findings, no sanitizer output, server still answers |
| `netfuzz.py client --cases 400 --seed 4242` | 633e106 debug | 137 bcurl runs (37 scripted, 100 random) in 41.3 s; 0 findings, 20 MiB body intact |
| `netfuzz.py server --cases 320 --seed 777` | 7ce6503 debug | 320 connections in 94.4 s; 0 findings, no sanitizer output, server still answers |
| `netfuzz.py client --cases 200 --seed 777` | 7ce6503 debug | 88 bcurl runs in 36.6 s; 1 finding: the `overrun` scenario (finding 2), added after the 633e106 run |
| `netfuzz.py checks` | 633e106 debug | 0 findings |
| `netfuzz.py checks` | 7ce6503 debug | 1 finding: ROOT with mode 0311 (search, no read): bserve exits at startup with "Permission denied" |
| `netfuzz.py slow` | 633e106 debug | drip: exit 2 after 30.6 s (correct); keepalive: bcurl waited 70.7 s and stopped only because the server closed (finding 3) |
| `conn_flood.py` | 633e106 release | FAIL: 200 connections, 200 processes, all still open 10 s later past a 3 s idle timeout |
| `conn_flood.py` | 7ce6503 release | PASS: peak 64 processes (the new default cap), unknown-frame connections closed at the idle timeout, requests during and after answered, none left |

Leaks: connection-process and listener descriptor counts stay flat (10 → 10
after 3000 requests on one connection and 1000 connections). The release
connection process holds 1456 KiB RSS from 2000 to 8000 requests. The debug
build grows to about 190 MiB, which is ASan's freed-memory quarantine and
not a leak; it does not grow in the release build.

The symlink-swap race fixed in 4f2578d is covered by the project's own
`TestSymlinkRace` in `tests/test_bserve.py` (all 73 tests pass on 7ce6503
under ASan/UBSan) and here by `fuzz_mappath.c`, which checks that the opened
descriptor is the inode `realpath` named.

## Findings and their status

All four were reported against 7ce6503 and are resolved on main. Each fix has a
regression test in `tests/`, and the checks that found them were re-run on
d98fb56 (see [Re-check after the fixes](#re-check-after-the-fixes)).

| # | Finding | Status |
|---|---|---|
| 1 | **Search-only directories (regression in 4f2578d).** Directories on the path, and ROOT itself, were opened with `O_RDONLY \| O_DIRECTORY`, which needs *read* permission where path lookup only needs *search*. A subdirectory at mode 0311 turned `/pub/file.txt` from 200 into 403 and `/pub` from 301 into 403; a ROOT at 0311 stopped bserve from starting. | **Fixed in 56c6e6e.** Directories are opened for search only (`O_SEARCH` / `O_PATH`, falling back to `O_RDONLY`), the last component is checked with `fstatat(..., AT_SYMLINK_NOFOLLOW)`, and only a regular file is opened. Test: `test_search_only_directory`, `TestSearchOnlyRoot`. |
| 2 | **bcurl wrote past `content-length`.** Every DATA payload went to stdout and the length was compared only after END: a server declaring 5 bytes and sending 20 MiB got all 20,971,520 bytes onto stdout before exit 2. | **Fixed in 2f7e679.** bcurl fails before writing anything beyond the declared length. Test: `test_never_writes_past_content_length`. |
| 3 | **bcurl had no overall deadline.** Every frame read got a fresh 30 s deadline, so a server sending an unknown frame every few seconds kept bcurl waiting indefinitely (70.7 s in the test). | **Fixed in 2f7e679.** Only a RESPONSE or DATA for the current request resets the wait (`-t`, default 30 s), matching bserve's rule from 08538fe. Test: `test_unknown_frames_do_not_extend_the_wait`. |
| 4 | **The connection cap has no per-peer fairness (by design, low).** One client holding all 64 slots gets everyone else refused with GOAWAY BUSY. | **Documented** in the README (bserve section). Accepted for a course server. |

## Re-check after the fixes

Run on d98fb56, which contains all four fixes:

| Check | Result |
|---|---|
| libFuzzer `mappath`, 90 s (the path code rewritten by 56c6e6e) | 38,060,303 execs, cov 69, 0 crashes or sanitizer reports |
| libFuzzer `server`, 90 s | 571,930 execs, cov 279, 0 crashes or sanitizer reports |
| libFuzzer `client`, 90 s (the bcurl code changed by 2f7e679) | 566,337 execs, cov 266, 0 crashes or sanitizer reports |
| `netfuzz.py checks` | 0 findings, including ROOT and a subdirectory at 0311 |
| `netfuzz.py client --cases 200 --seed 4242` | 88 bcurl runs, 0 findings, including the 20 MiB `overrun` scenario |
| `netfuzz.py slow` | bcurl exits 2 after 30.1 s against both the drip and the keepalive server |
| `conn_flood.py` | PASS: 200 connections, peak 64 processes, requests answered during and after the flood |
