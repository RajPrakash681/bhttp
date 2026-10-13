#!/bin/sh
# Builds every libFuzzer harness in fuzz/ with ASan + UBSan and runs them all
# in parallel for SECONDS each (default 240). Needs clang with -fsanitize=fuzzer;
# on macOS (Apple clang has no libFuzzer) it re-runs itself in Docker.
#
#   fuzz/run_fuzz.sh [SECONDS] [TARGET...]
#
# Output: fuzz/out/<target> (binaries), fuzz/out/<target>.log, corpora in
# fuzz/work/<target>, crash inputs in fuzz/out/crash-<target>-*.
set -eu
cd "$(dirname "$0")/.."
SECS=${1:-240}
[ $# -gt 0 ] && shift
TARGETS=${*:-"frame fields request url mappath server client"}
[ -d fuzz/seeds ] || python3 fuzz/gen_seeds.py

if ! echo 'int LLVMFuzzerTestOneInput(const char*d,unsigned long n){return 0;}' |
     clang -x c -fsanitize=fuzzer - -o /dev/null 2>/dev/null; then
    IMAGE=${FUZZ_IMAGE:-silkeh/clang:18}
    exec docker run --rm --name bhttp-fuzz-$$ -v "$PWD":/src -w /src "$IMAGE" \
        sh fuzz/run_fuzz.sh "$SECS" $TARGETS
fi

CFLAGS="-std=c11 -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE -g -O1 -fno-omit-frame-pointer \
 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -Isrc -pthread"
mkdir -p fuzz/out
for t in $TARGETS; do
    clang $CFLAGS -o fuzz/out/$t fuzz/fuzz_$t.c src/bhttp.c src/netio.c src/dump.c
done
for t in $TARGETS; do
    mkdir -p fuzz/work/$t
    seeds=fuzz/seeds/$t
    [ -d "$seeds" ] || seeds=
    case $t in server|client) max=65536 ;; url) max=20000 ;; *) max=16400 ;; esac
    ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1 \
        fuzz/out/$t -max_total_time="$SECS" -max_len=$max -timeout=10 -rss_limit_mb=2048 \
        -close_fd_mask=3 -print_final_stats=1 -artifact_prefix=fuzz/out/crash-$t- \
        fuzz/work/$t $seeds > fuzz/out/$t.log 2>&1 &
done
wait
for t in $TARGETS; do
    execs=$(grep -o 'stat::number_of_executed_units: *[0-9]*' fuzz/out/$t.log | grep -o '[0-9]*$' || echo '?')
    cov=$(grep -o 'cov: [0-9]*' fuzz/out/$t.log | tail -1 || true)
    crash=$(grep -cE 'ERROR: (AddressSanitizer|LeakSanitizer|libFuzzer)|runtime error|deadly signal' fuzz/out/$t.log || true)
    echo "$t: execs=$execs $cov sanitizer/crash reports=$crash corpus=$(ls fuzz/work/$t | wc -l)"
done
