#!/usr/bin/env bash
# Reproduces D-1 and D-2 end to end: ESBMC proofs, sanitizer witnesses,
# executable test cases, reachability. Run from this directory. Exits 0 only if
# every leg matches.
#
#   ./reproduce.sh            all four legs
#   ./reproduce.sh esbmc      one leg: esbmc | sanitizer | tests | reachability
#
# D-2's runtime legs need a nanosecond system_clock (libstdc++); on libc++ they
# are skipped, since its microsecond clock puts these dates inside the window.
# Set CXX to pick a compiler, or CLOCK_DEN to see another platform's rendering.

set -u

UPSTREAM_COMMIT=c84017197daa00de9cc05b1166e9106e1079f7f3
RAW=https://raw.githubusercontent.com/aws/aws-sdk-cpp/$UPSTREAM_COMMIT
CXX=${CXX:-g++}
CXXFLAGS="-std=c++11 -g -O0 -Istubs -Ivendor -Ivendor/include"
UBSAN="-fsanitize=undefined -fno-sanitize-recover=all"
SRC="vendor/source/utils/DateTimeCommon.cpp stubs/aws_platform_time_stub.cpp"
CLOCK_DEN=${CLOCK_DEN:-}

clock_den() { # ticks per second in system_clock::period
  if [[ -z "$CLOCK_DEN" ]]; then
    mkdir -p results
    printf '#include <chrono>\n#include <cstdio>\nint main(){std::printf("%%lld\\n",(long long)std::chrono::system_clock::period::den);}\n' > results/clock_probe.cpp
    $CXX -std=c++11 results/clock_probe.cpp -o results/clock_probe 2>/dev/null &&
      CLOCK_DEN=$(./results/clock_probe) || CLOCK_DEN=0
  fi
  echo "$CLOCK_DEN"
}

pass=0 fail=0
check() { # check <name> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then printf '  PASS  %s\n' "$1"; pass=$((pass + 1))
  else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$1" "$2" "$3"; fail=$((fail + 1)); fi
}

# Match the verdict line itself, not the last lines of the run: the version
# banner arrives on the other stream, and twice under load the verdict landed
# outside a two-line tail and read as a failed obligation. A run that produces
# no verdict at all now says so instead of failing as a wrong one.
verdict() {
  local out; out=$("$@" 2>&1)
  grep -m1 -E '^VERIFICATION (SUCCESSFUL|FAILED)' <<<"$out" ||
    printf 'no verdict; last lines: %s' "$(tail -3 <<<"$out" | tr '\n' ' ')"
}

leg_esbmc() {
  echo "[1/4] ESBMC -- find the defects symbolically"
  command -v esbmc >/dev/null || { echo "  SKIP  esbmc not on PATH"; return; }
  local h=harnesses
  check "D-1 overflow is reachable"     "VERIFICATION FAILED" \
    "$(verdict esbmc --overflow-check --unwind 101 $h/d1_accumulator_esbmc.c)"
  check "D-1 safe at <=9 digits"        "VERIFICATION SUCCESSFUL" \
    "$(verdict esbmc --overflow-check --unwind 101 -DBOUND_DIGITS=9 $h/d1_accumulator_esbmc.c)"
  check "D-2 overflow is reachable"     "VERIFICATION FAILED" \
    "$(verdict esbmc --overflow-check --unwind 2 $h/d2_time_point_esbmc.c)"
  check "D-2 safe inside the window"    "VERIFICATION SUCCESSFUL" \
    "$(verdict esbmc --overflow-check --unwind 2 -DASSUME_IN_WINDOW $h/d2_time_point_esbmc.c)"
}

leg_sanitizer() {
  echo "[2/4] UBSan -- confirm on the real 1.11.869 source"
  mkdir -p results
  $CXX $CXXFLAGS $UBSAN harnesses/datetime_parse_asan.cpp $SRC -o results/dt_trap || return
  $CXX $CXXFLAGS $UBSAN harnesses/datetime_range_ubsan.cpp $SRC -o results/dt_range || return
  check "D-1 traps in the day accumulator" "DateTimeCommon.cpp:482" \
    "$(./results/dt_trap rfc822 'Wed, 99999999999999999999 Oct 2002 08:00:00 GMT' 2>&1 | head -1)"

  local den; den=$(clock_den)
  if [[ "$den" != 1000000000 ]]; then
    echo "  SKIP  D-2 needs a nanosecond system_clock; this one is 1/$den s, so these dates are in range"
    return
  fi
  check "D-2 traps converting to time_point" "chrono.h:225" \
    "$(./results/dt_range 2>&1 | tail -1)"
}

leg_tests() {
  echo "[3/4] Test cases -- ordinary build, no sanitizer, wrong values visible"
  mkdir -p results
  $CXX $CXXFLAGS harnesses/datetime_cases.cpp $SRC -o results/dt_cases || return
  local out den; out=$(./results/dt_cases)
  den=$(grep -o 'clock_den=[0-9]*' <<<"$out" | cut -d= -f2)  # what the binary saw
  row() { grep -m1 "RESULT.*$1" <<<"$out"; }  # one line per case, so no misreads

  check "an ordinary timestamp round-trips" "RESULT PASS" "$(row '2002-10-02')"
  check "a 20-digit day is accepted"        "valid=1"     "$(row '99999999999999999999')"
  check "a nine-digit day inverts"          "RESULT FAIL" "$(row '999999999 Oct')"

  if [[ "$den" != 1000000000 ]]; then
    echo "  SKIP  the four D-2 cases: a 1/$den s system_clock represents those dates"
    check "the skip is reported"           "skipped=4"            "$(grep SUMMARY <<<"$out")"
    return
  fi
  check "never-expires reads as 1816"      "1816-03-30T05:56:08Z" "$(row 'Thu, 31 Dec 9999')"
  check "a 1600 timestamp reads as 2184"   "2184-07-20"           "$(row '1600-01-01')"
  check "the in-range cases still pass"    "failed=6 checked=10"  "$(grep SUMMARY <<<"$out")"
}

leg_reachability() {
  echo "[4/4] Reachability -- untrusted input reaches both, at $UPSTREAM_COMMIT"
  local tmp; tmp=$(mktemp -d)
  curl -fsS "$RAW/src/aws-cpp-sdk-core/source/client/AWSClient.cpp" -o "$tmp/AWSClient.cpp" 2>/dev/null \
    || { echo "  SKIP  no network"; return; }
  curl -fsS "$RAW/generated/src/aws-cpp-sdk-s3/source/model/GetObjectResult.cpp" -o "$tmp/GetObjectResult.cpp"
  curl -fsS "$RAW/generated/src/aws-cpp-sdk-s3/include/aws/s3/model/PutObjectRequest.h" -o "$tmp/PutObjectRequest.h"

  check "response Date header -> AutoDetect" "DateFormat::AutoDetect" \
    "$(sed -n '219p' "$tmp/AWSClient.cpp")"
  check "AutoDetect tries RFC822 first" "RFC822DateParser" \
    "$(sed -n '/case DateFormat::AutoDetect:/,/ISO_8601DateParser/p' vendor/source/utils/DateTimeCommon.cpp | grep -m1 DateParser)"
  check "S3 Last-Modified -> RFC822" "DateFormat::RFC822" \
    "$(sed -n '53p' "$tmp/GetObjectResult.cpp")"
  check "S3 Expires -> RFC822" "DateFormat::RFC822" \
    "$(sed -n '189p' "$tmp/GetObjectResult.cpp")"
  check "Expires is uploader-settable" "SetExpires" \
    "$(sed -n '610p' "$tmp/PutObjectRequest.h")"
  rm -rf "$tmp"
}

case "${1:-all}" in
  esbmc) leg_esbmc ;;
  sanitizer) leg_sanitizer ;;
  tests) leg_tests ;;
  reachability) leg_reachability ;;
  all) leg_esbmc; leg_sanitizer; leg_tests; leg_reachability ;;
  *) echo "usage: $0 [all|esbmc|sanitizer|tests|reachability]"; exit 2 ;;
esac

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
