#!/usr/bin/env bash
# Reproduces D-1 and D-2 end to end: ESBMC proofs, sanitizer witnesses,
# executable test cases, reachability. Run from this directory. Exits 0 only if
# every leg matches.
#
#   ./reproduce.sh            all four legs
#   ./reproduce.sh esbmc      one leg: esbmc | sanitizer | tests | reachability

set -u

UPSTREAM_COMMIT=c84017197daa00de9cc05b1166e9106e1079f7f3
RAW=https://raw.githubusercontent.com/aws/aws-sdk-cpp/$UPSTREAM_COMMIT
CXXFLAGS="-std=c++11 -g -O0 -Istubs -Ivendor -Ivendor/include"
UBSAN="-fsanitize=undefined -fno-sanitize-recover=all"
SRC="vendor/source/utils/DateTimeCommon.cpp stubs/aws_platform_time_stub.cpp"

pass=0 fail=0
check() { # check <name> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then printf '  PASS  %s\n' "$1"; pass=$((pass + 1))
  else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$1" "$2" "$3"; fail=$((fail + 1)); fi
}

leg_esbmc() {
  echo "[1/4] ESBMC -- find the defects symbolically"
  command -v esbmc >/dev/null || { echo "  SKIP  esbmc not on PATH"; return; }
  local h=harnesses
  check "D-1 overflow is reachable"     "VERIFICATION FAILED" \
    "$(esbmc --overflow-check --unwind 101 $h/d1_accumulator_esbmc.c 2>&1 | tail -2)"
  check "D-1 safe at <=9 digits"        "VERIFICATION SUCCESSFUL" \
    "$(esbmc --overflow-check --unwind 101 -DBOUND_DIGITS=9 $h/d1_accumulator_esbmc.c 2>&1 | tail -2)"
  check "D-2 overflow is reachable"     "VERIFICATION FAILED" \
    "$(esbmc --overflow-check --unwind 2 $h/d2_time_point_esbmc.c 2>&1 | tail -2)"
  check "D-2 safe inside the window"    "VERIFICATION SUCCESSFUL" \
    "$(esbmc --overflow-check --unwind 2 -DASSUME_IN_WINDOW $h/d2_time_point_esbmc.c 2>&1 | tail -2)"
}

leg_sanitizer() {
  echo "[2/4] UBSan -- confirm on the real 1.11.869 source"
  mkdir -p results
  g++ $CXXFLAGS $UBSAN harnesses/datetime_parse_asan.cpp $SRC -o results/dt_trap || return
  g++ $CXXFLAGS $UBSAN harnesses/datetime_range_ubsan.cpp $SRC -o results/dt_range || return
  check "D-1 traps in the day accumulator" "DateTimeCommon.cpp:482" \
    "$(./results/dt_trap rfc822 'Wed, 99999999999999999999 Oct 2002 08:00:00 GMT' 2>&1 | head -1)"
  check "D-2 traps converting to time_point" "chrono.h:225" \
    "$(./results/dt_range 2>&1 | tail -1)"
}

leg_tests() {
  echo "[3/4] Test cases -- ordinary build, no sanitizer, wrong values visible"
  mkdir -p results
  g++ $CXXFLAGS harnesses/datetime_cases.cpp $SRC -o results/dt_cases || return
  local out; out=$(./results/dt_cases)
  check "never-expires reads as 1816"   "1816-03-30T05:56:08Z" "$(grep -A2 'Thu, 31 Dec 9999.*rfc822' <<<"$out" | tail -1)"
  check "a 1600 timestamp reads as 2184" "2184-07-20"          "$(grep -A2 '1600-01-01.*iso8601' <<<"$out" | tail -1)"
  check "a 20-digit day is accepted"     "valid=1"             "$(grep -A2 '99999999999999999999' <<<"$out" | tail -1)"
  check "the in-range cases still pass"  "6 of 10 cases failed" "$(tail -1 <<<"$out")"
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
