#!/usr/bin/env bash
# Reproduces D-1 and D-2 end to end: ESBMC proofs, sanitizer witnesses,
# executable test cases, reachability, and the upstream fix. Run from this
# directory. Exits 0 only if every leg matches.
#
#   ./reproduce.sh            all five legs
#   ./reproduce.sh esbmc      one leg: esbmc | sanitizer | tests | reachability | fix
#
# A sixth leg, `module`, discharges the same two properties against the whole
# pristine translation unit rather than the extracted models. It is minutes per
# obligation rather than seconds, so `all` leaves it out; run it on its own.
#
# D-2's runtime legs need a nanosecond system_clock (libstdc++); on libc++ they
# are skipped, since its microsecond clock puts these dates inside the window.
# Set CXX to pick a compiler, or CLOCK_DEN to see another platform's rendering.

set -u

UPSTREAM_COMMIT=c84017197daa00de9cc05b1166e9106e1079f7f3
RAW=https://raw.githubusercontent.com/aws/aws-sdk-cpp/$UPSTREAM_COMMIT
FIXED_VERSION=1.11.877  # first tag carrying PR #3896
FIXED_RAW=https://raw.githubusercontent.com/aws/aws-sdk-cpp/$FIXED_VERSION
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
  echo "[1/5] ESBMC -- find the defects symbolically"
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
  echo "[2/5] UBSan -- confirm on the real 1.11.869 source"
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
  echo "[3/5] Test cases -- ordinary build, no sanitizer, wrong values visible"
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
  echo "[4/5] Reachability -- untrusted input reaches both, at $UPSTREAM_COMMIT"
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

leg_fix() {
  echo "[5/5] Fix -- both defects closed upstream in $FIXED_VERSION (PR #3896)"
  mkdir -p results
  local fixed=results/DateTimeCommon.$FIXED_VERSION.cpp
  curl -fsS "$FIXED_RAW/src/aws-cpp-sdk-core/source/utils/DateTimeCommon.cpp" -o "$fixed" 2>/dev/null \
    || { echo "  SKIP  no network"; return; }

  # The field widths we submitted went in unchanged: applying our patch to the
  # pristine file leaves no parser-side difference against what AWS shipped.
  local ours=results/DateTimeCommon.ourfix.cpp
  cp vendor/source/utils/DateTimeCommon.cpp "$ours"
  patch -s -p1 --no-backup-if-mismatch --input=fix/d1-bound-field-widths.patch "$ours"
  check "our field widths shipped verbatim" "0 parser lines differ" \
    "$(diff "$ours" "$fixed" | grep -c stateStartIndex) parser lines differ"
  check "D-2 is fixed by a range check" "IsSecondsSinceEpochRepresentable" \
    "$(grep -m1 IsSecondsSinceEpochRepresentable "$fixed")"

  # UBSan on both: a surviving overflow aborts, so any output is half the claim.
  $CXX $CXXFLAGS $UBSAN harnesses/datetime_parse_asan.cpp "$fixed" \
    stubs/aws_platform_time_stub.cpp -o results/dt_trap_fixed || return
  $CXX $CXXFLAGS $UBSAN harnesses/datetime_cases.cpp "$fixed" \
    stubs/aws_platform_time_stub.cpp -o results/dt_cases_fixed || return

  check "a 20-digit day is rejected, not wrapped" "valid=0" \
    "$(./results/dt_trap_fixed rfc822 'Wed, 99999999999999999999 Oct 2002 08:00:00 GMT' 2>&1 | tail -1)"

  local out den; out=$(./results/dt_cases_fixed); den=$(clock_den)
  if [[ "$den" == 1000000000 ]]; then
    check "never-expires is rejected, not read as 1816" "valid=0" \
      "$(grep -m1 'Thu, 31 Dec 9999' <<<"$out")"
  else
    echo "  SKIP  never-expires: a 1/$den s system_clock represents that date"
  fi
  check "every contract case holds on $FIXED_VERSION" "failed=0" \
    "$(grep SUMMARY <<<"$out")"
}

# The extracted harnesses exist because ESBMC could not parse the real TU. It
# can now, so the same properties can be put to the module itself: FAILED on
# 1.11.869 and SUCCESSFUL on 1.11.877 is the pair. Only the SUCCESSFUL runs need
# a complete unwind -- a counterexample is sound at any depth -- so the two
# directions get different bounds, and the unwinding assertions are left ON so a
# truncated loop cannot pass for a proof.
leg_module() {
  echo "[6] Module -- both properties on the pristine TU, not an extraction"
  command -v esbmc >/dev/null || { echo "  SKIP  esbmc not on PATH"; return; }
  mkdir -p results
  local fixed=results/DateTimeCommon.$FIXED_VERSION.cpp
  [[ -f "$fixed" ]] || curl -fsS "$FIXED_RAW/src/aws-cpp-sdk-core/source/utils/DateTimeCommon.cpp" \
    -o "$fixed" 2>/dev/null || { echo "  SKIP  no network"; return; }

  local -a common=(--std c++11 --overflow-check --include-file cctype
                   -I stubs -I vendor -I vendor/include)
  local -a d1=(-DDT_FORMAT=RFC822 '-DDT_INPUT="Wed, 99999999999999999999 Oct 2002 08:00:00 GMT"')
  local h=harnesses/datetime_pristine_esbmc.cpp
  local pristine=vendor/source/utils/DateTimeCommon.cpp
  local stub=stubs/aws_platform_time_stub.cpp

  # The whole violation block on one line: the site pins D-1 to a source line,
  # the property text pins D-2. Say so when there is no block at all -- these
  # runs are big enough to be OOM-killed, and a killed run must not be read as
  # "the property held".
  violation() {
    grep -A3 'Violated property' <<<"$1" | tr '\n' ' ' | grep . ||
      printf 'no violation reported; run may not have completed: %s' \
        "$(tail -2 <<<"$1" | tr '\n' ' ')"
  }

  # D-2 first: an ordinary 20-character date, ~0.6 GB and 20-30 s a side.
  local out
  out=$(esbmc "${common[@]}" --unwind 25 $h $pristine $stub 2>&1)
  check "D-2 overflows the seconds-to-nanoseconds multiply" "arithmetic overflow on mul" \
    "$(violation "$out")"
  check "the range check holds on $FIXED_VERSION" "VERIFICATION SUCCESSFUL" \
    "$(verdict esbmc "${common[@]}" --unwind 25 $h "$fixed" $stub)"

  # D-1 costs more, and the floor is not negotiable: strlen alone unwinds once
  # per character, so a 46-character input needs ~47 before the parse loop is
  # even reached -- ~1.7 GB and ~5m45s a side. The guard is only so a host with
  # no headroom cannot OOM-kill a proof and leave a log that reads clean.
  local free_gb; free_gb=$(free -g | awk '/^Mem:/ {print $7}')
  if (( ${free_gb:-0} < 4 )); then
    echo "  SKIP  the D-1 pair peaks near 1.7 GB and this leg wants 4 GB free;"
    echo "        this host has ${free_gb} GB"
    return
  fi
  out=$(esbmc "${common[@]}" --unwind 55 "${d1[@]}" $h $pristine $stub 2>&1)
  check "D-1 overflows the day accumulator at :482" "DateTimeCommon.cpp line 482" \
    "$(violation "$out")"
  check "the bounded accumulators hold on $FIXED_VERSION" "VERIFICATION SUCCESSFUL" \
    "$(verdict esbmc "${common[@]}" --unwind 55 "${d1[@]}" $h "$fixed" $stub)"
}

case "${1:-all}" in
  esbmc) leg_esbmc ;;
  sanitizer) leg_sanitizer ;;
  tests) leg_tests ;;
  reachability) leg_reachability ;;
  fix) leg_fix ;;
  module) leg_module ;;
  all) leg_esbmc; leg_sanitizer; leg_tests; leg_reachability; leg_fix ;;
  *) echo "usage: $0 [all|esbmc|sanitizer|tests|reachability|fix|module]"; exit 2 ;;
esac

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
