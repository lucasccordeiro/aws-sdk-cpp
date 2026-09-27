#!/usr/bin/env bash
# Reproduces J-1, J-2 and J-3 from the proofs outwards: ESBMC states each defect
# as a property over symbolic input and refutes it, ESBMC's test-case generator
# names a concrete value in each region of the defect's condition, those values
# run as tests against the pristine SDK under ASan and UBSan, and a native
# witness table widens the same three findings. Then a fuzz run that finds nothing in the
# parser itself, the delta against upstream cJSON, reachability, and the fix.
# Run from this directory. Exits 0 only if every leg matches.
#
#   ./reproduce.sh            all seven legs
#   ./reproduce.sh esbmc      one leg: esbmc | ctest | sanitizer | fuzz |
#                             delta | reachability | fix
#
# Needs ESBMC 8.5.0 (with Z3 and Bitwuzla) for the proofs and the
# counterexamples, a C++11 compiler for everything they are replayed on, clang
# with libFuzzer for the fuzz leg, and curl for the reachability leg.

set -u

# Every path below is relative to this directory. Run from elsewhere and the
# reads fail one by one, ending in a "no network" skip that is not the problem.
cd "$(dirname "$0")" || exit 2
ROOT=$PWD

UPSTREAM_VERSION=$(cat vendor/UPSTREAM_VERSION)
UPSTREAM_COMMIT=$(cat vendor/UPSTREAM_COMMIT)
CJSON_VERSION=$(cat reference/UPSTREAM_CJSON_VERSION)
# A tag can be moved; the commit cannot. REPORT.md pins both, so the re-check
# has to use the one that actually holds.
RAW=https://raw.githubusercontent.com/aws/aws-sdk-cpp/$UPSTREAM_COMMIT
CORE=src/aws-cpp-sdk-core
# Pins the size of the evidence tree, so a vanished vendor/ fails loudly instead
# of passing a drift check it never ran.
VENDORED_FILES=25
# Highest index in the witness's case table; the fix leg sweeps 0..LAST_CASE
# through both accessors.
LAST_CASE=14
# Pins the content of the normalised fork-vs-upstream diff, not just its size.
DELTA_SHA=22dff753a93bc9b6
# Both harnesses below build a string of symbolic length, so the bound has to
# clear the longest one they can build; the SUCCESSFUL rows report every
# unwinding assertion as PASSED at these values, which is what makes them sound.
PRINT_UNWIND=45
# --array-flattener on the literal harness is not cosmetic: atoll's 256-entry
# digit map is indexed by a symbolic character, and Z3's array theory takes over
# two minutes on it. Flattened, the same row is seven seconds. Bitwuzla is fast
# either way and agrees with both encodings.
LITERAL_FLAGS="--unwind 10 --array-flattener"
# What a complete run makes. Asserted at the end, so a leg that returned early is
# a failure rather than a shorter run.
EXPECTED_CHECKS=107
CXX=${CXX:-g++}
INCLUDES="-Istubs -Ivendor/include"
STUBS="stubs/aws_memory_stub.cpp stubs/aws_logging_link_stub.cpp"
MODULES="vendor/source/utils/json/JsonSerializer.cpp vendor/source/utils/Document.cpp \
vendor/source/utils/StringUtils.cpp vendor/source/external/cjson/cJSON.cpp"
# float-cast-overflow is the check that sees J-2, and GCC leaves it out of
# -fsanitize=undefined; naming it explicitly costs nothing on clang, where it is
# already included.
SAN="-fsanitize=address,undefined,float-cast-overflow -fno-omit-frame-pointer"

pass=0 fail=0 skip=0
# The legs delete their own scratch trees on every exit path; this is what
# catches an interrupt in between.
SCRATCH=()
cleanup() { [[ ${#SCRATCH[@]} -gt 0 ]] && rm -rf "${SCRATCH[@]}"; }
trap cleanup EXIT INT TERM
# A leg that cannot run has not matched, so it must not leave the run exiting 0.
skip() { printf '  SKIP  %s\n' "$1"; skip=$((skip + 1)); }
check() { # check <name> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then printf '  PASS  %s\n' "$1"; pass=$((pass + 1))
  else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$1" "$2" "$3"; fail=$((fail + 1)); fi
}

# check() matches a substring, which is what the message rows want and what the
# numeric rows must not have: "0" is a substring of every status from 10 to 130.
eq() { # eq <name> <expected> <actual>
  if [[ "$3" == "$2" ]]; then printf '  PASS  %s\n' "$1"; pass=$((pass + 1))
  else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$1" "$2" "$3"; fail=$((fail + 1)); fi
}

# A build that fails has to be a failure, not a leg that quietly stops: bare
# `|| return` leaves the totals reading "N passed, 0 failed" and exits 0.
build() { # build <output> <source...> -- <flags...>
  local out=$1; shift
  $CXX -std=c++11 -g -O0 $INCLUDES "$@" -o "$out" && return 0
  printf '  FAIL  build %s\n' "$out"; fail=$((fail + 1)); return 1
}

# Counting diagnostics rather than matching an empty string: an empty
# expectation matches anything, and `grep -c` prints 0 for no input, so silence
# alone cannot tell "clean" from "never ran". Callers pass output from a run
# that also produced a checked answer.
san_count() { grep -cE 'runtime error|ERROR: AddressSanitizer' <<<"$1"; }

# The 26-digit case aborts by design, so the status has to be captured on its
# own rather than read off a pipeline.
status_of() { "$@" >/dev/null 2>&1; printf '%d' "$?"; }

# Match the verdict line itself rather than a tail window: the version banner
# arrives on the other stream, and a run that produces no verdict at all should
# say so instead of failing as a wrong one.
verdict() {
  local out; out=$("$@" 2>&1)
  grep -m1 -E '^VERIFICATION (SUCCESSFUL|FAILED)' <<<"$out" ||
    printf 'no verdict; last lines: %s' "$(tail -3 <<<"$out" | tr '\n' ' ')"
}

both_solvers() { # both_solvers <name> <expected> <source> [flags...]
  local name=$1 want=$2 src=$3; shift 3
  local s
  for s in --z3 --bitwuzla; do
    check "$name (${s#--})" "$want" "$(verdict esbmc "$src" --std c++11 "$s" "$@")"
  done
}

violated() { # violated <source> [flags...] -- the property name ESBMC reports
  local src=$1; shift
  esbmc "$src" --std c++11 --z3 "$@" 2>&1 | grep -m1 -A1 '^  FAILED' | tr '\n' ' '
}

# Builds a patched copy of the four modules in a scratch tree, setting $tree and
# $patched. Both the counterexample leg and the fix leg need one; keeping it in
# one place stops the two copies drifting.
patched_tree() {
  tree=$(mktemp -d); SCRATCH+=("$tree")
  local rel
  for rel in source/external/cjson/cJSON.cpp source/utils/json/JsonSerializer.cpp \
             source/utils/Document.cpp source/utils/StringUtils.cpp; do
    mkdir -p "$tree/$CORE/$(dirname "$rel")"
    cp "vendor/$rel" "$tree/$CORE/$rel"
  done
  ( cd "$tree" && patch -p1 --quiet < "$ROOT/fix/json-number-range-and-print.patch" ) && {
    patched="$tree/$CORE/source/utils/json/JsonSerializer.cpp \
$tree/$CORE/source/utils/Document.cpp $tree/$CORE/source/utils/StringUtils.cpp \
$tree/$CORE/source/external/cjson/cJSON.cpp"
    return 0; }
  printf '  FAIL  the patch does not apply to %s\n' "$UPSTREAM_VERSION"; fail=$((fail + 1)); return 1
}

# One run, both its output and its status. The replays exit 3 or 4 when the value
# never reached an accessor, so a leg that reads only "did it abort" would count
# a replay that did nothing as a replay that behaved.
run_replay() { # run_replay <binary> -- sets $replay_out and $replay_status
  replay_out=$("$1" 2>&1); replay_status=$?
}

# Whether one named claim was discharged. ESBMC's default mode stops at the first
# violation and reports the rest NOT CHECKED, so a claim that guards a harness's
# own arithmetic is invisible there; --multi-property reaches it.
claim_status() { # claim_status <source> <claim text> [flags...]
  local src=$1 claim=$2; shift 2
  esbmc "$src" --std c++11 --multi-property "$@" 2>&1 |
    grep -m1 -E "^  [A-Z ]+ +\[.*\] +line +[0-9]+ +$claim" |
    grep -m1 -oE 'PASSED|FAILED|NOT CHECKED' || echo 'claim absent'
}

# A SUCCESSFUL verdict means nothing if the bound truncated a loop before the
# violating iteration. Reports the verdict, how many of the run's unwinding
# assertions were left undischarged, and how many there were -- the last so that
# suppressing them (--no-unwinding-assertions, which empirically turns truncated
# loops into false SUCCESSFULs) cannot read as a clean row.
fully_unwound() { # fully_unwound <source> [flags...]
  local src=$1; shift
  local out; out=$(esbmc "$src" --std c++11 --multi-property "$@" 2>&1)
  local unwinding; unwinding=$(grep -E '^  [A-Z ]+ +\[.*unwinding assertion' <<<"$out")
  printf '%s, %d unproven of %d' \
    "$(grep -m1 -oE 'VERIFICATION (SUCCESSFUL|FAILED)' <<<"$out" || echo 'no verdict')" \
    "$(grep -cv '^  PASSED' <<<"$unwinding")" \
    "$(grep -c '' <<<"$unwinding")"
}

leg_esbmc() {
  echo "[1/7] ESBMC -- the three defects, stated as properties over symbolic input"
  command -v esbmc >/dev/null || { skip "esbmc not on PATH"; return; }
  mkdir -p results

  # J-1. The literal's length is the free variable; nothing in the harness names
  # 26, and the counterexample is a length the solver chose.
  both_solvers "J-1: a wire literal can make the printer return null" "VERIFICATION FAILED" \
    harnesses/json_print_esbmc.cpp --unwind $PRINT_UNWIND
  check "and it is the pointer Aws::String receives" \
    "the pointer handed to Aws::String is not null" \
    "$(violated harnesses/json_print_esbmc.cpp --unwind $PRINT_UNWIND)"
  # The passing side of the same boundary. Without this row a printer that
  # rejected every literal would satisfy the one above just as well.
  both_solvers "J-1: and 25 characters or fewer always print" "VERIFICATION SUCCESSFUL" \
    harnesses/json_print_esbmc.cpp --unwind $PRINT_UNWIND -D BOUNDED

  # J-2. The double is symbolic and constrained only to be non-NaN, which is all
  # JSON's grammar can spell.
  both_solvers "J-2: a wire double can violate [conv.fpint]" "VERIFICATION FAILED" \
    harnesses/json_number_esbmc.cpp
  check "and it is the representability property that breaks" \
    "the double is representable as long long" "$(violated harnesses/json_number_esbmc.cpp)"

  # J-3. Mantissa and exponent are both symbolic, and atoll comes from ESBMC's
  # own C library model rather than from this harness.
  both_solvers "J-3: a kept literal can read back as a different number" "VERIFICATION FAILED" \
    harnesses/json_literal_esbmc.cpp $LITERAL_FLAGS
  check "and it is the denoted value that is lost" \
    "the accessor returns the value the kept literal denotes" \
    "$(violated harnesses/json_literal_esbmc.cpp $LITERAL_FLAGS)"

  # Why the J-2 harness states its property instead of leaving it to the tool: an
  # out-of-range conversion is not one of ESBMC's built-in checks. Written out
  # rather than described, so the day it starts failing is the day ESBMC gains
  # the check and this note needs deleting.
  cat > results/bare_conversion.c <<'EOF'
int main(void)
{
    double d = 1e300;
    long long x = (long long)d; /* undefined: [conv.fpint]/1 */
    (void)x;
    return 0;
}
EOF
  check "ESBMC's own checks do not see the conversion" "VERIFICATION SUCCESSFUL" \
    "$(verdict esbmc results/bare_conversion.c --overflow-check --nan-check --z3)"

  # Every SUCCESSFUL row above and in the fix leg rests on the bound being large
  # enough: a loop truncated before the violating iteration is reported NOT
  # CHECKED and the run still exits SUCCESSFUL. These assert the verdict and the
  # absence of an undischarged unwinding assertion together, so neither can be
  # read without the other.
  # The J-3 harness indexes a table of powers of ten, and checks each entry it
  # selects against its predecessor. That claim is only reached under
  # --multi-property: in ESBMC's default mode it is reported NOT CHECKED behind
  # the violation, and a corrupted entry would be invisible. Corrupting one turns
  # this row red, which is what makes the harness's arithmetic answerable.
  check "J-3's table of powers of ten checks out against its own recurrence" "PASSED" \
    "$(claim_status harnesses/json_literal_esbmc.cpp 'the power of ten is the one it says' \
        --bitwuzla $LITERAL_FLAGS)"

  eq "J-1's bound leaves its one loop proven" "VERIFICATION SUCCESSFUL, 0 unproven of 1" \
    "$(fully_unwound harnesses/json_print_esbmc.cpp --bitwuzla --unwind $PRINT_UNWIND -D BOUNDED)"
  eq "and J-3's leaves both of its own"       "VERIFICATION SUCCESSFUL, 0 unproven of 2" \
    "$(fully_unwound harnesses/json_literal_esbmc.cpp --bitwuzla $LITERAL_FLAGS -D FIXED)"
}

# ESBMC's counterexamples, made executable and run against the SDK. The leg
# above says a violating input exists; this one produces specific inputs and
# shows the pristine accessors mishandling each of them, under ASan and UBSan.
#
# The generated CMakeLists.txt would rebuild the harness with those values, which
# only re-runs the model. Each replay driver links the generated
# __VERIFIER_nondet_* against the real JsonSerializer.cpp and Document.cpp
# instead, so the witness is executed on the SDK.
leg_ctest() {
  echo "[2/7] Counterexamples -- ESBMC's witnesses, executed against the real accessors"
  command -v esbmc >/dev/null || { skip "esbmc not on PATH"; return; }
  mkdir -p results
  local tree patched
  patched_tree || return

  local gen cases n tc

  # ---- J-1: the length of the literal ------------------------------------
  # Each generator run starts from an empty directory: it refuses to overwrite
  # files it did not write, so a stale one would silently keep old witnesses.
  rm -rf results/esbmc-ctest-print
  gen=$(esbmc harnesses/json_print_ctest.cpp --std c++11 --z3 \
    --branch-coverage --generate-ctest-testcase \
    --ctest-output-dir results/esbmc-ctest-print 2>&1)
  check "J-1: both sides of the printer's guard are reached" "Branch Coverage: 100%" "$gen"
  cases=$(find results/esbmc-ctest-print -name 'test_case_*.cpp' | sort)
  eq "and each yields an executable test case" "2 cases" \
    "$(find results/esbmc-ctest-print -name 'test_case_*.cpp' | wc -l) cases"

  # Which witness lands in which region is the solver's choice, so the leg counts
  # outcomes rather than assuming an order. Both arms are counted from the exit
  # status, so a replay that bailed out before reaching an accessor (status 3 or
  # 4) lands in neither and shows up as a missing outcome rather than a pass.
  local aborted=0 printed=0 from_null=0 fixed_printed=0 fixed_round_trips=0
  local replay_out replay_status
  n=0
  for tc in $cases; do
    n=$((n + 1))
    build "results/replay_print_$n" harnesses/json_print_replay.cpp "$tc" $MODULES $STUBS $SAN || return
    run_replay ./results/replay_print_$n
    [[ "$replay_out" == *"construction from null"* ]] && from_null=$((from_null + 1))
    case $replay_status in
      134) aborted=$((aborted + 1)) ;;
      0)   printed=$((printed + 1)) ;;
    esac

    build "results/replay_print_fixed_$n" harnesses/json_print_replay.cpp "$tc" $patched $STUBS $SAN || return
    run_replay ./results/replay_print_fixed_$n
    [[ $replay_status -eq 0 ]] && fixed_printed=$((fixed_printed + 1))
    [[ "$replay_out" == *'round-trip: {"n":9'* ]] && fixed_round_trips=$((fixed_round_trips + 1))
  done
  eq "the over-length witness aborts the pristine SDK" "1 aborted"  "$aborted aborted"
  eq "on the null the printer returned"                "1 from null" "$from_null from null"
  eq "and the witness inside the guard round-trips"    "1 printed"   "$printed printed"
  # Presence of an answer, not absence of a crash: both witnesses must reach the
  # accessors and print the document back.
  eq "under the patch both witnesses print"            "2 printed"   "$fixed_printed printed"
  eq "and both documents come back with their number"  "2 round-trips" "$fixed_round_trips round-trips"

  # ---- J-2: the value of the double --------------------------------------
  rm -rf results/esbmc-ctest
  gen=$(esbmc harnesses/json_number_ctest.cpp --std c++11 --z3 \
    --branch-coverage --generate-ctest-testcase \
    --ctest-output-dir results/esbmc-ctest 2>&1)
  check "J-2: every region of the conversion is reached" "Branch Coverage: 100%" "$gen"
  cases=$(find results/esbmc-ctest -name 'test_case_*.cpp' | sort)
  eq "and each one yields an executable test case" "3 cases" \
    "$(find results/esbmc-ctest -name 'test_case_*.cpp' | wc -l) cases"

  local undefined=0 defined=0 fixed_diagnostics=0 fixed_read=0 infidelity=0 read=0
  n=0
  for tc in $cases; do
    n=$((n + 1))
    build "results/replay_$n" harnesses/json_number_replay.cpp "$tc" $MODULES $STUBS $SAN || return
    run_replay ./results/replay_$n
    [[ $replay_status -ne 0 ]] && infidelity=$((infidelity + 1))
    # "defined" is the no-diagnostic bucket, which a binary that printed nothing
    # also lands in, so the answer is counted beside it rather than inferred from
    # the driver's source.
    [[ "$replay_out" == *"AsInt64="* ]] && read=$((read + 1))
    if [[ $(san_count "$replay_out") -gt 0 ]]; then undefined=$((undefined + 1))
    else defined=$((defined + 1)); fi

    build "results/replay_fixed_$n" harnesses/json_number_replay.cpp "$tc" $patched $STUBS $SAN || return
    run_replay ./results/replay_fixed_$n
    fixed_diagnostics=$((fixed_diagnostics + $(san_count "$replay_out")))
    [[ $replay_status -eq 0 && "$replay_out" == *"AsInt64="* ]] && fixed_read=$((fixed_read + 1))
  done
  # Every generated double must render to JSON and parse back bit-identical, or
  # the replay is not running the counterexample it claims to. Rendering with
  # %.6g instead of %.17g makes this row fire.
  eq "each witness survives rendering to a response body" "0 lost" "$infidelity lost"
  eq "all three reach the accessors and read a value" "3 read" "$read read"
  eq "the two out-of-range witnesses are undefined on the pristine accessors" \
    "2 undefined" "$undefined undefined"
  eq "and the representable one is not"  "1 defined"   "$defined defined"
  # The diagnostic count alone would pass on three binaries that never ran, so
  # the answer is asserted beside it.
  eq "the patch closes all three"        "0 diagnostics" "$fixed_diagnostics diagnostics"
  eq "and all three still read a value"  "3 read"        "$fixed_read read"

  # ---- J-3: the mantissa and the exponent --------------------------------
  rm -rf results/esbmc-ctest-literal
  gen=$(esbmc harnesses/json_literal_ctest.cpp --std c++11 --z3 \
    --branch-coverage --generate-ctest-testcase \
    --ctest-output-dir results/esbmc-ctest-literal 2>&1)
  check "J-3: every region of the parser's condition is reached" "Branch Coverage: 100%" "$gen"
  cases=$(find results/esbmc-ctest-literal -name 'test_case_*.cpp' | sort)
  eq "and each one yields an executable test case" "3 cases" \
    "$(find results/esbmc-ctest-literal -name 'test_case_*.cpp' | wc -l) cases"

  local wrong=0 exact=0 fixed_exact=0
  n=0
  for tc in $cases; do
    n=$((n + 1))
    build "results/replay_literal_$n" harnesses/json_literal_replay.cpp "$tc" $MODULES $STUBS $SAN || return
    run_replay ./results/replay_literal_$n
    case $replay_status in
      5) wrong=$((wrong + 1)) ;;
      0) exact=$((exact + 1)) ;;
    esac

    build "results/replay_literal_fixed_$n" harnesses/json_literal_replay.cpp "$tc" $patched $STUBS $SAN || return
    run_replay ./results/replay_literal_fixed_$n
    [[ $replay_status -eq 0 ]] && fixed_exact=$((fixed_exact + 1))
  done
  eq "the kept-literal witness reads back as the wrong number" "1 wrong" "$wrong wrong"
  eq "and the two the parser keeps no literal for are exact"   "2 exact" "$exact exact"
  eq "the patch answers all three exactly"                     "3 exact" "$fixed_exact exact"
}

leg_sanitizer() {
  echo "[3/7] Sanitizers -- the same three defects, over fifteen response bodies"
  mkdir -p results
  build results/witness harnesses/json_number_witness.cpp $MODULES $STUBS $SAN || return

  local control; control=$(./results/witness 0 2>&1)
  check "an in-range number reads back exactly"        "AsInt64=42 "                 "$control"
  check "with both sanitizers silent"                  "diagnostics=0"               "diagnostics=$(san_count "$control")"
  local max; max=$(./results/witness 1 2>&1)
  check "so does the largest int64"                    "AsInt64=9223372036854775807" "$max"
  check "and that stays clean too"                     "diagnostics=0"               "diagnostics=$(san_count "$max")"

  # J-3: the literal is kept by parse_number, and atoll stops at the exponent.
  local exp; exp=$(./results/witness 2 2>&1)
  check "J-3: 1e300 reads back as 1"                   "AsInt64=1 "                  "$exp"
  check "with nothing to warn about -- it is a wrong answer, not UB" "diagnostics=0" "diagnostics=$(san_count "$exp")"

  # The same defect on a value int64 can hold exactly, which is the form that
  # makes it a corruption rather than a precision complaint.
  local inrange; inrange=$(./results/witness 6 2>&1)
  check "J-3: 5e9 reads back as 5"                     "AsInt64=5 "                  "$inrange"
  check "and GetInt64 agrees, which is what generated code calls" "GetInt64=5 "      "$inrange"
  check "while the document still prints it in full"   'round-trip: {"n":5e9}'       "$inrange"

  # J-2: the same number written with a decimal point takes the double path.
  local dot; dot=$(./results/witness 3 2>&1)
  check "J-2: AsInt64 converts out of range"           "JsonSerializer.cpp:515"      "$dot"
  # The site the reachability argument rests on: GetInt64(key) is what a
  # generated deserializer calls, so it must be asserted, not inferred from :515.
  check "J-2: and GetInt64, which generated code calls" "JsonSerializer.cpp:502"     "$dot"
  check "J-2: so does IsIntegerType"                   "JsonSerializer.cpp:641"      "$dot"
  check "J-2: and IsFloatingPointType"                 "JsonSerializer.cpp:656"      "$dot"
  check "and the diagnosis names the standard's words" "outside the range of representable values" "$dot"
  local inf; inf=$(./results/witness 4 2>&1)
  check "J-2: an overflowing exponent gets there as inf" "inf is outside the range"  "$inf"

  # J-1: printing a document whose literal does not fit the 26-byte buffer.
  local big; big=$(./results/witness 5 2>&1)
  check "J-1: the value is read before the write fails" "AsInt64=9223372036854775807" "$big"
  check "J-1: and the write builds a string from null" "construction from null"      "$big"
  eq    "J-1: which aborts the process"                "134"                          "$(status_of ./results/witness 5)"

  # J-1's boundary from the passing side. One character shorter, and the same
  # body prints: without this the suite pins only that 26 fails, not that 25
  # works, and a printer that rejected every literal would still pass.
  local ok25; ok25=$(./results/witness 7 2>&1)
  check "J-1: 25 characters print normally" \
    'round-trip: {"n":9999999999999999999999999}' "$ok25"
  eq    "and that case does not abort"                 "0"   "$(status_of ./results/witness 7)"

  # J-2's boundary. 2^63 is the smallest double outside the range, so this is
  # where a guard written `d <= (double)INT64_MAX` would still be undefined.
  local b63; b63=$(./results/witness 8 2>&1)
  check "J-2 starts at exactly 2^63, not only at huge values" \
    "9.22337e+18 is outside the range" "$b63"
  check "and a positive wire value reads back negative"  "AsInt64=-9223372036854775808" "$b63"
  # The other side of the same boundary: -2^63 is representable, so it must be
  # clean. A fix that saturated here would be over-correcting.
  local bmin; bmin=$(./results/witness 9 2>&1)
  check "while -2^63 is representable and exact"       "AsInt64=-9223372036854775808" "$bmin"
  check "with no diagnostic"                           "diagnostics=0" "diagnostics=$(san_count "$bmin")"

  # Document carries its own copy of all six sites.
  local doc; doc=$(./results/witness document 3 2>&1)
  check "J-2 again in Document::IsIntegerType"         "Document.cpp:492"            "$doc"
  check "J-2 again in Document::GetInt64"              "Document.cpp:506"            "$doc"
  check "J-2 again in Document::AsInt64"               "Document.cpp:519"            "$doc"
  check "and in Document::IsFloatingPointType"         "Document.cpp:549"            "$doc"
  eq    "J-1 again in Document::WriteCompact"          "134"                          "$(status_of ./results/witness document 5)"
}

leg_fuzz() {
  echo "[4/7] Fuzzing -- the parser itself, which is not where the defects are"
  command -v clang++ >/dev/null || { skip "clang++ not on PATH (libFuzzer)"; return; }
  rm -rf results/corpus && mkdir -p results/corpus
  printf '{"Item":{"id":{"S":"abc"},"n":{"N":"1750000000000"}}}' > results/corpus/ddb.json
  printf '{"__type":"ValidationException","message":"bad \\u00e9 input"}' > results/corpus/err.json
  printf '{"ContentLength":3221225472,"big":123456789012345678901234567890}' > results/corpus/big.json
  printf '{"a":-0.0e-0,"b":[true,false,null],"c":{"d":""}}' > results/corpus/misc.json

  clang++ -std=c++11 -g -O1 -fsanitize=fuzzer,address,undefined,float-cast-overflow \
    $INCLUDES -o results/parse_fuzz harnesses/cjson_parse_fuzz.cpp \
    vendor/source/external/cjson/cJSON.cpp 2>/dev/null ||
    { printf '  FAIL  build results/parse_fuzz\n'; fail=$((fail + 1)); return; }

  # Bounded by runs rather than time so the leg is reproducible; REPORT.md
  # records the longer campaign.
  local out; out=$(./results/parse_fuzz -runs=60000 -max_len=4096 \
    -artifact_prefix=results/ results/corpus 2>&1)
  check "parse, print and re-parse survive 60k mutations" "Done 60000 runs" "$out"
  check "with no crash to report"                         "artifacts=0" \
    "artifacts=$(find results -maxdepth 1 \( -name 'crash-*' -o -name 'oom-*' \) | wc -l)"
}

leg_delta() {
  echo "[5/7] Delta -- what the fork adds to upstream cJSON $CJSON_VERSION"
  local fork=vendor/source/external/cjson/cJSON.cpp
  local ref=reference/cJSON.c

  # The feature the defects grow from, and its absence upstream.
  check "the fork keeps a big integer's literal" "item->valuestring = (char*)cJSON_AS4CPP_strdup(number_c_string" \
    "$(grep -m1 'strdup(number_c_string' "$fork")"
  # Asserting the extracted range as well as the hit count: grep -c prints 0 on
  # empty input, so a sed range that selects nothing would otherwise read as
  # "upstream has no literal" and pass.
  local upstream_parse; upstream_parse=$(sed -n '/static cJSON_bool parse_number/,/^}/p' "$ref")
  eq "upstream keeps no literal at all" "102 lines, 0 hits" \
    "$(grep -c '' <<<"$upstream_parse") lines, $(grep -c 'valuestring' <<<"$upstream_parse") hits"
  check "and the fork prints through it"         "if (item->valuestring)" \
    "$(sed -n '/static cJSON_AS4CPP_bool print_number/,/^}/p' "$fork" | grep -m1 'item->valuestring')"

  # The buffer that cannot hold what parse_number is now allowed to keep. Both
  # sides, so a fork that grew the buffer would show up here rather than pass.
  check "the print buffer is 26 bytes in the fork"  "number_buffer[26]" \
    "$(grep -m1 'number_buffer\[' "$fork")"
  check "as it is upstream, where nothing long reaches it" "number_buffer[26]" \
    "$(grep -m1 'number_buffer\[' "$ref")"

  # Everything else the fork changes is hardening or thread safety. Renaming the
  # prefixes makes the two files comparable; the count is asserted so that a
  # future drift has to be looked at rather than absorbed.
  local delta; delta=$(sed -e 's/cJSON_AS4CPP_/cJSON_/g' -e 's/CJSON_AS4CPP_/CJSON_/g' "$fork" |
    diff -u "$ref" - | grep -c '^[-+][^-+]')
  eq "the whole delta is 101 changed lines" "101" "$delta"
  # The count alone would not notice a bounded write swapped for an unbounded one
  # in the same number of lines, and "no memory-safety drift" is the claim resting
  # on this leg. Pinning the content means any drift has to be re-read by hand.
  eq "and it is the delta that was read line by line" "$DELTA_SHA" \
    "$(sed -e 's/cJSON_AS4CPP_/cJSON_/g' -e 's/CJSON_AS4CPP_/CJSON_/g' "$fork" |
       diff -u "$ref" - | grep '^[-+][^-+]' | sha256sum | cut -c1-16)"
}

leg_reachability() {
  echo "[6/7] Reachability -- the vendored bytes, and who reads these numbers"
  local tmp; tmp=$(mktemp -d); SCRATCH+=("$tmp")
  curl -fsS "$RAW/$CORE/source/client/AWSErrorMarshaller.cpp" -o "$tmp/Marshaller.cpp" 2>/dev/null \
    || { skip "no network"; rm -rf "$tmp"; return; }
  curl -fsS "$RAW/generated/src/aws-cpp-sdk-lambda/source/model/FunctionConfiguration.cpp" \
    -o "$tmp/Generated.cpp"

  # The whole vendored tree, not just the four modules: REPORT.md cites headers
  # by line too. Names what drifted, since "differs" alone would not say where.
  local drift="" vendored=0
  while read -r rel; do
    vendored=$((vendored + 1))
    curl -fsS "$RAW/$CORE/$rel" -o "$tmp/upstream" 2>/dev/null &&
      diff -q "$tmp/upstream" "vendor/$rel" >/dev/null || drift="$drift $rel"
  done < <(cd vendor && find include source -type f | sort)
  # The count is asserted, not just printed: an empty vendor tree would leave
  # `drift` empty too and otherwise read as a clean pass.
  eq "all $VENDORED_FILES vendored files are upstream $UPSTREAM_VERSION" \
    "$VENDORED_FILES files, no drift" "$vendored files,${drift:- no drift}"

  # stubs/ precedes vendor/include on the include path, so a stub named after a
  # pinned header would silently replace the evidence.
  check "no stub shadows a vendored header" "none" \
    "$(comm -12 <(cd stubs && find . -name '*.h' | sed 's|^\./||' | sort) \
                <(cd vendor/include && find . -name '*.h' | sed 's|^\./||' | sort) |
       tr '\n' ' ' | grep . || echo none)"

  # J-1's in-SDK path: an error body off the wire, printed back out.
  check "the error marshaller parses the response body" "JsonValue(rawPayloadStr)" \
    "$(grep -m1 'return JsonValue(rawPayloadStr)' "$tmp/Marshaller.cpp")"
  check "and prints it back through WriteReadable"      "payloadView.WriteReadable()" \
    "$(grep -m1 'Error response is' "$tmp/Marshaller.cpp")"
  # AWS_LOGSTREAM_TRACE expands to AWS_LOGSTREAM, not AWS_LOG, and each defines
  # its own guard. `grep -m1` finds AWS_LOG's, which would stay green if the
  # guard were dropped from the macro J-1 actually goes through.
  check "behind a level guard, so trace has to be on"   "logSystem->GetLogLevel() >= level" \
    "$(sed -n '/define AWS_LOGSTREAM(/,/^$/p' vendor/include/aws/core/utils/logging/LogMacros.h |
       grep -m1 'GetLogLevel() >= level')"

  # J-2 and J-3 need no logging: this is what a generated deserializer does with
  # every int64 field a service returns.
  check "generated code reads int64 fields with GetInt64" "jsonValue.GetInt64(" \
    "$(grep -m1 'GetInt64(' "$tmp/Generated.cpp")"
  rm -rf "$tmp"
}

leg_fix() {
  echo "[7/7] Fix -- the same bodies, patched"
  mkdir -p results
  local tree patched rel
  patched_tree || return
  eq "the patch changes all four modules" "4 changed" \
    "$(local n=0; for rel in source/external/cjson/cJSON.cpp source/utils/json/JsonSerializer.cpp \
         source/utils/Document.cpp source/utils/StringUtils.cpp; do
         cmp -s "vendor/$rel" "$tree/$CORE/$rel" || n=$((n + 1)); done; printf '%d changed' "$n")"

  build results/witness_fixed harnesses/json_number_witness.cpp $patched $STUBS $SAN || return

  # Every case, through both accessors: REPORT.md claims the patched tree is
  # clean, and the Document half of that claim was previously unmeasured.
  # Both counters, because either alone is satisfied by a binary that ran and
  # produced nothing: san_count is 0 for silence as well as for cleanliness, and
  # a nonzero status is 0 for a program that never printed an answer.
  local i out all_clean=0 all_status=0 answered=0
  for i in $(seq 0 "$LAST_CASE"); do
    for out in "$(./results/witness_fixed $i 2>&1)" "$(./results/witness_fixed document $i 2>&1)"; do
      all_clean=$((all_clean + $(san_count "$out")))
      [[ "$out" == *"AsInt64="* ]] && answered=$((answered + 1))
    done
    [[ "$(status_of ./results/witness_fixed $i)" == 0 ]] || all_status=$((all_status + 1))
    [[ "$(status_of ./results/witness_fixed document $i)" == 0 ]] || all_status=$((all_status + 1))
  done
  eq    "every patched case reads a value back"        "30 answered"   "$answered answered"
  check "no case leaves a sanitizer diagnostic behind" "diagnostics=0" "diagnostics=$all_clean"
  eq    "and none of the thirty runs aborts"           "0 nonzero"     "$all_status nonzero"

  check "an overflowing exponent saturates instead of converting" \
    "AsInt64=9223372036854775807" "$(./results/witness_fixed 4 2>&1)"
  check "and 5e9 reads back as five billion" "AsInt64=5000000000" \
    "$(./results/witness_fixed 6 2>&1)"
  local control; control=$(./results/witness_fixed 0 2>&1)
  check "in-range values are untouched"     "AsInt64=42 "                 "$control"
  check "so is the largest int64"           "AsInt64=9223372036854775807" "$(./results/witness_fixed 1 2>&1)"
  check "1e300 saturates instead of reading as 1" "AsInt64=9223372036854775807" "$(./results/witness_fixed 2 2>&1)"
  check "1.5e300 saturates too"             "AsInt64=9223372036854775807" "$(./results/witness_fixed 3 2>&1)"
  local big; big=$(./results/witness_fixed 5 2>&1)
  check "and the 26-digit literal survives the round trip" \
    'round-trip: {"n":99999999999999999999999999}' "$big"
  local doc; doc=$(./results/witness_fixed document 5 2>&1)
  check "Document round-trips it as well" \
    'round-trip: {"n":99999999999999999999999999}' "$doc"

  # The boundary, both sides. 2^63 must saturate and -2^63 must not: a guard
  # written `d <= (double)INT64_MAX` passes the second and fails the first,
  # which is the mistake these two rows exist to catch.
  check "2^63 saturates rather than converting"        "AsInt64=9223372036854775807" \
    "$(./results/witness_fixed 8 2>&1)"
  check "and -2^63 stays exact"                        "AsInt64=-9223372036854775808" \
    "$(./results/witness_fixed 9 2>&1)"
  check "the first double below the range saturates low" "AsInt64=-9223372036854775808" \
    "$(./results/witness_fixed 10 2>&1)"
  check "-inf saturates low too"                       "AsInt64=-9223372036854775808" \
    "$(./results/witness_fixed 11 2>&1)"
  check "-0.0 reads back as zero"                      "AsInt64=0 " \
    "$(./results/witness_fixed 12 2>&1)"
  check "the minimum as a literal is exact"            "AsInt64=-9223372036854775808" \
    "$(./results/witness_fixed 13 2>&1)"
  check "and one past the maximum saturates"           "AsInt64=9223372036854775807" \
    "$(./results/witness_fixed 14 2>&1)"

  command -v esbmc >/dev/null || { skip "esbmc not on PATH"; return; }
  # The same three properties the first leg refuted, re-run against the patch.
  both_solvers "J-1: the patched printer has no length to fail on" "VERIFICATION SUCCESSFUL" \
    harnesses/json_print_esbmc.cpp --unwind $PRINT_UNWIND -D FIXED
  both_solvers "J-2: the guarded conversion holds for every double" "VERIFICATION SUCCESSFUL" \
    harnesses/json_number_esbmc.cpp -D FIXED
  both_solvers "J-3: the patched reader answers what the literal denotes" "VERIFICATION SUCCESSFUL" \
    harnesses/json_literal_esbmc.cpp $LITERAL_FLAGS -D FIXED
  # Not "the shipped helper is proved": nothing feeds fix/ to ESBMC. This pins
  # the model against a transcription of the patch's helper. The shipped copy is
  # covered by the native rows above, which do fail when it is mutated.
  both_solvers "the model and a transcription of the helper agree" "VERIFICATION SUCCESSFUL" \
    harnesses/json_number_esbmc.cpp -D FIXED -D EQUIVALENCE
}

case "${1:-all}" in
  esbmc)        leg_esbmc ;;
  ctest)        leg_ctest ;;
  sanitizer)    leg_sanitizer ;;
  fuzz)         leg_fuzz ;;
  delta)        leg_delta ;;
  reachability) leg_reachability ;;
  fix)          leg_fix ;;
  all)          leg_esbmc; leg_ctest; leg_sanitizer; leg_fuzz; leg_delta
                leg_reachability; leg_fix ;;
  *)            echo "usage: $0 [all|esbmc|ctest|sanitizer|fuzz|delta|reachability|fix]"; exit 2 ;;
esac

# Both READMEs quote a check count, so the run has to notice when it made fewer
# checks than it should have -- a leg that returns early otherwise reads as a
# smaller suite rather than a truncated one.
if [[ "${1:-all}" == all ]]; then
  # +1 for this row, which has not been counted yet, so the number pinned here is
  # the total the run goes on to print.
  eq "every check in the suite ran" "$EXPECTED_CHECKS checks" "$((pass + fail + 1)) checks"
fi

printf '\n%d passed, %d failed' "$pass" "$fail"
[[ $skip -eq 0 ]] && printf '\n' || printf ', %d skipped -- the run proves less than it reads\n' "$skip"
[[ $fail -eq 0 && $skip -eq 0 ]]
