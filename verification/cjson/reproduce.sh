#!/usr/bin/env bash
# Reproduces J-1, J-2 and J-3 end to end: native witnesses over the pristine
# sources, an ESBMC proof of the conversion precondition, a fuzz run that finds
# nothing in the parser itself, the delta against upstream cJSON, reachability,
# and the proposed fix. Run from this directory. Exits 0 only if every leg
# matches.
#
#   ./reproduce.sh            all six legs
#   ./reproduce.sh esbmc      one leg: sanitizer | esbmc | fuzz | delta |
#                             reachability | fix
#
# Needs a C++11 compiler, clang with libFuzzer for the fuzz leg, ESBMC 8.5.0
# (with Z3 and Bitwuzla) for the proofs, and curl for the reachability leg.

set -u

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
# Pins the content of the normalised fork-vs-upstream diff, not just its size.
DELTA_SHA=22dff753a93bc9b6
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

leg_sanitizer() {
  echo "[1/6] Sanitizers -- the pristine accessors on six response bodies"
  mkdir -p results
  build results/witness harnesses/json_number_witness.cpp $MODULES $STUBS $SAN || return

  local control; control=$(./results/witness 0 2>&1)
  check "an in-range number reads back exactly"        "AsInt64=42"                  "$control"
  check "with both sanitizers silent"                  "diagnostics=0"               "diagnostics=$(san_count "$control")"
  local max; max=$(./results/witness 1 2>&1)
  check "so does the largest int64"                    "AsInt64=9223372036854775807" "$max"
  check "and that stays clean too"                     "diagnostics=0"               "diagnostics=$(san_count "$max")"

  # J-3: the literal is kept by parse_number, and atoll stops at the exponent.
  local exp; exp=$(./results/witness 2 2>&1)
  check "J-3: 1e300 reads back as 1"                   "AsInt64=1"                   "$exp"
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

  # Document carries its own copy of all six sites.
  local doc; doc=$(./results/witness document 3 2>&1)
  check "J-2 again in Document::IsIntegerType"         "Document.cpp:492"            "$doc"
  check "J-2 again in Document::AsInt64"               "Document.cpp:519"            "$doc"
  check "and in Document::IsFloatingPointType"         "Document.cpp:549"            "$doc"
  eq    "J-1 again in Document::WriteCompact"          "134"                          "$(status_of ./results/witness document 5)"
}

leg_esbmc() {
  echo "[2/6] ESBMC -- the conversion precondition over every double"
  command -v esbmc >/dev/null || { skip "esbmc not on PATH"; return; }
  mkdir -p results

  both_solvers "a wire double can violate [conv.fpint]" "VERIFICATION FAILED" \
    harnesses/json_number_esbmc.cpp
  check "and it is the representability property that breaks" \
    "the double is representable as long long" "$(violated harnesses/json_number_esbmc.cpp)"

  # Why the harness states the property instead of leaving it to the tool: an
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
}

leg_fuzz() {
  echo "[3/6] Fuzzing -- the parser itself, which is not where the defects are"
  command -v clang++ >/dev/null || { skip "clang++ not on PATH (libFuzzer)"; return; }
  mkdir -p results/corpus
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
    "artifacts=$(find results -maxdepth 1 -name 'crash-*' -o -maxdepth 1 -name 'oom-*' | wc -l)"
}

leg_delta() {
  echo "[4/6] Delta -- what the fork adds to upstream cJSON $CJSON_VERSION"
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
    "$(wc -l <<<"$upstream_parse") lines, $(grep -c 'valuestring' <<<"$upstream_parse") hits"
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
  echo "[5/6] Reachability -- the vendored bytes, and who reads these numbers"
  local tmp; tmp=$(mktemp -d)
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
  check "all $VENDORED_FILES vendored files are upstream $UPSTREAM_VERSION" \
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
  check "behind a level guard, so trace has to be on"   "logSystem->GetLogLevel() >= level" \
    "$(grep -m1 'GetLogLevel() >= level' vendor/include/aws/core/utils/logging/LogMacros.h)"

  # J-2 and J-3 need no logging: this is what a generated deserializer does with
  # every int64 field a service returns.
  check "generated code reads int64 fields with GetInt64" "jsonValue.GetInt64(" \
    "$(grep -m1 'GetInt64(' "$tmp/Generated.cpp")"
  rm -rf "$tmp"
}

leg_fix() {
  echo "[6/6] Fix -- the same six bodies, patched"
  mkdir -p results
  local tree; tree=$(mktemp -d)
  local rel
  for rel in source/external/cjson/cJSON.cpp source/utils/json/JsonSerializer.cpp \
             source/utils/Document.cpp source/utils/StringUtils.cpp; do
    mkdir -p "$tree/$CORE/$(dirname "$rel")"
    cp "vendor/$rel" "$tree/$CORE/$rel"
  done
  ( cd "$tree" && patch -p1 --quiet < "$OLDPWD/fix/json-number-range-and-print.patch" ) || {
    printf '  FAIL  the patch does not apply to %s\n' "$UPSTREAM_VERSION"; fail=$((fail + 1))
    rm -rf "$tree"; return; }
  eq "the patch changes all four modules" "4 changed" \
    "$(local n=0; for rel in source/external/cjson/cJSON.cpp source/utils/json/JsonSerializer.cpp \
         source/utils/Document.cpp source/utils/StringUtils.cpp; do
         cmp -s "vendor/$rel" "$tree/$CORE/$rel" || n=$((n + 1)); done; printf '%d changed' "$n")"

  build results/witness_fixed harnesses/json_number_witness.cpp \
    "$tree/$CORE/source/utils/json/JsonSerializer.cpp" \
    "$tree/$CORE/source/utils/Document.cpp" \
    "$tree/$CORE/source/utils/StringUtils.cpp" \
    "$tree/$CORE/source/external/cjson/cJSON.cpp" $STUBS $SAN || { rm -rf "$tree"; return; }

  local i out all_clean=0
  for i in 0 1 2 3 4 5 6; do
    out=$(./results/witness_fixed $i 2>&1)
    all_clean=$((all_clean + $(san_count "$out")))
  done
  check "no case leaves a sanitizer diagnostic behind" "diagnostics=0" "diagnostics=$all_clean"
  eq    "and none of them aborts"                      "0"             "$(status_of ./results/witness_fixed 5)"

  check "an overflowing exponent saturates instead of converting" \
    "AsInt64=9223372036854775807" "$(./results/witness_fixed 4 2>&1)"
  check "and 5e9 reads back as five billion" "AsInt64=5000000000" \
    "$(./results/witness_fixed 6 2>&1)"
  local control; control=$(./results/witness_fixed 0 2>&1)
  check "in-range values are untouched"     "AsInt64=42"                  "$control"
  check "so is the largest int64"           "AsInt64=9223372036854775807" "$(./results/witness_fixed 1 2>&1)"
  check "1e300 saturates instead of reading as 1" "AsInt64=9223372036854775807" "$(./results/witness_fixed 2 2>&1)"
  check "1.5e300 saturates too"             "AsInt64=9223372036854775807" "$(./results/witness_fixed 3 2>&1)"
  local big; big=$(./results/witness_fixed 5 2>&1)
  check "and the 26-digit literal survives the round trip" \
    'round-trip: {"n":99999999999999999999999999}' "$big"
  local doc; doc=$(./results/witness_fixed document 5 2>&1)
  check "Document round-trips it as well" \
    'round-trip: {"n":99999999999999999999999999}' "$doc"

  rm -rf "$tree"

  command -v esbmc >/dev/null || { skip "esbmc not on PATH"; return; }
  both_solvers "the guarded conversion holds for every double" "VERIFICATION SUCCESSFUL" \
    harnesses/json_number_esbmc.cpp -D FIXED
  both_solvers "and the shipped helper is the one proved" "VERIFICATION SUCCESSFUL" \
    harnesses/json_number_esbmc.cpp -D FIXED -D EQUIVALENCE
}

case "${1:-all}" in
  sanitizer)    leg_sanitizer ;;
  esbmc)        leg_esbmc ;;
  fuzz)         leg_fuzz ;;
  delta)        leg_delta ;;
  reachability) leg_reachability ;;
  fix)          leg_fix ;;
  all)          leg_sanitizer; leg_esbmc; leg_fuzz; leg_delta; leg_reachability; leg_fix ;;
  *)            echo "usage: $0 [all|sanitizer|esbmc|fuzz|delta|reachability|fix]"; exit 2 ;;
esac

printf '\n%d passed, %d failed' "$pass" "$fail"
[[ $skip -eq 0 ]] && printf '\n' || printf ', %d skipped -- the run proves less than it reads\n' "$skip"
[[ $fail -eq 0 && $skip -eq 0 ]]
