# Verification harnesses for aws-cpp-sdk-core codecs.
#
#   make smoke      - ESBMC frontend/OM smoke test (concrete input, no properties)
#   make confirm    - ESBMC on the two named defect inputs (B-1, B-2)
#   make esbmc      - ESBMC memory-safety runs over the symbolic harnesses
#   make asan       - concrete ASan reproducers (independent cross-check)
#   make testgen    - executable test cases generated from the counterexamples
#   make repros     - status of the reproducers filed against esbmc/esbmc
#   make model      - regenerate model/ from pristine vendor/
#   make clean
#
# STATUS: the `esbmc` targets now run and confirm both defects. esbmc/esbmc#6184
# (placement new with no initializer -> one-operand "comma" -> adjust_comma reads
# op1() out of bounds; reproducer esbmc_bug_repros/placement_new_no_init.cpp) is
# fixed by #6195, and #6183 by #6190. Requires a build carrying both; against an
# older one these targets stop at a parse error or abort instead.
#
# The remaining OM defect, esbmc/esbmc#6199 (basic_string(const char*, n) asserts
# n < strlen(s); reproducer esbmc_bug_repros/om_string_ptr_len_ctor.cpp), is
# worked around in the harnesses rather than blocking them -- see REPORT.md.
#
# UNWIND is load-bearing -- do not lower it. Base64::Base64() populates a
# 256-entry decoding table via memset(256) plus a 64-iteration fill loop. Under
# a small --unwind those loops are truncated, every byte maps to SENTINEL_VALUE,
# the value3/value4 guards in Decode skip both inner writes, and ESBMC reports
# VERIFICATION SUCCESSFUL on a program that overflows. The old value here was 8,
# which produced exactly that false negative. Tell-tale of a vacuous run: ~100
# VCCs instead of ~18000.

ESBMC       ?= esbmc
CXX         ?= g++
UNWIND      ?= 300
MAXLEN      ?= 7

VERIF_DIR   := $(CURDIR)
INCLUDES    := -Istubs -Ivendor -Imodel/include
# ASan builds use pristine vendor headers: no CryptoBuffer surgery is needed
# there, so the compiled artefact is as close to upstream as possible.
ASAN_INC    := -Istubs -Ivendor -Ivendor/include

ESBMC_STD   := --std c++11
ESBMC_DEFS  := -D ESBMC_OM_MISSING_SHARED_PTR
# Array-bounds and pointer checks are ON BY DEFAULT in current ESBMC -- only
# --no-bounds-check / --no-pointer-check exist. The old affirmative spellings
# were removed and are now hard errors, so do not re-add them.
# --memory-leak-check is deliberately NOT passed: the OM's unique_ptr has its
# destructor #if 0-ed out, so a leak verdict against this model is meaningless.
# --force-malloc-success suppresses the allocation-failure counterexample from
# the Aws::Malloc stub, which otherwise masks the defect under test.
ESBMC_PROPS := --force-malloc-success
ESBMC_BOUND := --unwind $(UNWIND) --no-unwinding-assertions
# Every ESBMC run over the harnesses shares these. `testgen` replays the
# counterexample of the run `esbmc` performs, so the two MUST agree -- a flag
# added to one and not the other would have testgen confirming a counterexample
# from a different verification problem.
ESBMC_COMMON := $(ESBMC_STD) $(ESBMC_DEFS) $(ESBMC_PROPS) $(ESBMC_BOUND)

MEMSTUB     := stubs/aws_memory_stub.cpp
RESULTS     := results

.PHONY: all smoke confirm esbmc asan repros testgen model clean

all: confirm asan

model:
	@./scripts/make_model_headers.sh

$(RESULTS):
	@mkdir -p $(RESULTS)

# ---------------------------------------------------------------------------
# Step 1: does the frontend ingest the target at all?
# ---------------------------------------------------------------------------
smoke: model | $(RESULTS)
	@echo "== ESBMC smoke test (concrete input) =="
	-$(ESBMC) $(ESBMC_STD) $(ESBMC_DEFS) $(INCLUDES) \
	    harnesses/smoke_harness.cpp $(MEMSTUB) \
	    $(ESBMC_PROPS) $(ESBMC_BOUND) 2>&1 | tee $(RESULTS)/smoke.log

# ---------------------------------------------------------------------------
# Step 2: the two defects on their named inputs. Both are expected to report
# VERIFICATION FAILED -- that is the confirmation, not a problem.
# ---------------------------------------------------------------------------
confirm: model | $(RESULTS)
	@echo "== B-1: \"AAAA=\" -- expect assertion GetItem (index < m_length) =="
	-$(ESBMC) $(ESBMC_STD) $(ESBMC_DEFS) $(INCLUDES) \
	    harnesses/base64_decode_concrete.cpp $(MEMSTUB) \
	    $(ESBMC_PROPS) $(ESBMC_BOUND) 2>&1 | tee $(RESULTS)/confirm_b1.log \
	    | grep -E "Violated|assertion GetItem|VERIFICATION"
	@echo "== B-2: 0xffffffff -- expect access to object out of bounds =="
	-$(ESBMC) $(ESBMC_STD) $(ESBMC_DEFS) $(INCLUDES) -D CASE_B2 \
	    harnesses/base64_decode_concrete.cpp $(MEMSTUB) \
	    $(ESBMC_PROPS) $(ESBMC_BOUND) 2>&1 | tee $(RESULTS)/confirm_b2.log \
	    | grep -E "Violated|dereference failure|VERIFICATION"

# ---------------------------------------------------------------------------
# Step 3: memory-safety runs.
#
# ANY_BYTE  - unconstrained input bytes; models Decode's actual (absent)
#             precondition.
# ALPHABET  - bytes restricted to the RFC 4648 alphabet plus '='; the strongest
#             realistic caller precondition. A violation here is not an
#             under-constrained-harness artefact.
# ---------------------------------------------------------------------------
esbmc: model | $(RESULTS)
	@echo "== Base64::Decode -- unconstrained bytes =="
	-$(ESBMC) $(ESBMC_COMMON) $(INCLUDES) -D MAXLEN=$(MAXLEN) \
	    harnesses/base64_decode_harness.cpp $(MEMSTUB) \
	    2>&1 | tee $(RESULTS)/decode_anybyte.log
	@echo "== Base64::Decode -- base64 alphabet only =="
	-$(ESBMC) $(ESBMC_COMMON) $(INCLUDES) -D MAXLEN=$(MAXLEN) \
	    -D HARNESS_MODE_ALPHABET \
	    harnesses/base64_decode_harness.cpp $(MEMSTUB) \
	    2>&1 | tee $(RESULTS)/decode_alphabet.log

# ---------------------------------------------------------------------------
# Concrete reproducers. Built twice: with NDEBUG (release semantics, where
# Array::GetItem's assert is compiled out and the overflow is silent) and
# without (debug semantics, where the assert fires first).
# ---------------------------------------------------------------------------
ASAN_FLAGS := -std=c++11 -g -O1 -fsanitize=address,undefined \
              -fno-omit-frame-pointer

# ---------------------------------------------------------------------------
# Step 4: turn the ESBMC counterexamples into executable tests.
#
# https://esbmc.github.io/docs/c-cpp/ctest-gen/ -- --generate-ctest-testcase
# emits test_case.cpp (concrete __VERIFIER_nondet_* implementations replaying
# the counterexample), CMakeLists.txt and esbmc_verifier.h. Replaying those
# values against the *native* build turns a solver verdict into a process that
# actually crashes: an independent check that the counterexample is a real
# input and not an artefact of ESBMC's own model.
#
# Two defects in the generator are worked around here rather than blocking:
#
#  (a) The nondet-pointer stub is emitted as
#          static const void* v[] = { 0 };  return v[i++];
#      from a function returning void* (src/goto-symex/ctest.cpp:378, with
#      c_type "void*" from line 167). const void* -> void* is ill-formed in C++
#      and a constraint violation in C, so ANY counterexample containing a
#      nondet pointer yields a test case that does not compile. Both of ours
#      do. Rewritten below to `void *const v[]`.
#
#  (b) The generated CMakeLists.txt lists only $(MEMSTUB) as "the original
#      source" -- ctest.cpp:342 takes config.options "input-file", which holds
#      the LAST input file, not the entry-point TU. The harness that defines
#      main is therefore missing: in general the documented cmake+ctest flow
#      dies at link with "undefined reference to main", and here even earlier,
#      since the bare filename does not exist beside the generated
#      CMakeLists.txt. We compile directly instead.
#
# A replay is a CONFIRMATION only if all four hold; any other outcome fails the
# target, because a green testgen that means "the process died somehow" is
# worse than no testgen at all:
#
#   1. the generated char array has exactly MAXLEN entries -- see below;
#   2. no "replay: assumption violated" (the values are inside the harness's
#      own preconditions, so the crash is not self-inflicted);
#   3. a sanitizer diagnostic was raised at all; and
#   4. frame #0 is the Base64.cpp line the symbolic run indicted, not merely
#      some crash.
#
# On (1): ctest.cpp:370-380 emits ONE array per C type, filled in trace order
# from every nondet in the counterexample -- not only the harness's. The
# generated int and pointer arrays are proof of that: the harness makes no such
# calls, yet both arrays are non-empty. Today the char array holds exactly the
# MAXLEN bytes the harness asks for, but nothing in ESBMC guarantees that. One
# stray char-typed nondet ahead of the loop would shift every replayed byte by
# one, run v[i++] off the end of a MAXLEN-element array, and still "crash" --
# a false confirmation. The count check pins that assumption.
TESTGEN_ESBMC := $(ESBMC_COMMON) -D ESBMC_TESTGEN -D MAXLEN=$(MAXLEN) \
                 --generate-ctest-testcase
INCLUDES_ABS  := -I$(VERIF_DIR)/stubs -I$(VERIF_DIR)/vendor \
                 -I$(VERIF_DIR)/model/include

# $(1) = tag, $(2) = extra -D for the harness mode, $(3) = expected Base64.cpp
# line of frame #0 in the replay.
define testgen_case
	@echo "== $(1): generating test case from the ESBMC counterexample =="
	@rm -rf $(RESULTS)/testgen_$(1)
	@mkdir -p $(RESULTS)/testgen_$(1)
	-cd $(RESULTS)/testgen_$(1) && $(ESBMC) $(TESTGEN_ESBMC) $(2) \
	    $(INCLUDES_ABS) \
	    $(VERIF_DIR)/harnesses/base64_decode_harness.cpp $(VERIF_DIR)/$(MEMSTUB) \
	    > testgen.log 2>&1
	@test -f $(RESULTS)/testgen_$(1)/test_case.cpp \
	    || { echo "  FAIL: no test case generated (see testgen.log)"; exit 1; }
	@grep -E "^(char|unsigned long) __VERIFIER_nondet" -A3 \
	    $(RESULTS)/testgen_$(1)/test_case.cpp
	@n=`sed -n 's/.*static const char v\[\] = { \(.*\) };.*/\1/p' \
	      $(RESULTS)/testgen_$(1)/test_case.cpp | tr ',' '\n' | wc -l`; \
	 test "$$n" -eq $(MAXLEN) \
	    || { echo "  FAIL: char array has $$n entries, expected $(MAXLEN)"; \
	         echo "        replayed bytes would not line up with the harness"; \
	         exit 1; }
	@sed -i.bak 's/static const void\* v\[\]/static void *const v[]/' \
	    $(RESULTS)/testgen_$(1)/test_case.cpp
	@rm -f $(RESULTS)/testgen_$(1)/test_case.cpp.bak
	@echo "== $(1): replaying those values natively under ASan =="
	@$(CXX) $(ASAN_FLAGS) -DNDEBUG -D ESBMC_REPLAY -D MAXLEN=$(MAXLEN) $(2) \
	    $(ASAN_INC) harnesses/base64_decode_harness.cpp \
	    $(RESULTS)/testgen_$(1)/test_case.cpp $(MEMSTUB) \
	    -o $(RESULTS)/testgen_$(1)/replay
	@$(RESULTS)/testgen_$(1)/replay >/dev/null \
	    2>$(RESULTS)/testgen_$(1)/replay.log || true
	@log=$(RESULTS)/testgen_$(1)/replay.log; \
	 grep -oE 'replay: input=[0-9a-f]* len=[0-9]+' $$log || true; \
	 if grep -q 'replay: assumption violated' $$log; then \
	     echo "  FAIL: replayed values violate the harness preconditions --"; \
	     echo "        the crash would prove nothing about a legitimate input"; \
	     exit 1; \
	 fi; \
	 grep -oE 'ERROR: AddressSanitizer: [A-Za-z-]+' $$log | head -1; \
	 grep -q 'ERROR: AddressSanitizer' $$log \
	    || { echo "  FAIL: no sanitizer diagnostic -- counterexample did not"; \
	         echo "        survive contact with the real program"; exit 1; }; \
	 grep -oE '#0 .*Base64\.cpp:[0-9]+' $$log | head -1; \
	 grep -qE '#0 .*Base64\.cpp:$(3)' $$log \
	    || { echo "  FAIL: crashed away from Base64.cpp:$(3) -- not this defect"; \
	         exit 1; }; \
	 echo "  OK: $(1) reproduced at Base64.cpp:$(3)"
endef

testgen: model | $(RESULTS)
	$(call testgen_case,b1,-D HARNESS_MODE_ALPHABET,115)
	$(call testgen_case,b2,,103)

# Inputs where the sizing pass and the fill loop disagree, plus controls.
ASAN_CASES := AAAA AAAA= AAAA== AAAA=A QUJDRA= AAAAAAAA= AA== QUJD

asan: | $(RESULTS)
	@$(CXX) $(ASAN_FLAGS) -DNDEBUG $(ASAN_INC) \
	    harnesses/base64_decode_asan.cpp $(MEMSTUB) -o $(RESULTS)/b64_asan_ndebug
	@$(CXX) $(ASAN_FLAGS) $(ASAN_INC) \
	    harnesses/base64_decode_asan.cpp $(MEMSTUB) -o $(RESULTS)/b64_asan_debug
	@echo "== release semantics (-DNDEBUG): assert compiled out =="
	@for c in $(ASAN_CASES); do \
	    printf '%-12s ' "$$c"; \
	    if $(RESULTS)/b64_asan_ndebug "$$c" >/dev/null 2>$(RESULTS)/.err; then \
	        echo "ok"; \
	    else \
	        grep -oE 'ERROR: AddressSanitizer: [a-z-]+' $(RESULTS)/.err | head -1 \
	          || echo "FAILED (see $(RESULTS)/.err)"; \
	    fi; \
	done
	@echo "== debug semantics (asserts live) =="
	@for c in $(ASAN_CASES); do \
	    printf '%-12s ' "$$c"; \
	    if $(RESULTS)/b64_asan_debug "$$c" >/dev/null 2>$(RESULTS)/.err; then \
	        echo "ok"; \
	    else \
	        grep -oE "Assertion .* failed|ERROR: AddressSanitizer: [a-z-]+" $(RESULTS)/.err | head -1 \
	          || echo "FAILED"; \
	    fi; \
	done
	@rm -f $(RESULTS)/.err

# High-bit bytes exercise the signed-char index into the 256-entry decoding
# table. Passed as hex (-x) so the bytes survive the shell.
	@echo "== high-bit input bytes (signed char index into decoding table) =="
	@for h in ffffffff 80414141 e9e9e9e9 41414180; do \
	    printf '0x%-12s ' "$$h"; \
	    if $(RESULTS)/b64_asan_ndebug -x "$$h" >/dev/null 2>$(RESULTS)/.err; then \
	        echo "ok"; \
	    else \
	        grep -oE 'ERROR: AddressSanitizer: [A-Za-z-]+' $(RESULTS)/.err | head -1 \
	          || echo "FAILED"; \
	    fi; \
	done
	@rm -f $(RESULTS)/.err

# ---------------------------------------------------------------------------
# Reproducers filed against esbmc/esbmc.
#   #6183 (OM gaps)              -> FIXED by #6190, expect SUCCESSFUL
#   #6184 (GOTO-convert SIGABRT) -> FIXED by #6195, expect SUCCESSFUL
#   #6199 (basic_string ptr+len) -> STILL OPEN, expect FAILED
# A verdict flip on any of these means an ESBMC regression, an ESBMC older than
# the fixes, or -- for #6199 -- that the fix has landed and the harness
# workarounds described in REPORT.md can be reverted.
# ---------------------------------------------------------------------------
repros: model | $(RESULTS)
	@echo "== OM: missing <type_traits> members (#6183, fixed) =="
	-$(ESBMC) $(ESBMC_STD) esbmc_bug_repros/om_missing_type_traits.cpp 2>&1 \
	    | tail -4 | tee $(RESULTS)/repro_traits.log
	@echo "== OM: unique_ptr operator=(nullptr_t) (#6183, fixed) =="
	-$(ESBMC) $(ESBMC_STD) esbmc_bug_repros/om_unique_ptr_nullptr_assign.cpp 2>&1 \
	    | tail -4 | tee $(RESULTS)/repro_uniqptr.log
	@echo "== OM: basic_string ptr+len ctor (#6199, STILL OPEN -> expect FAILED) =="
	-$(ESBMC) $(ESBMC_STD) esbmc_bug_repros/om_string_ptr_len_ctor.cpp 2>&1 \
	    | tail -4 | tee $(RESULTS)/repro_string_ptr_len.log
	@echo "== crash: placement new with no initializer (minimal, #6184, fixed) =="
	-$(ESBMC) $(ESBMC_STD) esbmc_bug_repros/placement_new_no_init.cpp 2>&1 \
	    | tail -4 | tee $(RESULTS)/repro_placement_new.log
	@echo "== crash: GOTO conversion of Array<unsigned char> (#6184, fixed) =="
	-$(ESBMC) $(ESBMC_STD) $(ESBMC_DEFS) -Istubs -Imodel/include \
	    esbmc_bug_repros/crash_goto_convert_array.cpp \
	    $(ESBMC_PROPS) $(ESBMC_BOUND) 2>&1 | tail -4 | tee $(RESULTS)/repro_crash.log

clean:
	rm -rf $(RESULTS) model
