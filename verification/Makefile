# Verification harnesses for aws-cpp-sdk-core codecs.
#
#   make smoke      - ESBMC frontend/OM smoke test (concrete input, no properties)
#   make confirm    - ESBMC on the two named defect inputs (B-1, B-2)
#   make esbmc      - ESBMC memory-safety runs over the symbolic harnesses
#   make asan       - concrete ASan reproducers (independent cross-check)
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

MEMSTUB     := stubs/aws_memory_stub.cpp
RESULTS     := results

.PHONY: all smoke confirm esbmc asan repros model clean

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
	-$(ESBMC) $(ESBMC_STD) $(ESBMC_DEFS) $(INCLUDES) -D MAXLEN=$(MAXLEN) \
	    harnesses/base64_decode_harness.cpp $(MEMSTUB) \
	    $(ESBMC_PROPS) $(ESBMC_BOUND) 2>&1 | tee $(RESULTS)/decode_anybyte.log
	@echo "== Base64::Decode -- base64 alphabet only =="
	-$(ESBMC) $(ESBMC_STD) $(ESBMC_DEFS) $(INCLUDES) -D MAXLEN=$(MAXLEN) \
	    -D HARNESS_MODE_ALPHABET \
	    harnesses/base64_decode_harness.cpp $(MEMSTUB) \
	    $(ESBMC_PROPS) $(ESBMC_BOUND) 2>&1 | tee $(RESULTS)/decode_alphabet.log

# ---------------------------------------------------------------------------
# Concrete reproducers. Built twice: with NDEBUG (release semantics, where
# Array::GetItem's assert is compiled out and the overflow is silent) and
# without (debug semantics, where the assert fires first).
# ---------------------------------------------------------------------------
ASAN_FLAGS := -std=c++11 -g -O1 -fsanitize=address,undefined \
              -fno-omit-frame-pointer

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
