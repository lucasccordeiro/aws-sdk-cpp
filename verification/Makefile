# Verification harnesses for aws-cpp-sdk-core codecs.
#
#   make smoke      - ESBMC frontend/OM smoke test (concrete input, no properties)
#   make esbmc      - ESBMC memory-safety runs over the symbolic harnesses
#   make asan       - concrete ASan reproducers (the oracle that currently works)
#   make repros     - ESBMC frontend/crash reproducers for esbmc/esbmc issues
#   make model      - regenerate model/ from pristine vendor/
#   make clean
#
# STATUS: the `esbmc` targets do not complete on this toolchain -- ESBMC 8.4.0
# aborts during GOTO conversion on Aws::Utils::Array<unsigned char>. See
# REPORT.md and esbmc_bug_repros/. The `asan` target is what actually
# discharges the memory-safety claims today.

ESBMC       ?= esbmc
CXX         ?= g++
UNWIND      ?= 8
MAXLEN      ?= 6

VERIF_DIR   := $(CURDIR)
INCLUDES    := -Istubs -Ivendor -Imodel/include
# ASan builds use pristine vendor headers: no CryptoBuffer surgery is needed
# there, so the compiled artefact is as close to upstream as possible.
ASAN_INC    := -Istubs -Ivendor -Ivendor/include

ESBMC_STD   := --std c++11
ESBMC_DEFS  := -D ESBMC_OM_MISSING_TRAITS
ESBMC_PROPS := --memory-leak-check --bounds-check --pointer-check
ESBMC_BOUND := --unwind $(UNWIND) --no-unwinding-assertions

MEMSTUB     := stubs/aws_memory_stub.cpp
RESULTS     := results

.PHONY: all smoke esbmc asan repros model clean

all: asan

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
	    $(ESBMC_BOUND) 2>&1 | tee $(RESULTS)/smoke.log

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
# ---------------------------------------------------------------------------
repros: model | $(RESULTS)
	@echo "== OM: missing <type_traits> members =="
	-$(ESBMC) $(ESBMC_STD) esbmc_bug_repros/om_missing_type_traits.cpp 2>&1 \
	    | tail -4 | tee $(RESULTS)/repro_traits.log
	@echo "== OM: unique_ptr operator=(nullptr_t) =="
	-$(ESBMC) $(ESBMC_STD) esbmc_bug_repros/om_unique_ptr_nullptr_assign.cpp 2>&1 \
	    | tail -4 | tee $(RESULTS)/repro_uniqptr.log
	@echo "== crash: GOTO conversion of Array<unsigned char> =="
	-$(ESBMC) $(ESBMC_STD) $(ESBMC_DEFS) -Istubs -Imodel/include \
	    esbmc_bug_repros/crash_goto_convert_array.cpp \
	    $(ESBMC_BOUND) 2>&1 | tail -4 | tee $(RESULTS)/repro_crash.log

clean:
	rm -rf $(RESULTS) model
