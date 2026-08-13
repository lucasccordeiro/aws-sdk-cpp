# UUID string-constructor overflow -- verification harnesses.
#
#   make asan          - concrete ASan/UBSan reproducers over a table of inputs
#   make confirm       - ESBMC on the named defect input, release semantics
#   make esbmc         - ESBMC memory-safety runs over the symbolic harness
#   make esbmc-debug   - the named input again, with the asserts live
#   make clean
#
# Target under analysis: Aws::Utils::UUID::UUID(const Aws::String&)
# (vendor/source/utils/UUID.cpp:34-44), pinned at aws-sdk-cpp 1.11.869.
#
# Everything ASan and ESBMC analyse is byte-for-byte upstream: the real
# UUID.cpp, the real Array/String/memory headers, and verbatim extracts of the
# only two helpers the constructor calls (HashingUtils::HexDecode,
# StringUtils::Replace) -- see stubs/aws_str_hash_extract.cpp for why those two
# are extracted rather than vendored whole.

CXX        ?= g++
ESBMC      ?= esbmc

INCLUDES   := -Istubs -Ivendor -Ivendor/include
ASAN_FLAGS := -std=c++11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer

SRCS       := vendor/source/utils/UUID.cpp \
              stubs/aws_str_hash_extract.cpp \
              stubs/aws_memory_stub.cpp
HARNESS    := harnesses/uuid_ctor_asan.cpp

RESULTS    := results

# len(de-dashed hex body)/2 > 16  <=>  overflow. The first two are well-formed
# UUID strings a caller might actually pass; the rest bound the boundary.
#
# The 36-character dash-free case is the one the ESBMC harnesses use: it
# *satisfies* the constructor's documented precondition (length == UUID_STR_SIZE,
# the first assert) and overflows anyway, because the load-bearing check is the
# second assert on the de-dashed length. A caller that length-checks the string
# the way the API documents is still not safe.
OK_CASES     := 12345678-1234-1234-1234-123456789012 AAAA 0xAABBCCDD
OVER_CASES   := 12345678-1234-1234-1234-1234567890123456 \
                123456781234123412345678901234561234 \
                1234567890123456789012345678901234567890 \
                0xAABBCCDDEEFF00112233445566778899AABBCCDDEEFF

# ---------------------------------------------------------------------------
# ESBMC configuration.
#
# --no-assertions is RELEASE SEMANTICS and is the whole point: the two length
# constraints in the constructor are `assert`s, so a run with them live stops at
# an assert and never reaches the memcpy -- the debug behaviour, which
# `esbmc-debug` keeps as a separate, deliberately-different target. Bounds and
# pointer checks are unaffected by it (they are on by default; only
# --no-bounds-check / --no-pointer-check exist).
#
# UNWIND is NOT paired with --no-unwinding-assertions: a truncated loop in the
# OM's string model would otherwise be reported as SUCCESSFUL on a program that
# overflows. Leaving unwinding assertions on turns any insufficient bound into a
# visible "unwinding assertion loop" failure rather than a silent false negative.
#
# --force-malloc-success suppresses the allocation-failure counterexample from
# the Aws::Malloc stub, which otherwise masks the defect under test.
ESBMC_STD    := --std c++11
ESBMC_DEFS   := -D ESBMC_OM_MISSING_ALLOCATE_SHARED
ESBMC_PROPS  := --force-malloc-success
UNWIND       ?= 40
MAXLEN       ?= 36
ESBMC_SRCS   := stubs/aws_str_hash_extract.cpp stubs/aws_memory_stub.cpp
ESBMC_COMMON := $(ESBMC_STD) $(ESBMC_DEFS) $(INCLUDES) $(ESBMC_PROPS) \
                --unwind $(UNWIND)

# StringUtils::Replace is `for (pos = 0;; pos += replaceLength)` with
# replaceLength == strlen("") == 0 -- an unbounded loop whose only exit is
# s.find() returning npos. The OM keeps a heap-allocated string's contents in a
# symbolic array, so find() yields a symbolic index even for a fully concrete
# input, and symex explores the loop to the global bound with erase(), insert()
# and find() -- seven nested loops -- unrolled inside every iteration. At
# --unwind 64 that is a >20-minute run consuming >1 GB before the solver is
# reached; bounding this one loop brings the same query to ~3s of symex.
#
# The bound is 2, not 1, and unwinding assertions are deliberately left ON: if 2
# iterations were not enough, ESBMC reports a violated unwinding assertion for
# this loop rather than silently verifying a truncated program. The control run
# (`make confirm`, CASE_SAFE) returns SUCCESSFUL under exactly these flags,
# which is what discharges the bound -- a SUCCESSFUL verdict with unwinding
# assertions enabled means every loop bound here, including this one, was
# adequate. Do not add --no-unwinding-assertions to "make it converge": that
# converts this from a checked assumption into an unchecked one.
REPLACE_BOUND := --unwindsetname N@Aws@N@Utils@S@StringUtils@Replace:0:2

.PHONY: asan confirm esbmc esbmc-debug clean

$(RESULTS):
	@mkdir -p $(RESULTS)

asan: | $(RESULTS)
	@$(CXX) $(ASAN_FLAGS) -DNDEBUG $(INCLUDES) $(HARNESS) $(SRCS) -o $(RESULTS)/uuid_asan_ndebug
	@$(CXX) $(ASAN_FLAGS)          $(INCLUDES) $(HARNESS) $(SRCS) -o $(RESULTS)/uuid_asan_debug
	@echo "== release semantics (-DNDEBUG): length asserts compiled out =="
	@for c in $(OK_CASES) $(OVER_CASES); do \
	    printf '%-46s ' "$$c"; \
	    if $(RESULTS)/uuid_asan_ndebug "$$c" >/dev/null 2>$(RESULTS)/.err; then \
	        echo "ok"; \
	    else \
	        grep -oE 'ERROR: AddressSanitizer: [A-Za-z-]+' $(RESULTS)/.err | head -1 \
	          || echo "FAILED (see $(RESULTS)/.err)"; \
	    fi; \
	done
	@echo "== debug semantics (asserts live): over-length input trips the assert =="
	@for c in $(OVER_CASES); do \
	    printf '%-46s ' "$$c"; \
	    if $(RESULTS)/uuid_asan_debug "$$c" >/dev/null 2>$(RESULTS)/.err; then \
	        echo "ok"; \
	    else \
	        grep -oE "Assertion .* failed|ERROR: AddressSanitizer: [A-Za-z-]+" $(RESULTS)/.err | head -1 \
	          || echo "FAILED"; \
	    fi; \
	done
	@rm -f $(RESULTS)/.err

# ---------------------------------------------------------------------------
# ESBMC: the named defect input, under both semantics, plus the control.
#
#   confirm    -- 36 hex characters, no dashes. This input SATISFIES the
#                 constructor's documented precondition (length == 36) and
#                 overflows anyway. Expect VERIFICATION FAILED with an
#                 out-of-bounds write of the 18-byte HexDecode result.
#   CASE_SAFE  -- 32 hex characters -> exactly 16 bytes. Expect SUCCESSFUL, so
#                 the failing verdict is not something every input produces.
#   esbmc-debug -- the same over-length input with asserts LIVE. Expect FAILED
#                 on the *second* assert (UUID.cpp:41, the de-dashed length),
#                 not the first: that is the whole point of the input choice.
# ---------------------------------------------------------------------------
confirm: | $(RESULTS)
	@echo "== U-1: 36 hex chars, no dashes -- expect out-of-bounds write =="
	-$(ESBMC) $(ESBMC_COMMON) $(REPLACE_BOUND) --no-assertions \
	    harnesses/uuid_ctor_concrete.cpp $(ESBMC_SRCS) \
	    2>&1 | tee $(RESULTS)/confirm_u1.log \
	    | grep -E "Violated|dereference failure|VERIFICATION"
	@echo "== control: 32 hex chars -> exactly 16 bytes -- expect SUCCESSFUL =="
	-$(ESBMC) $(ESBMC_COMMON) $(REPLACE_BOUND) --no-assertions -D CASE_SAFE \
	    harnesses/uuid_ctor_concrete.cpp $(ESBMC_SRCS) \
	    2>&1 | tee $(RESULTS)/confirm_safe.log | grep -E "VERIFICATION"

esbmc-debug: | $(RESULTS)
	@echo "== U-1 with asserts live -- expect FAILED at UUID.cpp:41 =="
	-$(ESBMC) $(ESBMC_COMMON) $(REPLACE_BOUND) \
	    harnesses/uuid_ctor_concrete.cpp $(ESBMC_SRCS) \
	    2>&1 | tee $(RESULTS)/u1_debug.log \
	    | grep -E "Violated|assertion|VERIFICATION"

# ---------------------------------------------------------------------------
# Symbolic runs. See harnesses/uuid_ctor_harness.cpp for the two input models.
# ---------------------------------------------------------------------------
esbmc: | $(RESULTS)
	@echo "== UUID(String) -- length unconstrained in [0, $(MAXLEN)] =="
	-$(ESBMC) $(ESBMC_COMMON) $(REPLACE_BOUND) --no-assertions -D MAXLEN=$(MAXLEN) \
	    harnesses/uuid_ctor_harness.cpp $(ESBMC_SRCS) \
	    2>&1 | tee $(RESULTS)/sym_anylen.log \
	    | grep -E "Violated|dereference failure|VERIFICATION"
	@echo "== UUID(String) -- length pinned at the documented 36 =="
	-$(ESBMC) $(ESBMC_COMMON) $(REPLACE_BOUND) --no-assertions -D MAXLEN=$(MAXLEN) \
	    -D HARNESS_MODE_CONTRACT \
	    harnesses/uuid_ctor_harness.cpp $(ESBMC_SRCS) \
	    2>&1 | tee $(RESULTS)/sym_contract.log \
	    | grep -E "Violated|dereference failure|VERIFICATION"

clean:
	@rm -rf $(RESULTS)
