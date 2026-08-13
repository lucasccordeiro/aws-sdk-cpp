# UUID string-constructor overflow -- verification harnesses.
#
# Target under analysis: Aws::Utils::UUID::UUID(const Aws::String&)
# (vendor/source/utils/UUID.cpp:34-44), pinned at aws-sdk-cpp 1.11.869.
#
# Everything ASan analyses is byte-for-byte upstream: the real UUID.cpp, the
# real Array/String/memory headers, and verbatim extracts of the only two
# helpers the constructor calls (HashingUtils::HexDecode, StringUtils::Replace)
# -- see stubs/aws_str_hash_extract.cpp for why those two are extracted rather
# than vendored whole.

CXX        ?= g++

INCLUDES   := -Istubs -Ivendor -Ivendor/include
ASAN_FLAGS := -std=c++11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer

SRCS       := vendor/source/utils/UUID.cpp \
              stubs/aws_str_hash_extract.cpp \
              stubs/aws_memory_stub.cpp
HARNESS    := harnesses/uuid_ctor_asan.cpp

RESULTS    := results

# len(de-dashed hex body)/2 > 16  <=>  overflow. The first two are well-formed
# UUID strings a caller might actually pass; the rest bound the boundary.
OK_CASES     := 12345678-1234-1234-1234-123456789012 AAAA 0xAABBCCDD
OVER_CASES   := 12345678-1234-1234-1234-1234567890123456 \
                1234567890123456789012345678901234567890 \
                0xAABBCCDDEEFF00112233445566778899AABBCCDDEEFF

.PHONY: asan clean

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

clean:
	@rm -rf $(RESULTS)
