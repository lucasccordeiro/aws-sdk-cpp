# ESBMC vs. aws-cpp-sdk-core codecs — findings

**Target:** `aws/aws-sdk-cpp` @ `95988ca5527201b4ed8804a942d8d0788ad1755c` (v1.11.850)
**Function under analysis:** `Aws::Utils::Base64::Base64::Decode`
(`src/aws-cpp-sdk-core/source/utils/base64/Base64.cpp:91-121`)
**Tool:** ESBMC 8.4.0, x86_64 linux
**Cross-check:** GCC + AddressSanitizer/UBSan

---

## Summary

Two memory-safety defects were found in `Base64::Decode`, both reachable from
untrusted input through a public API that performs no validation of its
argument:

| # | Defect | Effect | Trigger |
|---|--------|--------|---------|
| **B-1** | Output buffer sized by one rule, written by another | **Heap buffer overflow (WRITE)**, 1 byte past the allocation | `"AAAA="`, `"AAAA=="`, `"AAAAAAAA="` — any input whose length is not a multiple of 4 and which ends in `'='` |
| **B-2** | `char` sign-extended before indexing a 256-entry table | **Wild out-of-bounds READ** → SEGV | any byte ≥ `0x80`, e.g. `\xFF\xFF\xFF\xFF` |

Both were **confirmed with a concrete reproducer under AddressSanitizer**, not
merely predicted. Neither is an artefact of an under-constrained harness — see
"Is it real?" below.

ESBMC's C++ frontend **did not ingest the target**. Seven distinct gaps in its
C++ operational model were found and worked around, after which ESBMC **aborts
during GOTO conversion** on `Aws::Utils::Array<unsigned char>`. That crash
blocks the symbolic proof, so ASan is the oracle that actually discharges the
claims here. Details in "ESBMC frontend results".

---

## B-1 — Heap buffer overflow in `Base64::Decode`

### The defect

`Decode` sizes its output buffer with one computation and fills it with a
different, independent one.

Sizing (`Base64.cpp:123-139`):

```cpp
size_t Base64::CalculateBase64DecodedLength(const Aws::String& b64input)
{
    const size_t len = b64input.length();
    if (len < 2) return 0;
    size_t padding = 0;
    if (b64input[len-1] == '=' && b64input[len-2] == '=') padding = 2;
    else if (b64input[len-1] == '=')                      padding = 1;
    return (len * 3 / 4 - padding);                       // line 138
}
```

Filling (`Base64.cpp:98-118`):

```cpp
size_t blockCount = str.length() / 4;                     // line 98
for (size_t i = 0; i < blockCount; ++i) {
    ...
    size_t bufferIndex = i * 3;
    buffer[bufferIndex] = ...;                            // line 109
    if (value3 != SENTINEL_VALUE) {
        buffer[++bufferIndex] = ...;                      // line 112
        if (value4 != SENTINEL_VALUE)
            buffer[++bufferIndex] = ...;                  // line 115
    }
}
```

The sizing pass counts padding at the **end of the string**. The fill loop only
ever looks at **complete 4-character blocks**, and `blockCount = len/4`
truncates any remainder. When the trailing `'='` lives in that truncated
remainder, it is subtracted from the buffer size but never seen by the loop —
so the loop takes the no-padding path and writes three bytes for a block the
allocation was shortened for.

Worked example, `"AAAA="` (length 5):

```
sizing:  len = 5, last char '=' , second-to-last 'A'  -> padding = 1
         decodedLength = 5*3/4 - 1 = 3 - 1 = 2        -> 2-byte allocation
filling: blockCount = 5/4 = 1  -> decodes the block "AAAA"
         'A' decodes to 0; SENTINEL_VALUE (255) is only ever the value of '='
         so neither value3 nor value4 is SENTINEL -> all three stores execute
         -> writes buffer[0], buffer[1], buffer[2]
```

`buffer[2]` is one past the end of a 2-byte heap allocation.

### Evidence

`make asan`, release semantics (`-DNDEBUG`, i.e. any release build of the SDK):

```
AAAA         ok
AAAA=        ERROR: AddressSanitizer: heap-buffer-overflow
AAAA==       ERROR: AddressSanitizer: heap-buffer-overflow
AAAA=A       ok
QUJDRA=      ok
AAAAAAAA=    ERROR: AddressSanitizer: heap-buffer-overflow
AA==         ok
QUJD         ok
```

Full diagnostic for `"AAAA="`:

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000012
WRITE of size 1 at 0x502000000012 thread T0
    #0 Aws::Utils::Base64::Base64::Decode(...) vendor/source/utils/base64/Base64.cpp:115
0x502000000012 is located 0 bytes after 2-byte region [0x502000000010,0x502000000012)
allocated by thread T0 here:
    #1 Aws::Malloc(char const*, unsigned long) stubs/aws_memory_stub.cpp:46
    #4 Aws::Utils::Array<unsigned char>::Array(unsigned long) vendor/include/aws/core/utils/Array.h:45
    #5 Aws::Utils::Base64::Base64::Decode(...) vendor/source/utils/base64/Base64.cpp:95
```

The written value is derived from input bytes, so this is attacker-influenced
data one byte past a heap allocation.

### Debug vs release

`Array::GetItem` (`Array.h:206-210`) carries `assert(index < m_length)`. So:

* **Debug build** — the assert fires first: `Assertion 'index < m_length' failed`.
  A crash, but a controlled one.
* **Release build (`NDEBUG`)** — the assert is compiled out and the overflow is
  **silent heap corruption**.

`make asan` runs both and shows the split. The assert means the defect is
detectable in testing, which likely explains why it has survived: release
builds are where it bites, and there it is silent.

### The controls matter

`AA==` was *predicted* to overflow by the crude arithmetic check printed by the
harness, but is actually **safe** — its `'='` characters sit inside the single
complete block, so the fill loop does see them and skips the later stores. The
crude predictor over-approximates; ASan is the oracle. The distinguishing
condition is narrower than "size < writes":

> `len % 4 != 0` **and** `str[len-1] == '='` **and** `len >= 5`
>
> i.e. the trailing `'='` sits at an index `>= blockCount*4` and is therefore
> invisible to the fill loop.

### Is it real, or an under-constrained harness?

Real. Three independent reasons:

1. **The inputs are well-formed base64 characters.** Every byte of `"AAAA="` is
   in the RFC 4648 alphabet plus the pad character. This is not a fuzzed blob
   of random bytes — it is the alphabet the function is *for*. The symbolic
   harness (`base64_decode_harness.cpp`) encodes exactly this as
   `HARNESS_MODE_ALPHABET`, the strongest realistic caller precondition, and
   the counterexample survives it.
2. **`Decode` documents and enforces no precondition.** Its declaration
   (`Base64.h:49`) is `ByteBuffer Decode(const Aws::String&) const;` with the
   comment "Decode a base64 string into a byte buffer." It validates nothing:
   not `len % 4`, not alphabet membership, not padding position. There is no
   precondition to violate.
3. **It is reachable from a public utility API.** `Decode` is public, and is
   wrapped by `HashingUtils::Base64Decode` (`HashingUtils.cpp:40`), itself
   public. Within the sparse checkout used here the concrete caller is
   `PrecalculatedHash.cpp:15` (`Base64Decode(hash.c_str())`); generated service
   clients were not checked out, so the full caller set upstream is wider than
   what was verified here. Both `Base64::Decode` and `HashingUtils::Base64Decode`
   are exported API that an SDK consumer may call on data of their choosing.

The only way to call this "not a bug" is to posit an undocumented precondition
that the input length is a multiple of 4 — which the function neither states
nor checks, and which its own padding logic implicitly denies (it goes out of
its way to handle a trailing `'='`).

---

## B-2 — Out-of-bounds read from sign-extended `char`

### The defect

`Base64.cpp:103-106`:

```cpp
uint32_t value1 = m_mimeBase64DecodingTable[uint32_t(rawString[stringIndex])];
```

`m_mimeBase64DecodingTable` is `uint8_t[256]` (`Base64.h:63`). `rawString` is
`const char*`, and plain `char` is **signed** on x86-64 Linux (and on every ABI
where `CHAR_MIN < 0`). For an input byte of `0xFF`:

```
rawString[i]            == (char)-1
uint32_t((char)-1)      == 4294967295        // sign-extend to int, then convert
m_mimeBase64DecodingTable[4294967295]        // ~4 GB past a 256-byte member array
```

The cast to `uint32_t` looks like it sanitises the index, but it is applied
*after* the value is already negative — it converts `-1` to `UINT32_MAX` rather
than to `255`.

### Evidence

```
0xffffffff     ERROR: AddressSanitizer: SEGV
0x80414141     ERROR: AddressSanitizer: SEGV
0xe9e9e9e9     ERROR: AddressSanitizer: SEGV
0x41414180     ERROR: AddressSanitizer: SEGV
```

```
ERROR: AddressSanitizer: SEGV on unknown address 0x7eacfd7000ff
The signal is caused by a READ memory access.
    #0 Aws::Utils::Base64::Base64::Decode(...) vendor/source/utils/base64/Base64.cpp:103
```

### Is it real?

Yes, with one portability caveat worth stating honestly: **it depends on `char`
being signed.** On x86-64 Linux/GCC and Clang it is, so the SDK is affected on
its most common server platform. On ARM (where `char` is unsigned by default)
the same code is benign, as it is under `-funsigned-char`.

It is a read, not a write, so the impact is a crash (DoS) or, if the wild
address happens to be mapped, decoding against attacker-influenced table data —
not direct memory corruption. Lower severity than B-1, but the same root cause
class: unvalidated input reaching raw index arithmetic.

Any non-ASCII byte reaches this. Base64 input arriving over the wire is exactly
where such bytes appear.

### Suggested fix (both defects)

B-2 is a one-character fix — index with an unsigned char:

```cpp
uint32_t value1 = m_mimeBase64DecodingTable[uint8_t(rawString[stringIndex])];
```

B-1 needs the two computations reconciled. The minimal fix is to make the
sizing pass agree with what the fill loop will actually do — compute the length
from `blockCount`, and only count padding that falls inside a complete block:

```cpp
const size_t blockCount = len / 4;
size_t padding = 0;
if (blockCount > 0) {
    const size_t last = blockCount * 4;          // one past the last full block
    if (b64input[last-1] == '=') padding++;
    if (b64input[last-2] == '=') padding++;
}
return blockCount * 3 - padding;
```

Rejecting `len % 4 != 0` outright would also work and is arguably more correct
for a strict RFC 4648 decoder, but is a behaviour change for existing callers.

---

## ESBMC frontend results

The first question asked was whether ESBMC's C++ frontend ingests the target at
all. **It does not, out of the box.** Here is exactly what blocked it, in the
order encountered.

Note: the flags in the original plan (`--cppstd`, `--parse-only`) do not exist
in ESBMC 8.4.0; the equivalents are `--std` and `--goto-functions-only`.

### Dependency friction (not ESBMC's fault)

`Base64.cpp` transitively includes only 9 SDK headers, but two of them include
`aws/crt/StlAllocator.h` and `aws/crt/Types.h` from the `aws-crt-cpp`
submodule. Both are needed only for code paths guarded by
`USE_AWS_MEMORY_MANAGEMENT` or for `CryptoBuffer`'s CRT interop, so three small
stub headers (`stubs/aws/...`) replace the entire submodule. `AWSMemory.cpp`'s
allocator plumbing is stubbed the same way, faithfully reproducing the
no-custom-memory-system path that a stock SDK build takes.

With those, **GCC compiles the TU cleanly.** Everything below is ESBMC-specific.

### Operational-model gaps (7)

| # | Missing from ESBMC's C++ OM | Used at | Worked around by |
|---|---|---|---|
| 1 | `std::size_t` not visible via `<cstdlib>` | `MemorySystemInterface.h:40` | shim includes `<cstddef>` first |
| 2 | `std::is_class` | `AWSMemory.h:132` | shim, via `__is_class` builtin |
| 3 | `std::is_polymorphic` | `AWSMemory.h:100,112` | shim, via `__is_polymorphic` |
| 4 | `std::is_trivially_default_constructible` | `AWSMemory.h:307,315` | shim, via `__is_trivially_constructible` |
| 5 | `std::is_trivially_destructible` | `AWSMemory.h:138` | shim, via `__is_trivially_destructible` |
| 6 | `std::unique_ptr::operator=(nullptr_t)` and `unique_ptr(nullptr_t)` | `Array.h:45,137` | **patched ESBMC's OM** (cannot be fixed externally) |
| 7 | `std::basic_string`: `const operator[]`, `push_back`, `reserve` | `Base64.cpp:55,73-76,133-135` | **patched ESBMC's OM** |
| 8 | `std::shared_ptr` / `allocate_shared` — absent entirely | `AWSAllocator.h:105,117` | parse-only declaration in the shim |

Gaps 2-5 and 8 are handled in `stubs/esbmc_compat.h` without touching ESBMC.
Gaps 6 and 7 are member functions of OM types and **cannot** be fixed from
outside, so `src/cpp/library/{memory,string}` were patched locally; those
patches are the basis of the upstream issue.

Notable: ESBMC's clang frontend already accepts the `__is_class` /
`__is_polymorphic` / `__is_trivially_*` builtins, so gaps 2-5 are a few lines
each to fix properly in the OM.

Also observed but not blocking: `std::basic_string::size()` returns `int`
rather than `size_type`, and OM `unique_ptr`'s destructor is `#if 0`-ed out
("TODO: fix remove goto sideeffect"), meaning the model never releases. The
latter makes `--memory-leak-check` results meaningless against this model —
worth knowing before trusting a leak verdict on any C++ target.

### Crash: GOTO conversion of `Array<unsigned char>`

With all eight gaps closed, ESBMC parses both TUs and then **aborts during
GOTO conversion**. Reproducer: `esbmc_bug_repros/crash_goto_convert_array.cpp`
— constructing a single `Aws::Utils::ByteBuffer` is enough; the crash needs no
code in `main` beyond that, and merely *including* the unmodified `Array.h`
(with `CryptoBuffer` present) triggers it with an empty `main`.

The abort message varies run to run over the same input:

```
Fatal glibc error: pthread_mutex_lock.c:450 ... assertion failed: e != ESRCH || !robust
The futex facility returned an unexpected error code.
terminate called after throwing an instance of 'std::system_error'  what(): Invalid argument
Fatal glibc error: tpp.c:83 (__pthread_tpp_change_priority): assertion failed: ...
```

Four different glibc/pthread failure modes from one deterministic input is the
signature of memory corruption inside ESBMC scribbling over glibc's thread
structures.

**Root cause (diagnosed under gdb): use-after-free of `irept::dt`.** The abort
resolves to `irept::detatch` (`src/util/irep.cpp:48`) locking
`old_data->dt_mutex`, reached from `clang_c_adjust::adjust_comma`. The block
being locked is already freed and recycled:

```
(gdb) p *data
$2 = {ref_count = 0,
      dt_mutex = {... __lock = -2147483487, __owner = 157060624,
                  __kind = 170985904 ...},
      named_sub = {... _M_color = (unknown: 0xa302e70) ...}}
```

`ref_count` is already 0, `__kind` is not a valid mutex kind, and an `_M_color`
enum holds a pointer. The bogus `__kind` is what sends glibc down the
priority-inheritance path (`__futex_lock_pi64`), which is why the symptom
shifts between runs.

Two earlier hypotheses are **ruled out**: it is not a data race (`info threads`
shows exactly one thread), and it is not stack exhaustion (the full backtrace
is 44 frames). The observation that `ulimit -s unlimited` changes the symptom
was a red herring — it perturbs allocation layout so the freed block is
recycled differently. Also ruled out: resource exhaustion (177 GB free, 797 of
1.49 M threads, peak RSS ~100 MB) and ESBMC's own `setrlimit`/thread paths
(neither `--memlimit` nor `--enable-keep-alive` was passed).

What remains unknown is *where* the reference count is unbalanced. See
[ESBMC_FIX_PLAN.md](ESBMC_FIX_PLAN.md) for the plan to find it.

Bisection: keeping `Array<T>` and dropping `CryptoBuffer` from `Array.h` makes
the same input convert and verify successfully. `scripts/make_model_headers.sh`
does that mechanically, which is enough to get past the *include*, but
constructing an `Array<unsigned char>` still crashes. A self-contained
reduction (no AWS headers) was attempted and did not reproduce; the filed issue
therefore points at this repository for exact reproduction.

**Consequence for this exercise:** no symbolic proof was obtained. The
harnesses in `harnesses/base64_decode_harness.cpp` are written, wired into
`make esbmc`, and ready to run the moment the crash is fixed. Everything
asserted about B-1 and B-2 above rests on the concrete ASan reproducers, which
is weaker than a proof over all inputs up to a bound — it demonstrates the bugs
exist but does not bound the set of inputs that trigger them.

### Issues filed against esbmc/esbmc

* **[esbmc/esbmc#6183](https://github.com/esbmc/esbmc/issues/6183)** — C++ OM
  missing `type_traits`, `unique_ptr`, `basic_string` and `shared_ptr` members.
  Reproducers: `esbmc_bug_repros/om_*.cpp`. A patch for the two gaps that cannot
  be shimmed externally is on branch `fix/cpp-om-unique-ptr-nullptr-assign`
  (+75 lines to `src/cpp/library/{memory,string}`).
* **[esbmc/esbmc#6184](https://github.com/esbmc/esbmc/issues/6184)** — SIGABRT
  during GOTO conversion on `ByteBuffer`, with varying glibc pthread
  assertions. Reproducer:
  `esbmc_bug_repros/crash_goto_convert_array.cpp`. Depends on #6183's patches
  to get far enough to crash.

---

## Reproducing

```bash
make asan     # the confirmed findings — B-1 and B-2
make smoke    # ESBMC frontend smoke test (currently aborts)
make esbmc    # symbolic harnesses (blocked on the crash)
make repros   # the ESBMC bug reproducers
```

`make asan` requires only GCC. The ESBMC targets require the two OM patches
described above; without them the run stops at a parse error instead.
