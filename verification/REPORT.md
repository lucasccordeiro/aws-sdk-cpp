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

ESBMC's C++ frontend **did not ingest the target**. Eight distinct gaps in its
C++ operational model were found and worked around, after which ESBMC **aborts
during GOTO conversion** on `Aws::Utils::Array<unsigned char>`. That crash
blocks the symbolic proof, so ASan is the oracle that actually discharges the
claims here. Details in "ESBMC frontend results".

Both blockers were filed upstream and both are now resolved or in review:
**#6183 is closed** by [PR #6190](https://github.com/esbmc/esbmc/pull/6190)
(merged 2026-07-19), and **#6184's cause was located** — placement new with no
initializer — and fixed in [PR #6195](https://github.com/esbmc/esbmc/pull/6195)
(open). With both applied, ESBMC now converts and symexes
`Aws::Utils::Array<unsigned char>`: `make smoke` is **green**, and the symbolic
harnesses run.

They do not yet *complete*, for a new reason: a third OM defect, found by
running them, makes ESBMC report a spurious `basic_string overflow` before
reaching `Decode`. See "Blocked again, one layer up". None of this changes any
finding about `Base64::Decode` below — those still rest on ASan. All three are
tracked in [ESBMC_FIX_PLAN.md](ESBMC_FIX_PLAN.md).

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

### Operational-model gaps (8)

| # | Missing from ESBMC's C++ OM | Used at | Status |
|---|---|---|---|
| 1 | `std::size_t` not visible via `<cstdlib>` | `MemorySystemInterface.h:40` | **fixed upstream** (#6190) |
| 2 | `std::is_class` | `AWSMemory.h:132` | **fixed upstream** (#6190) |
| 3 | `std::is_polymorphic` | `AWSMemory.h:100,112` | **fixed upstream** (#6190) |
| 4 | `std::is_trivially_default_constructible` | `AWSMemory.h:307,315` | **fixed upstream** (#6190) |
| 5 | `std::is_trivially_destructible` | `AWSMemory.h:138` | **fixed upstream** (#6190) |
| 6 | `std::unique_ptr::operator=(nullptr_t)` and `unique_ptr(nullptr_t)` | `Array.h:45,137` | **fixed upstream** (#6190) |
| 7 | `std::basic_string`: `const operator[]`, `push_back`, `reserve` | `Base64.cpp:55,73-76,133-135` | **fixed upstream** (#6190) |
| 8 | `std::shared_ptr` / `allocate_shared` — absent entirely | `AWSAllocator.h:105,117` | **still open** — parse-only declaration in the shim |

Gaps 1-7 were closed by [PR #6190](https://github.com/esbmc/esbmc/pull/6190),
merged 2026-07-19, which closed issue #6183. Gaps 6 and 7 are member functions
of OM types and could not have been fixed from outside the tool at all, which
is why they drove the upstream issue.

That fix was **confirmed end-to-end here**: with `stubs/esbmc_compat.h`
entirely disabled, the only parse errors that remain are `shared_ptr` and
`allocate_shared`. The shim is correspondingly down to `shared_ptr` alone, and
the Makefile gate was renamed `ESBMC_OM_MISSING_TRAITS` →
`ESBMC_OM_MISSING_SHARED_PTR`. The rename was forced rather than cosmetic:
against a #6190 build, shimming the traits is a redefinition error.

Gap 8 was deliberately left out of #6190 — reference counting, aliasing
constructors, `weak_ptr` and `enable_shared_from_this` need a real model, not a
header addition. It is the last thing standing between this repo and an
unshimmed run.

A ninth gap surfaced only once the crash was fixed and the harnesses could
actually run — `basic_string(const char*, size_t)` asserting `n < strlen(s)`,
described under "Blocked again, one layer up" below. It is a false positive
rather than a missing member, which is why it could not be found until
something reached it.

Also observed but not blocking, and **still unfixed**:
`std::basic_string::size()` returns `int` rather than `size_type`, and OM
`unique_ptr`'s destructor is `#if 0`-ed out ("TODO: fix remove goto
sideeffect"), meaning the model never releases. The latter makes
`--memory-leak-check` results meaningless against this model — worth knowing
before trusting a leak verdict on any C++ target. This repo therefore no longer
passes `--memory-leak-check` at all.

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

**Root cause: an out-of-bounds read on a one-operand `comma` expression,
triggered by placement new with no initializer.**

`Aws::NewArray` (`AWSMemory.h:185`) constructs elements with

```cpp
new (pointerToT + i) T;      // placement new, NO initializer
```

For a non-class `T`, `new (p) T;` default-initializes, which for such a type
performs *no* initialization at all ([dcl.init.general]). Clang therefore
attaches **no initializer child** to the `CXXNewExpr`, and ESBMC builds a
`comma` expression holding a single operand. `clang_c_adjust::adjust_comma`
(`src/clang-c-frontend/clang_c_adjust_expr.cpp:1589`) then does

```cpp
expr.type() = expr.op1().type();   // unguarded op1() on a 1-operand expr
```

reading one past the end of the operand vector.

The full chain is `ByteBuffer b(3)` → `Array(size_t)` → `MakeUniqueArray<T>` →
`NewArray<T>` → `new (pointerToT + i) T;`.

The differential is one character wide:

| Expression | Result |
|---|---|
| `new (p) int;` | crash |
| `new (p) int();` | `VERIFICATION SUCCESSFUL` |

**Correction to an earlier diagnosis.** This was previously reported here as a
*use-after-free of `irept::dt`*, on the strength of a gdb session showing
`irept::detatch` (`src/util/irep.cpp:48`) locking a `dt` with `ref_count == 0`,
an invalid mutex `__kind`, and an `_M_color` enum holding a pointer. The
observations were accurate; the interpretation was not. Those bytes are not
recycled heap — they are simply **out of bounds**. `ref_count == 0` on a
live-looking `irept` reads as "freed", but is equally consistent with "never
was an `irept`".

The OOB reading explains what the UAF theory had to hand-wave: no race is
needed (`info threads` showed one thread), no stack exhaustion is implied (44
frames), and the run-to-run variation in glibc's abort message follows from
*which* garbage lands in `__kind` and sends glibc down the
priority-inheritance path (`__futex_lock_pi64`). `ulimit -s unlimited` changing
the symptom was, as suspected, a layout perturbation rather than a fix. Also
ruled out earlier and still ruled out: resource exhaustion (177 GB free, 797 of
1.49 M threads, peak RSS ~100 MB) and ESBMC's own `setrlimit`/thread paths
(neither `--memlimit` nor `--enable-keep-alive` was passed).

**Reduction.** The self-contained reduction that earlier attempts failed to
find now exists: `esbmc_bug_repros/placement_new_no_init.cpp`, which needs no
AWS headers, no shim and no `-I` flags. `crash_goto_convert_array.cpp` is kept
as the original end-to-end trigger.

Bisection (recorded for completeness): keeping `Array<T>` and dropping
`CryptoBuffer` from `Array.h` makes the same input convert and verify
successfully — `scripts/make_model_headers.sh` does that mechanically — but
constructing an `Array<unsigned char>` still crashes, because that is the path
that reaches `NewArray`.

**Fixed** by [PR #6195](https://github.com/esbmc/esbmc/pull/6195) (open at time
of writing): the C++ frontend no longer emits a `comma` for an
initializer-less `CXXNewExpr` — the value of `new (p) T;` is just the placement
address — and `adjust_comma` gains an explicit `operands().size() == 2` assert
so that any other producer of a malformed comma fails loudly instead of reading
out of bounds. Two regression tests ship with it under
`regression/esbmc-cpp/cpp/placement_new_no_init{,_fail}/`.

Verified here against a build carrying both #6190 and #6195:
`placement_new_no_init.cpp` returns `VERIFICATION SUCCESSFUL`, and so does
`make smoke` — the acceptance criterion this repo set for the crash, since it
means `Aws::Utils::Array<unsigned char>` now converts and symexes.

`crash_goto_convert_array.cpp` also converts now, and reaches the solver. It
reports `VERIFICATION FAILED` for an unrelated reason: `Aws::NewArray`
(`AWSMemory.h:166-171`) does not check `Malloc`'s result before casting and
placement-newing into it, so on the allocation-failure path `Array::operator[]`
dereferences null. That is an allocation-failure property, not the crash and
not B-1 — most verification setups assume allocation succeeds. Recorded here
only so the non-`SUCCESSFUL` verdict is not mistaken for the crash persisting.

### Blocked again, one layer up: `basic_string(const char*, size_t)`

With the crash gone, `make esbmc` runs the symbolic harnesses for the first
time. Both modes now terminate with `VERIFICATION FAILED` — but on a **spurious
property inside ESBMC's own string model**, not inside `Decode`:

```
Violated property:
  file <om>/string line 1132 function basic_string
  basic_string overflow
  n::1 < return_value$_strlen$1
```

The OM's two-argument constructor (`src/cpp/library/string:1132`) asserts:

```cpp
__ESBMC_assert(n < strlen(s), "basic_string overflow");
```

That is wrong twice over. [string.cons] gives this constructor exactly one
precondition — "`[s, s + n)` is a valid range" — and effects "constructs an
object whose initial value is the range `[s, s + n)`". So:

* **The operator is wrong.** `n == strlen(s)` is the canonical case, and the
  strict `<` rejects it. Minimal reproducer, no AWS headers:

  ```cpp
  std::string s("abc", 3);   // ESBMC: "basic_string overflow"
  ```

* **The premise is wrong.** `s` need not be null-terminated at all, so
  `strlen(s)` is not part of the precondition and is itself undefined behaviour
  on a valid non-terminated argument. A faithful model cannot be phrased in
  terms of `strlen`.

Minor, but in the same line: the `strlen(s)` assert runs *before* the
`s != NULL` assert below it, so a null argument is dereferenced before it is
checked.

The harness trips this because `Aws::String input(raw, len)` passes a `len`
that can equal `strlen(raw)` — which is exactly what the constructor is for.
It is a **false positive**, so it does not threaten soundness, but it does
block the symbolic proof just as surely as the crash did.

**Consequence for this exercise:** still no symbolic proof, but the blocker has
moved twice and is now much shallower. The crash is fixed and the harnesses in
`harnesses/base64_decode_harness.cpp` now execute end-to-end; what stops them
is a single wrong comparison in the OM's `basic_string` constructor, which
fires before control reaches `Decode`. Everything asserted about B-1 and B-2
above therefore still rests on the concrete ASan reproducers — weaker than a
proof over all inputs up to a bound, since it demonstrates the bugs exist
without bounding the set of inputs that trigger them.

Order of blockers, for the record: OM members missing (#6183, fixed) → GOTO
conversion crash (#6184, fixed) → spurious `basic_string overflow` (open). Each
was only discoverable once the previous one was cleared, which is the ordinary
shape of bringing a real codebase under a verifier for the first time.

### Issues filed against esbmc/esbmc

* **[esbmc/esbmc#6183](https://github.com/esbmc/esbmc/issues/6183)** —
  **CLOSED.** C++ OM missing `type_traits`, `unique_ptr`, `basic_string` and
  `shared_ptr` members. Reproducers: `esbmc_bug_repros/om_*.cpp`. Fixed by
  [PR #6190](https://github.com/esbmc/esbmc/pull/6190), merged 2026-07-19, with
  five regression tests under `regression/esbmc-cpp/cpp/github_6183*`.
  `shared_ptr` was deliberately excluded and needs its own issue.
* **[esbmc/esbmc#6184](https://github.com/esbmc/esbmc/issues/6184)** —
  **fix in review.** SIGABRT during GOTO conversion on `ByteBuffer`, with
  varying glibc pthread assertions. Cause: unguarded `op1()` in `adjust_comma`
  against the one-operand `comma` that placement-new-without-initializer
  produces. Fixed by [PR #6195](https://github.com/esbmc/esbmc/pull/6195).
  Reproducers: `esbmc_bug_repros/placement_new_no_init.cpp` (minimal, no AWS
  headers) and `esbmc_bug_repros/crash_goto_convert_array.cpp` (end-to-end;
  needs #6190 to get far enough to crash).
* **Not yet filed** — `basic_string(const char*, size_t)` asserts
  `n < strlen(s)`, rejecting the canonical `std::string("abc", 3)` and
  contradicting [string.cons]. Reproducer:
  `esbmc_bug_repros/om_string_ptr_len_ctor.cpp`.

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
