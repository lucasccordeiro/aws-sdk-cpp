# ESBMC vs. aws-cpp-sdk-core codecs — findings

**Target:** `aws/aws-sdk-cpp` @ `95988ca5527201b4ed8804a942d8d0788ad1755c` (v1.11.850)
**Function under analysis:** `Aws::Utils::Base64::Base64::Decode`
(`src/aws-cpp-sdk-core/source/utils/base64/Base64.cpp:91-121`)
**Tool:** ESBMC master `8d3cee251a` (8.4.0, carrying #6190/#6195/#6209/#6210/
#6225/#6403; originally reported against `d0bb9881f2`)
**Cross-check:** GCC + AddressSanitizer/UBSan

> **Provenance caveat for the 2026-07-28 run.** The binary was built from
> `8d3cee251a` *plus uncommitted local changes* to `src/esbmc/bmc.cpp` and
> `src/goto-symex/symex_target_equation.cpp` in the working tree it came from.
> The verdicts and violated properties below are robust to that, and were
> cross-checked against the previous `cf6a8d56f9` run, but the exact VCC counts
> are not reproducible from the pinned commit alone. Re-run against a clean
> build before quoting the numbers anywhere they matter.

---

## Disclosure and upstream status

Both defects were reported to AWS Security on **2026-07-29** under coordinated
disclosure. On **2026-08-12** AWS published a GitHub advisory and a CVE record
for each, plus [Security Bulletin 2026-080-AWS](https://aws.amazon.com/security/security-bulletins/2026-080-aws/),
crediting Lucas Carvalho Cordeiro and Rafael Sa Menezes of the University of
Manchester:

| Here | Advisory | CVE | CWE | CVSS 3.1 | CVSS 4.0 |
|---|---|---|---|---|---|
| **B-1** heap overflow (WRITE) | [GHSA-wxx3-prfc-69xx](https://github.com/aws/aws-sdk-cpp/security/advisories/GHSA-wxx3-prfc-69xx) | [CVE-2026-19642](https://www.cve.org/CVERecord?id=CVE-2026-19642) | CWE-787 | 5.9 medium (`AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H`) | 6.0 medium |
| **B-2** out-of-bounds READ | [GHSA-mxm9-xpf9-x66x](https://github.com/aws/aws-sdk-cpp/security/advisories/GHSA-mxm9-xpf9-x66x) | [CVE-2026-19643](https://www.cve.org/CVERecord?id=CVE-2026-19643) | CWE-125 | 5.3 medium (`AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H`) | 6.0 medium |

Amazon (AMZN) is the assigning CNA for both. All three channels give the
affected range as `<= 1.11.861` — which contains the 1.11.850 tree analysed
here — fix it in **[1.11.862](https://github.com/aws/aws-sdk-cpp/releases/tag/1.11.862)**
(tagged 2026-08-03), and state that no configuration or runtime option avoids
either issue, so upgrading is the only remedy. AWS notes that remote code
execution has not been demonstrated for B-1.

The CVE record for B-2 is titled "Out-of-bounds read in the Base64 decoder in
Amazon aws-sdk-cpp **on signed-char platforms**", which is the same scoping the
"Is it real?" discussion below arrives at independently: the defect is real
where `char` is signed and benign where it is not.

**The fix is a replacement, not a repair.**
[PR aws/aws-sdk-cpp#3882](https://github.com/aws/aws-sdk-cpp/pull/3882)
(`8eeac049c3`, merged 2026-08-03) deletes the hand-written codec and forwards
`Encode`, `Decode` and both length calculations to `Aws::Crt::Base64*` in the
[AWS Common Runtime](https://github.com/awslabs/aws-crt-cpp) — 126 lines of
index arithmetic deleted from `Base64.cpp`, 26 lines of forwarding added.
Neither minimal patch suggested below was taken; both defects are removed along
with the code that carried them. Both advisories add that consumers who vendor
or statically link the SDK must confirm their build picks up the updated
`aws-crt-cpp` submodule, not only the updated SDK sources.

That PR also adds `TestBase64DecodeNeverWritesMoreThanCalculatedLength`
(`tests/aws-cpp-sdk-core-tests/utils/HashingUtilsTest.cpp`), asserting
`Base64Decode(input).GetLength() <= CalculateBase64DecodedLength(input)` over
`"AAAA="`, `"AAAAA="`, `"AAAAAA="`, `"AAAAAAA="` and every byte `0x80`-`0xFF`
prefixed to `"AAA"` — the B-1 and B-2 triggering classes respectively.

**On reachability**, both advisories state that "the decoder is reachable from
the generated C++ service clients, which use it for a variety of features."
That is the vendor's assertion, and it settles the question for practical
purposes; it is not an independent result of this exercise. The caveat under
"Is it real?" below still describes what was checked *here* — this repo's sparse
`vendor/` checkout contains no generated client, so no caller was enumerated
locally.

`vendor/` deliberately stays pinned at the vulnerable 1.11.850 tree: every
harness and every verdict below is a statement about pre-fix code, and updating
it to 1.11.862 would silently turn the confirmations into non-reproductions.

---

## Summary

Two memory-safety defects were found in `Base64::Decode`, both reachable from
untrusted input through a public API that performs no validation of its
argument:

| # | Defect | Effect | Trigger |
|---|--------|--------|---------|
| **B-1** (CVE-2026-19642) | Output buffer sized by one rule, written by another | **Heap buffer overflow (WRITE)**, 1 byte past the allocation | `"AAAA="`, `"AAAA=="`, `"AAAAAAAA="` — any input whose length is not a multiple of 4 and which ends in `'='` |
| **B-2** (CVE-2026-19643) | `char` sign-extended before indexing a 256-entry table | **Wild out-of-bounds READ** → SEGV | any byte ≥ `0x80`, e.g. `\xFF\xFF\xFF\xFF` |

Both were **confirmed with a concrete reproducer under AddressSanitizer**, not
merely predicted. Neither is an artefact of an under-constrained harness — see
"Is it real?" below.

ESBMC's C++ frontend **did not originally ingest the target**. Eight distinct
gaps in its C++ operational model were found and worked around, after which
ESBMC **aborted during GOTO conversion** on `Aws::Utils::Array<unsigned char>`.
Details in "ESBMC frontend results".

**Five issues were filed against ESBMC along the way, and all five are now
closed:**

| Issue | What it was | Closed by |
|---|---|---|
| [#6183](https://github.com/esbmc/esbmc/issues/6183) | C++ OM missing `type_traits`, `unique_ptr`, `basic_string` members | [#6190](https://github.com/esbmc/esbmc/pull/6190) |
| [#6184](https://github.com/esbmc/esbmc/issues/6184) | SIGABRT in GOTO conversion — placement new with no initializer | [#6195](https://github.com/esbmc/esbmc/pull/6195) |
| [#6199](https://github.com/esbmc/esbmc/issues/6199) | Spurious `basic_string overflow` before `Decode` is reached | [#6225](https://github.com/esbmc/esbmc/pull/6225) |
| [#6207](https://github.com/esbmc/esbmc/issues/6207) | Generated CTest case did not compile | [#6209](https://github.com/esbmc/esbmc/pull/6209) |
| [#6208](https://github.com/esbmc/esbmc/issues/6208) | Generated `CMakeLists.txt` omitted the TU defining `main` | [#6210](https://github.com/esbmc/esbmc/pull/6210) |

Consequently **the harnesses now carry no workarounds at all**, and the
generated `model/` tree — upstream `Array.h` with `CryptoBuffer` cut out, the
last deviation between what upstream ships and what ESBMC saw — has been deleted
along with the script that produced it. Everything below is measured against
pristine `vendor/` sources. Full history in
[ESBMC_FIX_PLAN.md](ESBMC_FIX_PLAN.md).

**With those in place, both defects are now independently confirmed by ESBMC**,
no longer resting on AddressSanitizer alone:

| Run | Verdict |
|---|---|
| B-1, concrete `"AAAA="` | `VERIFICATION FAILED` — `assertion index < m_length` in `Array::GetItem` (`vendor/include/aws/core/utils/Array.h:208`), after `allocationSize = 2` |
| B-1, symbolic, RFC 4648 alphabet only | `VERIFICATION FAILED` — same property |
| B-2, concrete `\xFF\xFF\xFF\xFF` | `VERIFICATION FAILED` — `dereference failure: Access to object out of bounds` at `Base64.cpp:103` |
| B-2, symbolic, unconstrained bytes | `VERIFICATION FAILED` — same property at `Base64.cpp:104` |

The two symbolic modes separate the defects cleanly: constrained to the base64
alphabet the harness finds B-1, and with bytes unconstrained it finds B-2 first,
since a high-bit byte is reachable sooner than the length arithmetic.

The symbolic B-2 lands on line 104 rather than 103 because those are the *same
defect at a different byte position*: lines 103-106 are the four decoding-table
lookups `value1`..`value4` of one block, all with the same sign-extended index,
and the solver's witness happens to put the high-bit byte second. The concrete
case, whose four bytes are all `0xFF`, faults at the first lookup. Nothing
distinguishes the four lines but which byte the caller supplied.

Both counterexamples have since been turned into **executable tests** with
ESBMC's [CTest generation](https://esbmc.github.io/docs/c-cpp/ctest-gen/) and
replayed against a native ASan build, where both crash — see "From
counterexample to executable test" below. Neither defect now rests on reading a
solver trace.

The alphabet-constrained run is the stronger result: it says the overflow
follows from the length arithmetic itself, over *every* input of length < 7
drawn from the base64 alphabet, not just the three hand-picked strings ASan was
pointed at. That B-2 falls out of the unconstrained mode without being asked for
is the corresponding statement for the sign-extension defect.

⚠️ **`--unwind` is load-bearing.** `Base64::Base64()` fills a 256-entry decoding
table via `memset(256)` plus a 64-iteration loop. Under a small `--unwind` those
loops are truncated, every byte maps to `SENTINEL_VALUE`, the `value3`/`value4`
guards skip both inner writes, and ESBMC reports **`VERIFICATION SUCCESSFUL` on
a program that overflows**. The Makefile's original `--unwind 8` produced exactly
that false negative; it is now 300. Tell-tale of a vacuous run: ~100 VCCs where
a real one generates ~18000.

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
   public. That wrapper is a bare pass-through — its whole body is
   `return s_base64.Decode(encodedMessage);` — so it adds no validation
   between an SDK consumer and the defect. Both are exported API that an SDK
   consumer may call on data of their choosing.

   **Correction — the one call site this report used to name is not a
   caller.** Earlier revisions cited `PrecalculatedHash.cpp:15`
   (`Base64Decode(hash.c_str())`) as the concrete in-tree caller. It is not.
   That translation unit opens with `using namespace Aws::Crt;`, and the call
   is *unqualified*. `HashingUtils::Base64Decode` is a static class member, so
   unqualified lookup can never find it — `PrecalculatedHash` derives from
   `Hash`, not from `HashingUtils`, and there is no using-declaration. The name
   binds instead to the namespace-scope
   `Aws::Crt::Base64Decode(const String&) -> Vector<uint8_t>`
   (`aws/crt/Types.h:70`), i.e. the aws-c-common decoder, a different
   implementation entirely. The next line settles it independently:
   `decoded.data()` / `decoded.size()` are `Crt::Vector` members;
   `Aws::Utils::ByteBuffer` exposes `GetUnderlyingData()` / `GetLength()`
   (`Array.h:222,232`) and would not compile there.

   The claim survives on reasons 1, 2 and the `HashingUtils.cpp:40` half of
   this one — but the SDK-side caller set lives in the generated service
   clients, which are **not** in this repo's 12-file sparse `vendor/`
   checkout and were therefore never enumerated here. Treat "reachable from
   public API" as established and "here is who calls it in practice" as
   unverified *locally* — AWS's advisories now state that the decoder is
   reachable from the generated service clients (see "Disclosure and upstream
   status"), which answers the question on the vendor's authority rather than
   on evidence in this repo.

   Note on provenance: `HashingUtils.cpp`, `PrecalculatedHash.{h,cpp}` and
   `aws/crt/Types.h` are all absent from `vendor/`, so none of these
   references can be checked locally. They were verified by fetching each
   file at the pinned commit `95988ca5` (aws-crt-cpp from `main`) and reading
   the bodies. The earlier error came from confirming that a line of text
   existed without confirming what the name on it bound to.

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
the same code is benign, as it is under `-funsigned-char`. AWS scoped
CVE-2026-19643 the same way, down to the title — "… **on signed-char
platforms**".

This is where the symbolic run earns its keep. Re-running `make asan` on
arm64 macOS reports `ok` for all four high-bit inputs — the wild address happens
to be mapped there, so nothing faults and the sanitizer sees nothing. ESBMC
flags the same inputs on the same machine, because it reasons about the declared
bound of a 256-entry array rather than waiting for an unmapped page. A sanitizer
finds a defect only where the platform happens to punish it; the bounds argument
holds regardless. On x86_64 Linux the platform *does* punish it: the 2026-07-20
re-run of `make asan` reports `ERROR: AddressSanitizer: SEGV` for all four
high-bit inputs (`0xffffffff`, `0x80414141`, `0xe9e9e9e9`, `0x41414180`), so on
the SDK's most common server platform the defect faults concretely as well as
symbolically.

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

**Upstream took neither.** 1.11.862 replaces the whole implementation with the
AWS Common Runtime's, so both defects go away with the arithmetic that produced
them — see "Disclosure and upstream status".

---

## From counterexample to executable test

A counterexample is a claim about the *model*. The question it leaves open is
whether the input it names is real — whether a process fed exactly those bytes
crashes. ESBMC's `--generate-ctest-testcase`
([docs](https://esbmc.github.io/docs/c-cpp/ctest-gen/)) closes that gap: it
emits `test_case.cpp` holding concrete `__VERIFIER_nondet_*` implementations
that replay the counterexample's values in trace order. Linking those against a
*native* ASan build of the same harness — no ESBMC, no operational model, real
libstdc++ `std::string`, real allocator — executes the exact input the solver
chose. `make testgen`.

| Defect | Counterexample ESBMC chose | Native replay |
|---|---|---|
| **B-1** (alphabet mode) | `len = 5`, bytes `{122,122,89,47,61,...}` = **`"zzY/="`** | `heap-buffer-overflow`, WRITE at `Base64.cpp:115` |
| **B-2** (unconstrained) | `len = 4`, bytes `{0x3c,0xbd,0x3d,0x3d}` — high-bit byte second | `SEGV`, READ at `Base64.cpp:104` |

Both replays crash at the same source lines the symbolic runs indicted, and
each prints the input it reconstructed (`replay: input=7a7a592f3d len=5`) so
the table above is checkable rather than asserted. Two things are worth drawing
out:

* **The solver picks the witness, not the test author.** `"zzY/="` is not in
  the hand-written `ASAN_CASES` table. It is the same structural class as
  `AAAA=` — length 5, one trailing pad — so the novelty is not the byte
  values; it is that the alphabet-mode run *bounds the triggering set* and then
  returns a member of it, rather than confirming three strings someone guessed.
  That is the difference between a test suite and a proof.

  The witnesses are not stable across runs, and should not be quoted as if they
  were: an earlier revision of this table recorded `"yy/x="` and a length-6 B-2
  input beginning `0x80`, from the same harnesses under the previous ESBMC
  build. Widening the input space (see below) changed which member of the
  triggering set the solver returns. What is stable is the *set*, and the source
  line each member faults at.
* **The harness assumptions are checked at replay time, not assumed.** Under
  `ESBMC_REPLAY` every `__ESBMC_assume` becomes a hard `abort()` (not
  `assert()` — the replay is built `-DNDEBUG` for release semantics, which
  would compile `assert` out). So the B-1 replay would abort rather than crash
  if the counterexample contained a byte outside the RFC 4648 alphabet.
  Verified by tampering: substituting `0x01` for the first byte produces
  `replay: assumption violated: (c >= 'A' && c <= 'Z') || ...` and no
  overflow. The guard is live, so the crash is a genuine alphabet-only input.

### What `make testgen` will and will not accept

A confirmation target that cannot fail is decoration. This one fails unless all
four hold, and each failure path was exercised rather than assumed:

| Guard | Failure exercised by |
|---|---|
| A test case was generated at all (also kills the stale-artefact path — the case directory is `rm -rf`'d first) | `make testgen ESBMC=false` → `FAIL: no test case generated` |
| The generated `char` array holds exactly `MAXLEN` entries | injected 8th entry → `FAIL: char array has 8 entries` |
| No `replay: assumption violated` | tampered first byte → abort, no overflow |
| Frame `#0` is the expected `Base64.cpp` line, not merely *some* crash | asserting line 999 → `FAIL: crashed away from Base64.cpp:999` |

The fourth guard fired for real on the 2026-07-28 re-run, which is the best
evidence it is not decoration: with the input space widened, B-2's witness moved
from the `value1` lookup to `value2` and the target failed with
`crashed at Base64.cpp:104, expected 103`. The guard was then widened to accept
any of the four table lookups (103-106) — the four lines that *are* the defect —
and no further, so a crash at the B-1 stores (109/112/115) or anywhere else in
the file still fails the target.

The third guard matters because `abort()` raises no `ERROR: AddressSanitizer:`
line — without an explicit check, the most dangerous outcome would have been
the quietest. The fourth matters because UBSan does not halt by default, so a
UB-only finding would otherwise read as a clean exit.

The `MAXLEN` count guard pins an assumption ESBMC does not guarantee:
`ctest.cpp:370-380` emits one array per C type, filled in trace order from
*every* nondet in the counterexample, not only the harness's — the generated
`int` and pointer arrays are proof, since the harness makes no such calls. One
stray `char`-typed nondet ahead of the loop would shift every replayed byte by
one and still produce a crash: a false confirmation.

### Two defects in ESBMC's test-case generator

Both were worked around in the Makefile; neither blocked the result. Both are
now **fixed upstream**: [#6207](https://github.com/esbmc/esbmc/issues/6207) by
[PR #6209](https://github.com/esbmc/esbmc/pull/6209) and
[#6208](https://github.com/esbmc/esbmc/issues/6208) by
[PR #6210](https://github.com/esbmc/esbmc/pull/6210). **Both workarounds have
since been deleted from the Makefile** rather than kept as no-ops, and the
generated artefacts were re-inspected against the current build to confirm the
fixes are doing what they claim: the emitted arrays are east-const
(`static char const v[]`, `static void* const v[]`) and the generated
`CMakeLists.txt` now names both TUs by absolute path.

1. **The generated C++ test case does not compile**
   ([#6207](https://github.com/esbmc/esbmc/issues/6207), **fixed** by
   [PR #6209](https://github.com/esbmc/esbmc/pull/6209)). The nondet-pointer stub was
   emitted as `static const void* v[] = { 0 }; return v[i++];` from a function
   returning `void*` (`src/goto-symex/ctest.cpp:378`, with `c_type` `"void*"`
   from line 167). `const` + `void*` composes to *array of pointer to const
   void*, so the `return` drops a qualifier: a hard error in C++, and in C a
   constraint violation that GCC diagnoses as a warning by default and an
   error under `-pedantic-errors`. Any counterexample containing a nondet
   pointer is affected — both of ours are. #6209 emits the declaration in
   **east-const** form — `static void* const v[]`, binding `const` to the
   array element rather than the pointee — which is identical for every scalar
   spelling, so the generated case now compiles unmodified. The change applies
   to *every* nondet table, not just pointers: the `char` array is now
   `static char const v[]` too, so the `testgen` target's count-check regex was
   widened to accept both spellings, and its `void*` `sed` rewrite — a no-op
   against a post-#6209 build — has been deleted.
2. **The generated `CMakeLists.txt` omits the file defining `main`**
   ([#6208](https://github.com/esbmc/esbmc/issues/6208), **fixed** by
   [PR #6210](https://github.com/esbmc/esbmc/pull/6210)). It emitted
   `add_executable(test_case <src> test_case.c)` where `<src>` came from
   `ctest.cpp:342` reading the `input-file` option — which, since `optionst`
   stores options in a `map<string,string>`, only ever held the *last*
   positional argument, not the entry-point TU. Given `esbmc main.c helper.c`,
   the generated target listed `helper.c` and the documented `cmake … && ctest`
   flow died at link with `undefined reference to 'main'`. Here it failed even
   earlier: the name was written bare while the `CMakeLists.txt` lands in the
   output directory, so CMake reported "Cannot find source file" at generate
   time. #6210 reads the full input list from `configt::args` and emits
   absolute paths, so the generated project now names every TU and configures
   even when ESBMC did not run in the sources' own directory. We compile the
   replay directly regardless, so the `testgen` target is unaffected — the fix
   makes the documented `cmake … && ctest` flow usable, which our flow bypasses.

Not a defect, but worth recording because it silently broke this target once:
current ESBMC writes the generated files into an **`esbmc-ctest/`
subdirectory** by default rather than the working directory, and there is now a
`--ctest-output-dir <dir>` option to control it. The symptom of not knowing that
is `FAIL: no test case generated` on a run that in fact generated one perfectly
well. The Makefile pins `--ctest-output-dir .`.

---

## ESBMC frontend results

The first question asked was whether ESBMC's C++ frontend ingests the target at
all. **Originally it did not.** Everything in this section is the record of what
blocked it; all of it is now fixed upstream except the `std::allocate_shared`
half of gap 8. Kept because it is the evidence behind the filed issues, and
because anyone running against an older ESBMC will hit it again.

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
| 8a | `std::shared_ptr` — absent entirely | `AWSAllocator.h:105` | **fixed upstream** (#6403) |
| 8b | `std::allocate_shared` — absent entirely | `AWSAllocator.h:117` | **still open** — parse-only declaration in the shim |

Gaps 1-7 were closed by [PR #6190](https://github.com/esbmc/esbmc/pull/6190),
merged 2026-07-19, which closed issue #6183. Gaps 6 and 7 are member functions
of OM types and could not have been fixed from outside the tool at all, which
is why they drove the upstream issue.

That fix was **confirmed end-to-end here**: with `stubs/esbmc_compat.h`
entirely disabled, the only parse errors that remained were `shared_ptr` and
`allocate_shared`. The shim shrank to `shared_ptr` alone and the Makefile gate
was renamed `ESBMC_OM_MISSING_TRAITS` → `ESBMC_OM_MISSING_SHARED_PTR`. The
rename was forced rather than cosmetic: against a #6190 build, shimming the
traits is a redefinition error.

Gap 8 was deliberately left out of #6190 — reference counting, aliasing
constructors, `weak_ptr` and `enable_shared_from_this` need a real model, not a
header addition. **Half of it has since landed anyway**:
[PR #6403](https://github.com/esbmc/esbmc/pull/6403), "[om] Model shared_ptr,
weak_ptr and make_shared", supplies a real reference-counted `shared_ptr` — not
the declaration-only placeholder this repo proposed as an interim step. The
hand-written `shared_ptr` was therefore deleted from the shim, and the same
forced-rename happened a second time: `ESBMC_OM_MISSING_SHARED_PTR` →
`ESBMC_OM_MISSING_ALLOCATE_SHARED`.

**What #6403 did not add is `std::allocate_shared`**, which is the name
`AWSAllocator.h:117` actually calls. Its absence is a *parse* error, not a link
error — with no declaration the name is not a template, so clang reads the `<`
in `std::allocate_shared<T, Aws::Allocator<T>>` as less-than and reports
`'T' does not refer to a value`. That is why an uninstantiated function template
is enough to block the whole translation unit, and it is the last thing standing
between this repo and an unshimmed run. The remaining shim is one declaration
with no definition, so a harness that ever genuinely reaches `allocate_shared`
fails at link time rather than verifying against an allocator-blind
substitute.

Reproducer: `esbmc_bug_repros/om_allocate_shared.cpp` — no AWS headers, accepted
by `g++ -fsyntax-only`, and pinned by `make repros`. Not yet filed upstream.

A ninth gap surfaced only once the crash was fixed and the harnesses could
actually run — `basic_string(const char*, size_t)` asserting `n < strlen(s)`,
described under "Blocked again, one layer up" below. It is a false positive
rather than a missing member, which is why it could not be found until
something reached it. It is now fixed by
[PR #6225](https://github.com/esbmc/esbmc/pull/6225).

Also observed but not blocking: `std::basic_string::size()` returns `int`
rather than `size_type`, which is **still unfixed** (`src/cpp/library/string:1753`)
and is wrong for any string longer than `INT_MAX` as well as in template
deduction.

The other item that used to sit here — OM `unique_ptr`'s destructor `#if 0`-ed
out with "TODO: fix remove goto sideeffect", meaning the model never released —
**has been fixed**; both specialisations now call `deleter(ptr)`. That warning
mattered, because it made `--memory-leak-check` report passes it had not earned
on any C++ target using `unique_ptr`, so its retirement was checked rather than
assumed. Mutation test, both directions: a raw `new` with no `delete` reports
`dereference failure: forgotten memory`, and the same allocation held in a
`unique_ptr` reports `VERIFICATION SUCCESSFUL`. The flag is usable again. This
repo still does not pass it — these harnesses assert memory safety, not
ownership — but no longer because it would be meaningless.

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
successfully — a since-deleted script, `scripts/make_model_headers.sh`, did
that mechanically into a generated `model/` tree — but constructing an
`Array<unsigned char>` still crashes, because that is the path that reaches
`NewArray`.

**Fixed** by [PR #6195](https://github.com/esbmc/esbmc/pull/6195) (merged
2026-07-19): the C++ frontend no longer emits a `comma` for an
initializer-less `CXXNewExpr` — the value of `new (p) T;` is just the placement
address — and `adjust_comma` gains an explicit `operands().size() == 2` assert
so that any other producer of a malformed comma fails loudly instead of reading
out of bounds. Two regression tests ship with it under
`regression/esbmc-cpp/cpp/placement_new_no_init{,_fail}/`.

Verified here against a build carrying both #6190 and #6195:
`placement_new_no_init.cpp` returns `VERIFICATION SUCCESSFUL`, and so does
`make smoke` — the acceptance criterion this repo set for the crash, since it
means `Aws::Utils::Array<unsigned char>` now converts and symexes.

**The stronger check has since been done too.** `make smoke` passed against the
*generated* `Array.h`, with `CryptoBuffer` cut out — so it showed the crash was
gone from the `NewArray` path, not that the header which originally triggered it
was ingestible. Pointing every ESBMC target at pristine
`vendor/include/aws/core/utils/Array.h`, `CryptoBuffer` and all, now converts,
symexes and reports B-1 at `Array.h:208`. The `model/` tree and the script that
generated it have been deleted: there is no longer any deviation between what
upstream ships and what ESBMC analyses.

`crash_goto_convert_array.cpp` also converts now, and reaches the solver. Left
to itself it reports `VERIFICATION FAILED` for an unrelated reason:
`Aws::NewArray` (`AWSMemory.h:166-171`) does not check `Malloc`'s result before
casting and placement-newing into it, so on the allocation-failure path
`Array::operator[]` dereferences null. That is an allocation-failure property,
not the crash and not B-1 — most verification setups assume allocation
succeeds, so the Makefile passes `--force-malloc-success` and the reproducer
reports `VERIFICATION SUCCESSFUL`. Recorded here so that neither verdict is
mistaken for the crash persisting.

### One layer up: `basic_string(const char*, size_t)` — #6199, now fixed

With the crash gone, `make esbmc` ran the symbolic harnesses for the first
time. Both modes initially terminated with `VERIFICATION FAILED` — but on a
**spurious property inside ESBMC's own string model**, not inside `Decode`:

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
It is a **false positive**, so it does not threaten soundness.

Filed as [esbmc/esbmc#6199](https://github.com/esbmc/esbmc/issues/6199), which
also reports two further defects in the same constructor found while reducing
it: the copy loop stops at embedded nulls while `_size` is already `n`, so a
value containing one is silently truncated while `length()` still reports `n`
(confirmed by removing the assertion locally and re-running); and the `strlen`
assertion is evaluated before the `s != NULL` check below it.

**Was worked around; now reverted.** Unlike the crash, this one could be
side-stepped from the harness, and two constraints did that:

* `__ESBMC_assume(len < MAXLEN)` rather than `<=` in
  `base64_decode_harness.cpp`, plus a trailing filler byte in the string
  literals of `base64_decode_concrete.cpp`, so the backing array always held a
  spare byte. Those filler bytes were **not** part of the input under test — the
  explicit length excluded them.
* `__ESBMC_assume(c != '\0')` on each symbolic byte. A spare byte alone was not
  enough once bytes are unconstrained: an interior NUL shortens `strlen(raw)`
  and tripped the same bogus precondition.

**[PR #6225](https://github.com/esbmc/esbmc/pull/6225) landed on 2026-07-22 and
both are gone.** The constructor now checks `s != NULL` first, checks `n`
against the model's capacity, and copies exactly `n` characters with no `strlen`
anywhere — so embedded nulls survive and `n == strlen(s)` is unremarkable. The
symbolic harness is back to `len <= MAXLEN` over a genuinely unconstrained byte
range, and the concrete harness's literals are exactly the inputs under test.

That matters for what the ANY_BYTE mode now claims. `c != '\0'` was the
narrowest constraint that kept the mode meaningful, but it *was* a constraint:
the mode explored every byte value except one. It now explores all 256, and the
input space grew accordingly — 18186 VCCs before, 19737 after. B-2 still falls
out of it, and the run's witness moved to a different byte position as a result.

**Consequence for this exercise:** the symbolic proof is obtained, with no
harness workarounds behind it. See the verdict table in the Summary. B-1 and B-2
no longer rest on the ASan reproducers alone; the alphabet-constrained run
bounds the set of triggering inputs rather than merely exhibiting three of them.

Order of blockers, for the record: OM members missing (#6183) → GOTO conversion
crash (#6184) → spurious `basic_string overflow` (#6199) — all three now fixed.
Each was only discoverable once the previous one was cleared, which is the
ordinary shape of bringing a real codebase under a verifier for the first time.
Nothing appeared behind the third.

### Issues filed against esbmc/esbmc

* **[esbmc/esbmc#6183](https://github.com/esbmc/esbmc/issues/6183)** —
  **CLOSED.** C++ OM missing `type_traits`, `unique_ptr`, `basic_string` and
  `shared_ptr` members. Reproducers: `esbmc_bug_repros/om_*.cpp`. Fixed by
  [PR #6190](https://github.com/esbmc/esbmc/pull/6190), merged 2026-07-19, with
  five regression tests under `regression/esbmc-cpp/cpp/github_6183*`.
  `shared_ptr` was deliberately excluded; it was modelled later and separately by
  [PR #6403](https://github.com/esbmc/esbmc/pull/6403), which left
  `allocate_shared` — the name this target actually calls — still missing.
* **[esbmc/esbmc#6184](https://github.com/esbmc/esbmc/issues/6184)** —
  **CLOSED.** SIGABRT during GOTO conversion on `ByteBuffer`, with
  varying glibc pthread assertions. Cause: unguarded `op1()` in `adjust_comma`
  against the one-operand `comma` that placement-new-without-initializer
  produces. Fixed by [PR #6195](https://github.com/esbmc/esbmc/pull/6195).
  Reproducers: `esbmc_bug_repros/placement_new_no_init.cpp` (minimal, no AWS
  headers) and `esbmc_bug_repros/crash_goto_convert_array.cpp` (end-to-end;
  needs #6190 to get far enough to crash).
* **[esbmc/esbmc#6199](https://github.com/esbmc/esbmc/issues/6199)** —
  **CLOSED** by [PR #6225](https://github.com/esbmc/esbmc/pull/6225), merged
  2026-07-22. `basic_string(const char*, size_t)` asserted `n < strlen(s)`,
  rejecting the canonical `std::string("abc", 3)` and contradicting
  [string.cons]; the copy loop also truncated at embedded nulls, and `strlen`
  was evaluated before the null check. All three are addressed: the constructor
  now null-checks first and copies exactly `n` characters with no `strlen`.
  Reproducer: `esbmc_bug_repros/om_string_ptr_len_ctor.cpp`, which now reports
  `VERIFICATION SUCCESSFUL`. The harness workarounds it forced have been
  reverted.
* **[esbmc/esbmc#6207](https://github.com/esbmc/esbmc/issues/6207)** —
  **CLOSED** by [PR #6209](https://github.com/esbmc/esbmc/pull/6209).
  `--generate-ctest-testcase` emitted `static const void* v[]` returned from a
  `void*` function, so any counterexample with a nondet pointer produced a test
  case that did not compile. #6209 switches the emitted declaration to
  east-const (`static void* const v[]`) for every scalar type, with two
  `CHECK_FILE` regression tests under
  `regression/witnesses/test_case_generation/ctest_gen_pointer{,_cpp}`. The
  `testgen` target's workaround has been deleted.
* **[esbmc/esbmc#6208](https://github.com/esbmc/esbmc/issues/6208)** —
  **CLOSED** by [PR #6210](https://github.com/esbmc/esbmc/pull/6210).
  The generated `CMakeLists.txt` named only the last input file (the
  `map<string,string>`-backed `input-file` option retained only the last
  positional argument), omitting the TU that defines `main`, so the documented
  `cmake && ctest` flow failed. #6210 reads the full list from `configt::args`
  and emits absolute paths, with C and C++ two-TU regression tests under
  `regression/witnesses/test_case_generation/ctest_gen_multifile{,_cpp}`. We
  compile the replay directly, so the `testgen` target never depended on it.

---

## Reproducing

```bash
make confirm  # ESBMC on the two named defect inputs   -> both VERIFICATION FAILED
make esbmc    # ESBMC over the symbolic harnesses      -> VERIFICATION FAILED
make testgen  # counterexamples -> executable tests    -> both crash under ASan
make smoke    # ESBMC frontend/OM smoke test           -> VERIFICATION SUCCESSFUL
make repros   # the filed ESBMC reproducers            -> see below
make asan     # independent ASan cross-check
```

`VERIFICATION FAILED` from `confirm` and `esbmc` is the expected, desired result
— it is the confirmation.

Under `repros`, the five reproducers for **filed** issues are now expected to
report `SUCCESSFUL`, since every issue they pin is fixed; a `FAILED` there means
an ESBMC regression or a build predating the fixes. The sixth,
`om_allocate_shared.cpp`, is expected to stop at `ERROR: PARSING ERROR` — it
pins the one gap that remains, and when it starts parsing, the shim and the
`-D` that gates it can both be deleted and this repo needs no compatibility
layer at all.

The ESBMC targets need a build carrying #6190, #6195, #6209, #6210 and #6225;
`make asan` requires only a C++ compiler.

**Last re-run: 2026-07-28, x86_64 Linux, ESBMC `8d3cee251a` (see the provenance
caveat at the top).** Every target green, against pristine `vendor/` headers with
no harness workarounds:

| Target | Result |
|---|---|
| `smoke` | `VERIFICATION SUCCESSFUL` (18302 VCCs) |
| `confirm` | FAILED on both inputs — B-1 `index < m_length` at `Array.h:208` (18252 VCCs); B-2 out-of-bounds read at `Base64.cpp:103` (18247 VCCs) |
| `esbmc` | FAILED on both modes (19737 VCCs each) — ALPHABET on B-1 at `Array.h:208`, ANY_BYTE on B-2 at `Base64.cpp:104` |
| `testgen` | B-1 `"zzY/="` → `heap-buffer-overflow` at `Base64.cpp:115`; B-2 `3cbd3d3d` → `SEGV` at `Base64.cpp:104` |
| `repros` | `SUCCESSFUL` on all five filed issues; `om_allocate_shared.cpp` stops at `PARSING ERROR`, as expected |
| `asan` | 3 of 8 overflow under `-DNDEBUG`, same 3 assert in debug, all 4 high-bit inputs SEGV |

The VCC counts are up from the 2026-07-20 run (18164/18152 for `confirm`, 18186
for `esbmc`) for two independent reasons, both intended: reverting the #6199
workarounds widened the symbolic input space, and dropping the `model/` tree put
`CryptoBuffer` back into the translation unit. The earlier `cf6a8d56f9` run and
the arm64 macOS run against `d0bb9881f2` agreed on every verdict.
