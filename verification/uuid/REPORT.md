# ESBMC/ASan vs. aws-cpp-sdk-core `UUID` — findings

**Target:** `aws/aws-sdk-cpp` @ `c84017197daa00de9cc05b1166e9106e1079f7f3` (v1.11.869, the
current release at the time of writing)
**Function under analysis:** `Aws::Utils::UUID::UUID(const Aws::String&)`
(`src/aws-cpp-sdk-core/source/utils/UUID.cpp:34-44`)
**Cross-check:** GCC + AddressSanitizer/UBSan (`make asan`)
**Status:** ASan-confirmed on 1.11.869. Reachability enumerated against the full
SDK tree — no untrusted-input caller of the string constructor exists (see
"Reachability"), so U-1 is a latent hardening bug, not a remotely triggerable
one. ESBMC symbolic harness is the remaining next step (see "Open items").

---

## Summary

`UUID(const Aws::String&)` copies a decoded byte string into a fixed 16-byte
member with a `memcpy` whose length is derived from the *input* length, guarded
only by `assert`s that vanish under `NDEBUG`:

| # | Defect | Effect | Trigger |
|---|--------|--------|---------|
| **U-1** | Output copied into `m_uuid[16]` with a length taken from the input, not the buffer | **Heap/stack buffer overflow (WRITE)**, up to input-length/2 − 16 bytes past the allocation | any string whose de-dashed hex body exceeds 32 characters, e.g. a UUID-shaped `8-4-4-4-16` string, or a bare 40-hex-char string |

Confirmed with a concrete reproducer under AddressSanitizer against
byte-for-byte upstream `UUID.cpp` — not merely predicted.

## U-1 — Buffer overflow in the UUID string constructor

### The defect

`UUID.cpp:34-44`:

```cpp
Aws::Utils::UUID::UUID(const Aws::String& uuidToConvert)
{
    assert(uuidToConvert.length() == UUID_STR_SIZE);         // 0x24 == 36
    memset(m_uuid, 0, sizeof(m_uuid));                       // m_uuid is unsigned char[16]
    Aws::String escapedHexStr(uuidToConvert);
    StringUtils::Replace(escapedHexStr, "-", "");
    assert(escapedHexStr.length() == UUID_BINARY_SIZE * 2);  // 32
    ByteBuffer&& rawUuid = HashingUtils::HexDecode(escapedHexStr);
    memcpy(m_uuid, rawUuid.GetUnderlyingData(), rawUuid.GetLength());   // line 43
}
```

`m_uuid` is a fixed 16-byte member (`UUID.h:54`). `HexDecode` returns a buffer
of length `floor(hexChars / 2)`, where `hexChars` is the argument length after
`'-'` removal (minus 2 more for an optional `0x`/`0X` prefix). The `memcpy`
copies `rawUuid.GetLength()` bytes into `m_uuid` — so whenever the de-dashed hex
body exceeds 32 characters, more than 16 bytes are written and the copy runs off
the end of the object.

The two `assert`s are the *only* things that constrain the input length, and
[assert.h]/[cassert] compiles them to nothing when `NDEBUG` is defined — i.e. in
any release build of the SDK. There is no runtime length check on the other
side of them.

Worked example, `"12345678-1234-1234-1234-1234567890123456"` (a UUID-shaped
string whose final group is 16 hex chars instead of 12):

```
length 40, four '-' removed        -> escapedHexStr length 36
HexDecode(36 chars)                -> 18-byte ByteBuffer
memcpy(m_uuid /*16*/, ..., 18)     -> writes 2 bytes past a 16-byte allocation
```

### Evidence

`make asan`, release semantics (`-DNDEBUG`, i.e. any release build of the SDK):

```
12345678-1234-1234-1234-123456789012           ok            (canonical, 32 hex -> 16 bytes)
AAAA                                           ok            (2 bytes)
0xAABBCCDD                                     ok            (0x prefix, 4 bytes)
12345678-1234-1234-1234-1234567890123456       heap-buffer-overflow
1234567890123456789012345678901234567890       heap-buffer-overflow   (40 bare hex -> 20 bytes)
0xAABBCCDDEEFF00112233445566778899AABBCCDDEEFF heap-buffer-overflow
```

Full diagnostic for the UUID-shaped over-length input:

```
input_len=40 hex_chars=36 decoded_bytes=18 m_uuid=16  <-- PREDICTED OVERFLOW
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000020
WRITE of size 18 at 0x502000000020 thread T0
    #2 Aws::Utils::UUID::UUID(...) vendor/source/utils/UUID.cpp:43
    #3 Aws::New<Aws::Utils::UUID, ...>(...) vendor/include/aws/core/utils/memory/AWSMemory.h:72
0x502000000020 is located 0 bytes after 16-byte region [0x502000000010,0x502000000020)
allocated by thread T0 here:
    #1 Aws::Malloc(char const*, unsigned long) stubs/aws_memory_stub.cpp:31
```

The bytes written past the allocation are `HexDecode`'s output, i.e. derived
from the caller's string — attacker-influenced data one or more bytes past the
object.

### Debug vs release

Same split as any assert-guarded overflow:

* **Debug build** — the first `assert(uuidToConvert.length() == UUID_STR_SIZE)`
  fires: `Assertion 'uuidToConvert.length() == UUID_STR_SIZE' failed`. A
  controlled crash. `make asan` shows this on the over-length inputs in the
  "debug semantics" block.
* **Release build (`NDEBUG`)** — both asserts are compiled out and the overflow
  is **silent memory corruption**.

The asserts make the defect visible in a debug/test build, which is likely why
it has survived: release is where it bites, and there it is silent.

### Fidelity of the reproducer

Everything ASan analyses is byte-for-byte upstream 1.11.869: the real
`UUID.cpp`, the real `Array.h`/`AWSString.h`/`AWSMemory.h` headers, and the
constructor's two helpers reproduced verbatim — `HashingUtils::HexDecode` and
`StringUtils::Replace` (see `stubs/aws_str_hash_extract.cpp` for why those two
are extracted rather than the whole hashing/crypto subsystem vendored). Only
`HexDecode`'s output *length* matters to the overflow, and that length is a pure
function of the input length regardless of the byte values, so the extract is
faithful for the property under test. The UUID object is heap-allocated in the
harness so the write lands in an allocation with ASan redzones; the same store
off a stack-resident `UUID` is equally out of bounds.

### Is it real, or an under-constrained harness?

The inputs are ordinary strings — no invalid bytes, no fuzzed blobs. The
constructor's contract is "parse a GUID string"; the canonical 36-character form
decodes to exactly 16 bytes and is safe. The defect is that the constructor
*documents* a 36-character precondition (via the assert and the `UUID_STR_SIZE`
comment) but does not *enforce* it in release, and its `memcpy` trusts the
decoded length instead of clamping to `sizeof(m_uuid)`. Any caller that
constructs a `UUID` from a string it did not itself length-check reaches this.

### Suggested fix

Clamp the copy to the destination, and/or reject a non-canonical length at
runtime rather than only under `assert`:

```cpp
if (rawUuid.GetLength() != sizeof(m_uuid)) { /* reject: throw / empty / flagged-invalid */ }
memcpy(m_uuid, rawUuid.GetUnderlyingData(), sizeof(m_uuid));
```

## Reachability

The `vendor/` checkout here contains no callers, so the caller set was
enumerated against the full SDK tree at 1.11.869 (GitHub code search plus
reading each hit). The question is specifically who constructs
`Aws::Utils::UUID` **from a string** — the only constructor that runs the
overflowing `memcpy`; the separate `UUID(const unsigned char[16])` binary
constructor always copies exactly `sizeof(m_uuid)` and is not U-1.

What the caller set looks like:

* **Generation, not parsing.** The in-`core` constructions —
  `AsyncCallerContext` (`PseudoRandomUUID`), `STSCredentialsProvider`,
  `TransferHandle`, `S3ExpressSigner` — all call `RandomUUID()` /
  `PseudoRandomUUID()`. They produce a UUID; they never parse a caller-supplied
  string, so they cannot reach U-1.
* **Wire-sourced UUIDs use the binary constructor.** The event-stream decoder
  path (`EventHeader.h`) turns a UUID-typed header into
  `Aws::Utils::UUID(buffer.GetUnderlyingData())` — the 16-byte binary
  constructor, whose copy length is fixed by the code, not by the header. That
  path does not reach the string constructor.
* **The one string-constructor call site in `core`** is the error branch of
  `EventHeaderValue::GetEventHeaderValueAsUuid()` (`EventHeader.h`), which passes
  a fixed local `char[32] = {0}` — an empty string after decode, so a zero-byte
  copy. Safe, and not attacker-influenced.
* **Generated service clients store UUIDs as `Aws::String`**, not as
  `Aws::Utils::UUID`. The model setters/parsers keep the value as a string; none
  of the model `.cpp` files construct `Aws::Utils::UUID` from a response field.

**Conclusion: no untrusted-input caller of `UUID(const Aws::String&)` exists in
the SDK.** U-1 is a real memory-safety defect in the function, but it is a
latent robustness/hardening bug rather than a remotely triggerable one: the only
way to hit it is for an SDK *consumer* to pass an unvalidated, over-length string
to the public constructor. This is a *negative* result — it hands out no exploit
path — which is why it is recorded in the open rather than withheld. It is
argued from the caller set, not machine-checked; a directed re-scan of any
future release should repeat it.

## Open items

* **ESBMC symbolic harness.** Bound a symbolic `Aws::String` and prove the
  overflow follows from the length arithmetic over a class of inputs, as was
  done for Base64 B-1 — reusing this repo's `ESBMC_OM_MISSING_ALLOCATE_SHARED`
  shim. Not yet built.
* **Disclosure.** Given the negative reachability result above, U-1 does not meet
  the bar that made the Base64 defects coordinated-disclosure cases (reachable
  from untrusted input). It is treated as a public hardening finding. Should a
  future caller parse an untrusted string into `UUID`, revisit: that would make
  it a coordinated-disclosure candidate for AWS Security, not a public issue —
  see the channel rules in the top-level `verification/`.

---

## Reproducing

```bash
cd verification/uuid
make asan     # GCC + ASan/UBSan cross-check; needs only a C++ compiler
```

Over-length inputs report `heap-buffer-overflow` under `-DNDEBUG` and trip the
length assert without it; canonical 36-character UUID strings are `ok` under
both. `make asan` runs both semantics.
