# ESBMC/ASan vs. aws-cpp-sdk-core `UUID` — findings

**Target:** `aws/aws-sdk-cpp` @ `c84017197daa00de9cc05b1166e9106e1079f7f3` (v1.11.869, the
current release at the time of writing)
**Function under analysis:** `Aws::Utils::UUID::UUID(const Aws::String&)`
(`src/aws-cpp-sdk-core/source/utils/UUID.cpp:34-44`)
**Cross-check:** GCC + AddressSanitizer/UBSan (`make asan`)
**Status:** ASan-confirmed on 1.11.869. ESBMC symbolic harness and a
reachability pass are the next steps (see "Open items").

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

## Open items

* **ESBMC symbolic harness.** Bound a symbolic `Aws::String` and prove the
  overflow follows from the length arithmetic over a class of inputs, as was
  done for Base64 B-1 — reusing this repo's `ESBMC_OM_MISSING_ALLOCATE_SHARED`
  shim. Not yet built.
* **Reachability.** Enumerate in-tree callers of `UUID(const Aws::String&)`
  reachable from untrusted input (server responses, headers, user-supplied
  identifiers). The sparse `vendor/` checkout here contains no callers, so this
  is unverified locally — treat "no enforced precondition on a public
  constructor" as established and practical reachability as open, exactly as the
  Base64 report did before AWS confirmed it.
* **Disclosure.** If reachability from untrusted input holds, this is a
  coordinated-disclosure candidate for AWS Security, not a public issue — see
  the channel rules in the top-level `verification/`.

---

## Reproducing

```bash
cd verification/uuid
make asan     # GCC + ASan/UBSan cross-check; needs only a C++ compiler
```

Over-length inputs report `heap-buffer-overflow` under `-DNDEBUG` and trip the
length assert without it; canonical 36-character UUID strings are `ok` under
both. `make asan` runs both semantics.
