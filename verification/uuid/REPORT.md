# ESBMC/ASan vs. aws-cpp-sdk-core `UUID` — findings

**Target:** `aws/aws-sdk-cpp` @ `c84017197daa00de9cc05b1166e9106e1079f7f3` (v1.11.869, the
current release at the time of writing)
**Function under analysis:** `Aws::Utils::UUID::UUID(const Aws::String&)`
(`src/aws-cpp-sdk-core/source/utils/UUID.cpp:34-44`)
**Cross-check:** GCC + AddressSanitizer/UBSan (`make asan`)
**Status:** ASan-confirmed and ESBMC-confirmed on 1.11.869, the two agreeing on
both the release and the debug outcome, with the symbolic counterexample
replayed natively (see "Symbolic confirmation"). Reachability enumerated against
the full SDK tree — no untrusted-input caller of the string constructor exists
(see "Reachability"), so U-1 is a latent hardening bug, not a remotely
triggerable one.

---

## Summary

`UUID(const Aws::String&)` copies a decoded byte string into a fixed 16-byte
member with a `memcpy` whose length is derived from the *input* length, guarded
only by `assert`s that vanish under `NDEBUG`:

| # | Defect | Effect | Trigger |
|---|--------|--------|---------|
| **U-1** | Output copied into `m_uuid[16]` with a length taken from the input, not the buffer | **Heap/stack buffer overflow (WRITE)**, up to input-length/2 − 16 bytes past the allocation | any string whose de-dashed hex body exceeds 32 characters, e.g. a UUID-shaped `8-4-4-4-16` string, or a bare 40-hex-char string |

Confirmed with a concrete reproducer under AddressSanitizer against
byte-for-byte upstream `UUID.cpp` — not merely predicted — and independently by
ESBMC over a symbolic input, which also fixes the boundary: 34 characters is the
shortest string that overflows.

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
123456781234123412345678901234561234           heap-buffer-overflow   (36 hex -> 18 bytes; length 36 PASSES the first assert)
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

* **Debug build** — one of the two asserts fires and the crash is controlled.
  Which one depends on the input, and the difference matters: a string longer
  than 36 characters trips the first,
  `assert(uuidToConvert.length() == UUID_STR_SIZE)`, but a 36-character
  dash-free string passes that one and is caught only by the second,
  `assert(escapedHexStr.length() == UUID_BINARY_SIZE * 2)`. `make asan` shows
  both in the "debug semantics" block.
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

## Symbolic confirmation (ESBMC)

The ASan work above pins U-1 to named inputs. The ESBMC harnesses answer the
next question: does the overflow follow from the length arithmetic over a
*class* of inputs, rather than from the particular strings someone thought to
try?

### Configuration, and why each flag is there

| Flag | Why |
|---|---|
| `--no-assertions` | **Release semantics.** Both length constraints in the constructor are `assert`s. With them live, ESBMC stops at one of them and never reaches the `memcpy` — the debug behaviour, kept as its own target (`make esbmc-debug`). Bounds and pointer checks are unaffected. |
| `--unwind 40`, unwinding assertions **on** | 40 covers every real trip count (36-character string loops, 18-iteration `HexDecode` and copy loops). Unwinding assertions are left enabled so an inadequate bound surfaces as a violated unwinding assertion instead of a silent false `SUCCESSFUL`. |
| `--unwindsetname …StringUtils@Replace:0:2` | See below. |
| `--force-malloc-success` | Suppresses the allocation-failure counterexample from the `Aws::Malloc` stub, which otherwise masks the defect under test. |

**The one per-loop bound.** `StringUtils::Replace` is
`for (pos = 0;; pos += replaceLength)` with `replaceLength == strlen("") == 0`
— unbounded, exiting only when `find` returns `npos`. ESBMC's OM keeps a
heap-allocated string's contents in a symbolic array, so `find` yields a
symbolic index *even for a fully concrete input*, and symex unrolls the loop to
the global bound with `find`, `erase` and `insert` — seven nested loops — inside
every iteration. At `--unwind 64` that is a >20-minute run past 1 GB of symex
state before the solver is ever reached. Bounding this one loop to 2 brings the
same query to ~3 s of symex.

That bound is an assumption, so it is *checked rather than asserted*: unwinding
assertions stay on, and the control run below returns `SUCCESSFUL` under exactly
these flags. A `SUCCESSFUL` verdict with unwinding assertions enabled is only
possible if every loop bound in the run, this one included, was adequate. This
is why `--no-unwinding-assertions` is not used anywhere here, unlike the Base64
harnesses.

### Results

All runs against byte-for-byte upstream `UUID.cpp`. The concrete pair — the
defect verdict and the control that keeps it non-vacuous — was run under both
Bitwuzla and Z3 and they agree; the rest are Bitwuzla, noted per row.

| Run | Input model | Verdict | Property |
|---|---|---|---|
| `confirm` | 36 hex chars, no dashes (concrete) | **FAILED** (Bitwuzla + Z3) | `dereference failure: Access to object out of bounds`, `allocationSize = 18` |
| `confirm` control | 32 hex chars → exactly 16 bytes (concrete) | **SUCCESSFUL** (Bitwuzla + Z3) | — |
| `esbmc-debug` | same as `confirm`, asserts live | **FAILED** (Bitwuzla) | `assertion escapedHexStr.length() == UUID_BINARY_SIZE * 2` (`UUID.cpp:41`) |
| `esbmc` ANY_LEN | length symbolic in [0, 36], bytes symbolic hex | **FAILED** (Bitwuzla) | out-of-bounds write; witness `len = 36`, 18 bytes decoded |
| `esbmc` CONTRACT | length pinned at 36, bytes symbolic hex | **FAILED** (Bitwuzla) | out-of-bounds write; witness `077777777700777777777777777777777777` |
| `esbmc` ANY_LEN, `MAXLEN=33` | length symbolic in [0, 33] | **SUCCESSFUL** (Bitwuzla) | — |
| `esbmc` ANY_LEN, `MAXLEN=34` | length symbolic in [0, 34] | **FAILED** (Bitwuzla) | out-of-bounds write; witness `8891D54447710000ee7cCd888777777777`, `len = 34` |

### The boundary, machine-checked

The last two rows bracket the defect exactly. `HexDecode` returns an empty
buffer for an odd-length or shorter-than-2 argument and `floor(hexChars / 2)`
bytes otherwise, so 32 characters give exactly 16 bytes — a full `m_uuid` and
still safe — 33 gives nothing, and 34 gives 17. Running the same harness at
`MAXLEN = 33` and `MAXLEN = 34` turns that arithmetic into a checked claim:

* **≤ 33 characters: SUCCESSFUL.** Over *every* dash-free hex string of length 0
  to 33 — not a sample — the constructor is memory-safe. Unwinding assertions
  are on, so this is a real bounded proof rather than a truncated run.
* **≤ 34 characters: FAILED**, with a 34-character witness. 34 is therefore the
  minimal overflowing length, and the failing verdict is not an artefact of
  handing the harness an absurdly long string.

The pair is also what rules out vacuity: the two runs differ only in the length
bound, so the `SUCCESSFUL` one cannot be passing because the harness fails to
reach the code — the identical harness fails one character later.

The `MAXLEN = 33` proof rests on Bitwuzla alone, and not for want of trying: the
same query under Z3 was still running at the 900 s cap (`ERROR: Timed out`) with
3.4 GB resident, against Bitwuzla's 79 s. Finding a counterexample is the easy
direction — every `FAILED` row above lands in seconds to a couple of minutes —
whereas discharging all 1463 remaining VCCs is where the solvers diverge. So the
safety half of the bracket is a single-solver result; the defect half is not.

Both symbolic modes exclude the `0x`/`0X` prefix (`x` is not in the assumed hex
alphabet). That path only *shortens* the decoded body by one byte, so it can
neither create an overflow the model misses nor weaken the ≤ 33 proof.

### What the symbolic runs add over ASan

**The documented precondition is not sufficient.** Every over-length input the
ASan table originally carried was *also* longer than 36 characters, so each one
violates the constructor's first assert — from which a reader could conclude
that a caller who checks `length() == 36`, the one constraint the API documents
(`UUID_STR_SIZE`, and the comment "2 characters per byte + 4 dashes = 36
bytes"), is safe. It is not. The ESBMC input is 36 characters exactly, passes
that assert, and overflows anyway, because the load-bearing check is the
*second* assert on the de-dashed length. `esbmc-debug` shows this directly: with
asserts live the violation reported is `UUID.cpp:41`, not `:37`. CONTRACT mode
makes it a statement about the whole class — over all 36-character dash-free hex
strings, the copy is out of bounds. That case has since been added to the ASan
table too, where it behaves identically.

**The counterexample is a real input, not a model artefact.** Replaying the
CONTRACT witness against the *native* ASan build reproduces the defect at the
same site:

```
$ ./results/uuid_asan_ndebug 077777777700777777777777777777777777
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 18 at 0x502000000020
    #2 Aws::Utils::UUID::UUID(...) vendor/source/utils/UUID.cpp:43
0x502000000020 is located 0 bytes after 16-byte region
```

The two tools also agree on the debug half: ASan reports
`Assertion 'escapedHexStr.length() == UUID_BINARY_SIZE * 2' failed` for this
input, which is the property ESBMC names at `UUID.cpp:41`.

### Provenance

**Tool:** ESBMC 8.4.0, master `b1fa394aa4`. As with the Base64 run, the binary
came from a working tree carrying *uncommitted local changes* — here to
`src/pointer-analysis/value_set.cpp`, which is on the path for the very
dereference checks these verdicts rest on. The binary was copied aside and every
run above was executed against that one pinned copy, so the runs are internally
consistent; the verdicts are additionally corroborated by two independent
solvers and by the native ASan replay, which does not involve ESBMC at all. The
VCC counts, however, are not reproducible from the pinned commit alone. Re-run
against a clean build before quoting numbers anywhere they matter.

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

### The event-stream path, checked against the CRT

The wire-facing bullet above deserves its own note, because on a first read it
looks like the more dangerous of the two paths. `EventHeader.h` guards the
16-byte invariant with `assert` alone — gone under `NDEBUG` — and then sizes the
buffer from a *header-supplied* length:

```cpp
case EventHeaderType::UUID:
    assert(header->header_value_len == 16u);
    m_eventHeaderVariableLengthValue = ByteBuffer(
        static_cast<uint8_t*>(aws_event_stream_header_value_as_uuid(header).buffer),
        header->header_value_len);
```

Read on its own that is a server-reachable out-of-bounds read waiting for a UUID
header whose length is not 16. It is not one, and the reason is in the CRT
rather than in the SDK. In `aws-c-event-stream`'s decoder, only the two
variable-length types take their length from the wire; every fixed-size type,
UUID included, is assigned a constant:

```c
    case AWS_EVENT_STREAM_HEADER_STRING:
    case AWS_EVENT_STREAM_HEADER_BYTE_BUF:
        decoder->state = s_read_header_value_len;
        break;
    ...
    case AWS_EVENT_STREAM_HEADER_UUID:
        current_header->header_value_len = 16;
        decoder->state = s_read_header_value;
        break;
```

`header_value_len` is therefore not attacker-controlled on this path. The value
itself lives in fixed inline storage — `uint8_t static_val[16]` in the header
union — and the accessor hands back a 16-byte view of it by construction:
`aws_byte_buf_from_array(header->header_value.static_val, UUID_LEN)`. The other
way a UUID header can be built, `aws_event_stream_add_uuid_header_by_cursor`,
rejects any other length outright, since `AWS_RETURN_ERROR_IF` raises when its
condition is *false* (`if (!(cond)) { return aws_raise_error(err); }`):

```c
    AWS_RETURN_ERROR_IF(value.len == UUID_LEN, AWS_ERROR_EVENT_STREAM_MESSAGE_INVALID_HEADERS_LEN);
```

So the SDK's asserts are redundant with an invariant the CRT enforces by
construction, and the release build is safe for the same reason the debug build
is. **Defensive-coding observation, not a defect** — recorded because "assert-only
guard on a length that feeds a `memcpy`" is exactly the shape of U-1, and the
difference between the two is worth being explicit about.

Two caveats on this one. The CRT quotes are from `aws-c-event-stream` at `main`,
not at whatever commit the 1.11.869 submodule chain pins, so the invariant is
verified for current upstream rather than for that exact build; and the argument
is a source reading, not a machine-checked proof — the SDK side depends on a
CRT-side invariant that no compiler or verifier here enforces across the
boundary. If the CRT ever routed UUID through `s_read_header_value_len`, the
SDK's release build would follow it without complaint.

One curiosity while confirming this: the type-mismatch branch of
`GetEventHeaderValueAsUuid()` returns `Aws::Utils::UUID(uuid)` from a local
`char uuid[32] = {0}` — the U-1 string constructor on an empty `Aws::String`,
whose length is 0 and so would trip U-1's *own* first assert. It never does: the
branch is preceded by `assert(m_eventHeaderType == EventHeaderType::UUID)`,
which fires first in a debug build, and in release both sets of asserts are gone
and the call decodes zero bytes. Safe in both builds, though by construction
rather than by design.

**Conclusion: no untrusted-input caller of `UUID(const Aws::String&)` exists in
the SDK.** U-1 is a real memory-safety defect in the function, but it is a
latent robustness/hardening bug rather than a remotely triggerable one: the only
way to hit it is for an SDK *consumer* to pass an unvalidated, over-length string
to the public constructor. This is a *negative* result — it hands out no exploit
path — which is why it is recorded in the open rather than withheld. It is
argued from the caller set, not machine-checked; a directed re-scan of any
future release should repeat it.

## Open items

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
make asan          # GCC + ASan/UBSan cross-check; needs only a C++ compiler
make confirm       # ESBMC on the named input, plus the safe control
make esbmc         # ESBMC over the symbolic harness, both input models
make esbmc-debug   # the same input with asserts live
```

Over-length inputs report `heap-buffer-overflow` under `-DNDEBUG` and trip a
length assert without it; canonical 36-character UUID strings are `ok` under
both. `make asan` runs both semantics.

The boundary runs quoted above are the symbolic harness at a different bound:

```bash
make esbmc MAXLEN=33   # expect SUCCESSFUL
make esbmc MAXLEN=34   # expect FAILED
```
