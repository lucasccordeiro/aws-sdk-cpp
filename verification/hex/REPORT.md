# ESBMC vs. aws-cpp-sdk-core `HexDecode` — findings

**Target:** `aws/aws-sdk-cpp` @ `5650a800bfaca7326a4da336df2e4053ad559867`
(v1.11.878, the current release at the time of writing)
**Function under analysis:** `Aws::Utils::HashingUtils::HexDecode(const Aws::String&)`
(`src/aws-cpp-sdk-core/source/utils/HashingUtils.cpp:174-230`)
**Cross-check:** GCC + AddressSanitizer/UBSan, and an `LD_PRELOAD` interposer on
`<cctype>`
**Status:** ESBMC-confirmed over every two-character input under both Bitwuzla
and Z3, reproduced natively on the whole pristine module, and closed by the
patch in `fix/`. Reachability enumerated across the repository: the two non-test
call sites both pass `HexDecode` a string the SDK built itself, so H-1 is a
latent hardening bug in public API, not a remotely triggerable one.

---

## Summary

`HexDecode` has no rejecting path. Its only character check is an `assert`, and
the predicate it asserts is the wrong one:

| # | Defect | Effect | Trigger |
|---|--------|--------|---------|
| **H-1** | Input characters are checked with `StringUtils::IsAlnum`, and a failure is reported only by `assert(0)` | Malformed input decodes to a full-length buffer indistinguishable from a successful decode; distinct strings alias to the same bytes | any even-length string containing a letter outside `a`–`f`/`A`–`F` (every build), or any other non-hex byte (release builds) |

`"K1"` decodes to `0x41`, the same byte as `"41"`. `"EW"` decodes to `0x00`,
the same as `"00"`. Of the 3844 two-character strings the guard admits, 3360
are not hex; all 256 byte values are producible and the largest preimage holds
25 distinct strings.

There is **no memory-safety consequence** — ASan and UBSan are clean on every
input tried, and ESBMC's bounds and pointer checks pass on all of them. The
defect is that the function's contract and its behaviour disagree: callers get
"decoded successfully" for input a hex decoder must reject.

## H-1 — `HexDecode` accepts what it should reject

### The defect

```cpp
ByteBuffer HashingUtils::HexDecode(const Aws::String& str)
{
    assert(str.length() % 2 == 0);                     // :177
    assert(str.length() >= 2);                         // :178

    if(str.length() < 2 || str.length() % 2 != 0)      // :180
        return ByteBuffer();                           // :182  <- the one real rejection
    ...
    for (size_t i = readIndex; i < str.length(); i += 2)
    {
        if(!StringUtils::IsAlnum(str[i]) || !StringUtils::IsAlnum(str[i + 1]))
        {
            //contains non-hex characters
            assert(0);                                 // :202  <- and this one is not
        }

        char firstChar = str[i];
        uint8_t distance = firstChar - '0';
        if(isalpha(firstChar))                         // :208
        {
            firstChar = static_cast<char>(toupper(firstChar));
            distance = firstChar - 'A' + 10;
        }
        unsigned char val = distance * 16;
        ...
    }
    return hexBuffer;
}
```

The length rule at `:180` is enforced twice — as an `assert` and as an `if` that
returns. The character rule at `:199` is enforced once, as an `assert`, and the
`assert` is not followed by a `return`, so control falls through to the
arithmetic either way. Two distinct failures follow.

**Every build, including debug.** `StringUtils::IsAlnum` (`StringUtils.h:203`)
is

```cpp
return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
```

— 62 accepted characters where hex has 22. For `'g'`–`'z'` and `'G'`–`'Z'` the
guard *passes*, so `assert(0)` is never reached and `NDEBUG` is irrelevant. This
is not the "release drops the check" shape of U-1; there is no build in which
`"K1"` is rejected.

**Release builds, any byte.** For a byte outside the alnum set the guard fires,
and in a release build `assert(0)` expands to nothing. Decoding continues.

### What the arithmetic then does

`distance` is derived without any bound on its range:

```
'0'-'9'  ->  0..9        (c - '0')
'A'-'Z'  -> 10..35       (toupper(c) - 'A' + 10)
'a'-'z'  -> 10..35
```

and the first digit is scaled by 16 into an `unsigned char`:

```cpp
unsigned char val = distance * 16;   // 35 * 16 = 560, truncated to 48
```

The truncation is well defined — the multiplication happens in `int` after
integer promotion and the conversion to `unsigned char` is modular
([conv.integral]) — which is why UBSan has nothing to say. It is also what makes
the map many-to-one: `distance` values 4 and 20 both scale to 64, so `'4'` and
`'K'` are interchangeable in the first position. `"41"` and `"K1"` are the same
two bytes to every caller downstream.

### The ctype precondition

`isalpha` and `toupper` are called with a plain `char` (`:208`, `:210`, `:219`,
`:221`). On every mainstream ABI `char` is signed, so an input byte ≥ 0x80
arrives negative. C17 7.4p1 requires the argument to be "representable as an
`unsigned char`" or equal to `EOF`; anything else is undefined behaviour. This
is reachable exactly on the release-build path above.

Neither sanitizer checks it — UBSan has no ctype instrumentation — and neither
does ESBMC, whose model implements `isalpha` as a range test over `int`
(`src/c2goto/library/ctype.c:26`). glibc's table is padded for indices −128…−1,
so it does not misbehave in practice; other implementations are entitled to.
`stubs/ctype_precondition_guard.c` interposes on both functions and reports the
argument, which is how the claim below is measured rather than argued.

### Evidence

Native, on the whole pristine translation unit (`./reproduce.sh sanitizer`,
`tests`):

| Input | Release (`-DNDEBUG`) | Debug | Note |
|---|---|---|---|
| `41` | `41` | `41` | well formed |
| `K1` | `41` | `41` | **aliases `41`, in both builds** |
| `EW` | `00` | `00` | aliases `00` |
| `v0` | `F0` | `F0` | aliases `f0` |
| `zz` | `53` | `53` | accepted |
| `\x80\x80` | `50` | `Assertion '0' failed` (`:202`) | the only row `NDEBUG` changes |
| `0x41` | `41` | `41` | prefix stripped, as intended |
| `0x` | *(empty)* | *(empty)* | length rule met, nothing decoded |
| `4` | *(empty)* | `Assertion 'str.length() % 2 == 0' failed` (`:177`) | odd length: the one real rejection, and the one the asserts agree with |

ASan and UBSan report nothing on any of these. Under the ctype interposer,
`\x80\x80` reports `isalpha(-128)` and aborts; `41` passes through untouched.

Census over all 65 536 two-character inputs, computed by the same binary
(`results/witness_plain` with no arguments):

| | |
|---|---|
| admitted by the guard | 3844 |
| of those, not hex | **3360** |
| byte values produced | 256 |
| largest preimage | 25 strings |

### Through a public API

`./reproduce.sh entrypoint` runs the same module from one public SDK call —
`UUID(const Aws::String&)`, the caller enumerated under "Reachability" — with
`HexDecode` never named. The 36-character argument is what an application would
have parsed out of a request or a config file:

| Argument | Renders as | Note |
|---|---|---|
| `550e8400-e29b-41d4-a716-446655440000` | `550E8400-E29B-41D4-A716-446655440000` | well formed, round-trips |
| `550e8400-e29b-K1d4-a716-446655440000` | `550E8400-E29B-41D4-A716-446655440000` | **the `K` is accepted, then erased** |
| `GGGGGGGG-GGGG-GGGG-GGGG-GGGGGGGGGGGG` | `10101010-1010-1010-1010-101010101010` | no hex digit anywhere |
| `0G0G0G0G-0G0G-0G0G-0G0G-0G0G0G0G0G0G` | `10101010-1010-1010-1010-101010101010` | aliases the row above, bytes and all |

Row 2 returns the 16 bytes of row 1, so neither the `ByteBuffer` nor the
rendered string distinguishes them. The debug build answers identically: the
asserts at `UUID.cpp:37` and `:41` are length checks that hold on any
36-character four-dash string, and `HashingUtils.cpp:202` — the one `IsAlnum`
guards — is never reached. ASan and UBSan report nothing on any row of either
build. No build configuration available to an application surfaces this.

This is the two-character result embedded in a realistic argument; it is
executed, not proved, and the machine-checked statement remains the
two-character one below. It is reported because it fixes what the defect costs
a caller who never heard of `HexDecode`.

## Symbolic confirmation (ESBMC)

### Configuration, and why each flag is there

| Flag | Why |
|---|---|
| `--std c++11` | the SDK's baseline |
| `-D NDEBUG` | release semantics — the macro state of a shipped build. **Not** `--no-assertions`: that also drops `__ESBMC_assert`, leaving the harness unable to state any property. Checked directly — a program whose only property is `__ESBMC_assert(x == 0, ...)` with `x` set to 1 verifies `SUCCESSFUL` under that flag. Runs without it are the debug semantics, and two of the properties fail there too. |
| `--unwind 16` | the input is two characters; the decode loop runs once. Unwinding assertions are left **on**, so an inadequate bound would surface as a violated unwinding assertion instead of a silent `SUCCESSFUL`. |
| `--force-malloc-success` | suppresses the allocation-failure counterexample from the `Aws::Malloc` stub, which would otherwise mask the property |
| `-D ESBMC_OM_MISSING_ALLOCATE_SHARED` | the one shared OM shim, described in `../stubs/esbmc_compat.h` |

Input model: two `nondet_char()` bytes, constrained per mode
(`harnesses/hex_decode_esbmc.cpp`). The property is asserted with
`__ESBMC_assert`, which survives `-D NDEBUG` because it is an intrinsic rather
than the `assert` macro.

### Results

Every row run under **both Bitwuzla and Z3**, verdicts agreeing; 2–4 s each.

| Mode | Semantics | Verdict | Witness |
|---|---|---|---|
| `HEX_ONLY` (control) | release | **SUCCESSFUL** | — |
| `VALIDATION` | debug | **FAILED** | `"pp"` |
| `VALIDATION` | release | **FAILED** | |
| `ANY_BYTE` | release | **FAILED** | `"\|\|"` (0x7C) |
| `HIGH_BIT` | release | **FAILED** | `"\xFC\xFC"` |
| `ALIAS` | debug | **FAILED** | `"v0"` decodes to `"f0"`'s byte |

`VALIDATION` asserts `out.GetLength() == 0 || input was hex`. `ALIAS` decodes
two symbolic strings — one constrained to hex digits, one alnum with at least
one non-hex character — and asserts the results differ.

The control is the row that makes the rest mean something: with every byte
assumed to be a hex digit the same property **verifies**, so `FAILED` above is
not a harness that fails for any input at all.

`HIGH_BIT` is the class that reaches `isalpha` negative. ESBMC does not check
the ctype precondition itself, so this row establishes reachability of the
input class and the interposer establishes the call; together they are the
claim, and neither half is enough alone.

### Fidelity of the model

The ESBMC legs analyse `HexDecode` and, in the fixed variant, `IsHexDigit` —
**sliced verbatim from the vendored file by `reproduce.sh` at run time**, with
`awk`, into `results/hexdecode_pristine.cpp`. No hand-copied body exists in this
tree, and the reachability leg diffs the vendored file against
`raw.githubusercontent.com` at the pinned tag, so the bytes ESBMC reads are the
shipped ones.

What the slice drops is the other 20 functions of the translation unit, none of
which `HexDecode` calls. That is not a modelling choice; ESBMC cannot parse the
file — confirmed on 8.4.0 and again on 8.5.0. Three operational-model gaps:

| Gap | Where it bites | Model |
|---|---|---|
| `std::list` declared with one template parameter — `std::list<T, Alloc>` is "too many template arguments" | `AWSList.h:17`, used by the SHA-256 tree hash at `HashingUtils.cpp:80,116,130` | `src/cpp/library/list:53` |
| `std::basic_ifstream`, `basic_ofstream`, `basic_fstream`, `basic_iostream` aliases absent although the classes exist | `AWSStreamFwd.h:17-22` | `src/cpp/library/fstream:60,93,124`, `iostream:12` |
| `std::ios::pos_type` absent | `HashingUtils.cpp:132` | `src/cpp/library/ios:159` |

The first two are SDK headers, so `stubs/esbmc/` substitutes them on the ESBMC
include path only and the native builds keep the pristine ones. The third names
a member of a model class, which nothing outside ESBMC can add; `-D
pos_type=streampos` was tried and breaks the model's own `streambuf`. None of
the three is within reach of `HexDecode`. Filed on 2026-08-26 as esbmc/esbmc#7331,
#7332 and #7333, on the pattern of #7138-7141.

A fourth blocker is not an ESBMC defect and is not filed. `HashingUtils.cpp`
calls `isalpha` and `toupper` (`:208`, `:210`, `:219`, `:221`) without including
`<cctype>`, relying on a transitive include that ESBMC's headers do not provide;
under them the identifiers are undeclared. The standard guarantees only that a
header supplies its own synopsis ([res.on.headers]) — nothing guarantees that
some other header supplies `<cctype>`'s — so this is fragile in the SDK rather
than missing in the model. The slice's prologue includes `<cctype>` explicitly,
which is why it parses where the whole file does not.

The native legs have no such restriction: the sanitizer and test binaries link
the whole pristine `HashingUtils.cpp`, with link stubs only for the hash classes
the other functions instantiate (`stubs/aws_crypto_link_stub.cpp`).

## Reachability

GitHub code search over `aws/aws-sdk-cpp`, 2026-08-26: 15 hits for `HexDecode`
across nine files, six of those files under `tests/`. The three that are not
tests:

| Site | Argument | Untrusted? |
|---|---|---|
| `include/aws/core/utils/HashingUtils.h:43` | the declaration | — |
| `source/utils/UUID.cpp:42` | the caller's UUID string, dashes removed | only as far as the caller is |
| `source/auth/signer/AWSAuthV4Signer.cpp:239` | `payloadHash` | no |

The signer's argument is produced two lines earlier by `ComputePayloadHash`
(`:514-537`), which returns either `HexEncode(sha256Digest)` or the
`EMPTY_STRING_SHA256` constant — 64 lower-case hex characters either way. The
call is guarded by `request.GetRequestHash().first == "sha256"`, and its purpose
is to avoid re-hashing a body the SDK just hashed. No wire data reaches it.

`UUID.cpp:42` is the U-1 site. Its reachability was enumerated for that finding
against the full SDK tree: no untrusted-input caller of the string constructor
exists — wire-sourced UUIDs use the 16-byte binary constructor. See
[../uuid/REPORT.md](../uuid/REPORT.md) "Reachability".

Outside the SDK, a GitHub-wide search for `HashingUtils::HexDecode` returns only
vendored copies of aws-sdk-cpp itself in the first 40 results. Code search
indexes default branches and caps its output, so this bounds nothing; it is
reported for what it is.

**Conclusion.** No path in this SDK hands `HexDecode` a string it did not build.
H-1 is a defect in a public codec that ships to applications, handled — like
U-1 — as a public finding rather than a coordinated disclosure.

## Suggested fix

`fix/h1-reject-non-hex.patch`, two hunks:

```cpp
+static bool IsHexDigit(char c)
+{
+    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
+}
...
-        if(!StringUtils::IsAlnum(str[i]) || !StringUtils::IsAlnum(str[i + 1]))
+        if(!IsHexDigit(str[i]) || !IsHexDigit(str[i + 1]))
         {
             //contains non-hex characters
             assert(0);
+            return ByteBuffer();
         }
```

Three properties close together. Non-hex input returns empty, so it decodes to
nothing and can alias nothing; and every character that reaches `isalpha` is now
in `0x30`–`0x66`, satisfying C17 7.4p1 by construction rather than by luck.

The empty return reuses the failure signal the odd-length path already has
(`:182`), so no caller sees a new kind of value. The `assert` is kept ahead of
it: a debug build still stops at the same place. Well-formed input is
untouched — prefix stripping and case-insensitivity are unchanged, and the five
well-formed contract cases pass identically before and after.

After the patch, all three ESBMC properties re-verify under both solvers, and
all 13 contract cases pass in the native build (`./reproduce.sh fix`).

### The one caller that changes

`UUID.cpp:43` `memcpy`s `rawUuid.GetUnderlyingData()`, which is `nullptr` for an
empty `Array` (`Array.h:45`). A non-hex UUID string therefore reaches
`memcpy(dst, nullptr, 0)` — undefined per C17 7.24.1p2 via 7.1.4p1, benign on
every implementation we know of, and **already reachable today** for an
odd-length de-dashed body. Both halves measured, not argued — the patched
entry-point build on a non-hex string (`./reproduce.sh fix`), and the pristine
one on an odd-length string:

```
$ ./results/entrypoint_uuid_fixed_asan            # patched, "...-K1d4-..."
vendor/source/utils/UUID.cpp:43:19: runtime error: null pointer passed as
    argument 2, which is declared to never be null

$ ../uuid/results/uuid_asan_ndebug "12345678-1234-1234-1234-12345678901"  # U-1
vendor/source/utils/UUID.cpp:43:19: runtime error: null pointer passed as
    argument 2, which is declared to never be null
```

Same line, same diagnostic, with and without the patch: the patch widens the set
of inputs that take an existing path rather than creating one. That belongs to
U-1's file, not to `HexDecode`. A caller-side fix would guard the `memcpy` on
`GetLength() != 0`.

The patch also does not give this constructor an error channel it never had.
Every rejected string now yields the nil UUID, so the two no-hex arguments in
the table above still parse alike — distinguishable from a decode failure only
by a change to `UUID`'s own signature, which is outside this finding.

## Not claimed

- **No memory corruption.** No OOB read or write, no leak. ASan, UBSan and
  ESBMC's bounds and pointer checks are clean on every input above. The single
  UBSan diagnostic quoted in this report is `UUID.cpp`'s null `memcpy`.
- **No exploit, and no affected caller inside the SDK.** The aliasing is a
  property of the decoder; whether it matters depends on what an application
  does with the bytes.
- **No claim about longer inputs beyond the obvious.** The proofs are over
  two-character inputs, which is one decode iteration. Longer strings repeat the
  same loop body, so the same witnesses embed in them — the entry-point leg
  executes exactly that on a 36-character UUID string — but embedding is
  demonstrated by running it, not machine-checked, and only the two-character
  statement is proved.
- **Not a regression.** The code is unchanged between 1.11.869, where U-1 was
  found, and 1.11.878.

## Reproducing

```sh
./reproduce.sh              # 51 checks, ~3 min
./reproduce.sh esbmc        # or one leg at a time: esbmc, sanitizer,
                            # tests, reachability, entrypoint, fix
```

Everything ESBMC and the native builds analyse is byte-for-byte upstream
1.11.878, pinned by `vendor/UPSTREAM_VERSION` and `vendor/UPSTREAM_COMMIT` and
re-checked file by file — all 36 — against `raw.githubusercontent.com` by the
reachability leg, which fetches by commit rather than by the movable tag. `stubs/`
holds only verification-only substitutes, each documenting what it stands in
for.

Findings generated with AI tools and reviewed by Lucas Cordeiro, University of
Manchester.
