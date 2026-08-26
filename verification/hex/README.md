# Missing input validation in `HashingUtils::HexDecode` — H-1

`Aws::Utils::HashingUtils::HexDecode` (`src/aws-cpp-sdk-core/source/utils/HashingUtils.cpp:174-230`)
never rejects a malformed argument. It decodes it and returns a buffer that
looks exactly like a successful decode. Pinned here at
**1.11.878** (`5650a800bfaca7326a4da336df2e4053ad559867`), the current release
on 2026-08-26; `vendor/` holds that file unmodified.

The character guard is

```cpp
if(!StringUtils::IsAlnum(str[i]) || !StringUtils::IsAlnum(str[i + 1]))
{
    //contains non-hex characters
    assert(0);            // HashingUtils.cpp:199-203
}
```

and it is wrong twice over. `IsAlnum` (`StringUtils.h:203`) accepts all 62
alphanumerics where only 22 are hex digits, so `'g'`–`'z'` and `'G'`–`'Z'` walk
straight past it — **in a debug build too**, since the assert never fires for
them. And where the guard does fire, on any other byte, `assert(0)` is all that
happens: a release build compiles it out and decoding continues into the next
statement.

Neither case is memory-unsafe. What is wrong is the *result*:

```
"41" -> 0x41        "K1" -> 0x41        both, decoded, indistinguishable
"00" -> 0x00        "EW" -> 0x00
"f0" -> 0xF0        "v0" -> 0xF0
```

Of the 3844 two-character strings the guard admits, **3360 are not hex**. Every
one of the 256 byte values has a preimage, the largest holding 25 distinct
strings. A caller that hex-decodes an identifier and compares the *bytes* — the
natural way to use this API — cannot tell `"K1"` from `"41"`.

Two smaller consequences fall out of the same guard. Bytes ≥ 0x80 reach
`isalpha`/`toupper` as a negative `char` (`HashingUtils.cpp:208-221`), which is
undefined behaviour: C17 7.4p1 requires an argument representable as
`unsigned char` or equal to `EOF`. And because the return type carries no error
channel, output length is a function of *input length alone* — `"0x"` decodes to
nothing at all — so a caller cannot recover the rejection the function never
performs.

**This is a latent hardening bug, not a remotely triggerable one.** Neither of
the two non-test call sites in the SDK feeds `HexDecode` anything it did not
produce itself (see "Reachability"). `HexDecode` is public API, though, and
what an application passes it is outside this repository.

## Run it

```sh
./reproduce.sh          # 37 checks, ~2 min
```

Needs ESBMC 8.4.0 (Bitwuzla and Z3), a C++11 compiler and curl. Each leg also
runs alone: `./reproduce.sh esbmc | sanitizer | tests | reachability | fix`. Set
`CXX` to choose the compiler. Expect **37 passed, 0 failed**; a failure is what
would need explaining.

| Leg | What it establishes |
|---|---|
| **ESBMC** | Over *every* two-character input: what the function accepts, and that a rejected string can decode to an accepted one's bytes |
| **Sanitizers** | The same on the whole pristine module — and that ASan and UBSan have nothing to say about it |
| **Tests** | Ordinary release build: 8 of 13 contract cases fail, plus the census above |
| **Reachability** | The two non-test callers at the pinned tag, and what each one passes |
| **Fix** | `fix/h1-reject-non-hex.patch`: every contract case and every ESBMC property goes green |

### ESBMC — the acceptance is proved, not sampled

All six rows agree under **Bitwuzla and Z3**; each takes 2–4 s.

| Property, over all inputs of the model | Semantics | Verdict |
|---|---|---|
| Hex input decodes without complaint (control) | release | **SUCCESSFUL** |
| A non-empty result implies the input was hex | **debug** | **FAILED** — witness `"pp"` |
| The same | release | **FAILED** |
| The same, input bytes unconstrained | release | **FAILED** — witness `"\|\|"` |
| The same, input bytes ≥ 0x80 | release | **FAILED** — witness `"\xFC\xFC"` |
| A non-hex string never decodes to a hex string's bytes | **debug** | **FAILED** — witness `"v0"` vs `"f0"` |

The control matters: the property is not trivially false, and a well-formed
argument still decodes. The two **debug** rows matter more — they are the ones
that do not need `NDEBUG`. `IsAlnum` lets those witnesses through, so the
`assert` a debug build keeps is never reached, and the defect is not the
familiar "release drops the check" shape that U-1 has.

Release semantics here is `-D NDEBUG`, the macro state of an actual release
build, not ESBMC's `--no-assertions`: that flag also drops `__ESBMC_assert`, so
the harness could not state a property at all under it.

### Why a slice

The ESBMC legs analyse `HexDecode` **sliced out of the pristine file at run
time** by `reproduce.sh` — upstream bytes, never a hand-written copy, and the
same leg re-slices the patched file for the fix. The rest of the translation
unit is dropped because ESBMC 8.4.0 cannot parse it. Three operational-model
gaps, each of which stops the parse dead:

| Gap | Where |
|---|---|
| `std::list` is declared with one template parameter, so `std::list<T, Alloc>` is "too many template arguments" | `AWSList.h:17`, model at `src/cpp/library/list:53` |
| `std::basic_ifstream` / `basic_ofstream` / `basic_fstream` / `basic_iostream` aliases are missing, though the classes exist | `AWSStreamFwd.h:17-22`, classes at `src/cpp/library/fstream:60,93,124` |
| `std::ios::pos_type` is missing | `HashingUtils.cpp:132`, model at `src/cpp/library/ios:159` |

The first two are shimmed in `stubs/esbmc/` — they are *SDK* headers, so a
substitute is on the include path rather than an edit. The third names a member
of a model class directly and cannot be shimmed from outside ESBMC. None of the
three is anywhere near `HexDecode`: they are in the SHA-256 tree hash and in
stream typedefs. Not filed upstream yet.

The whole module is analysed natively, by the sanitizer and test legs, which
have no such gap.

### Reachability, read off the pinned tag

GitHub code search over `aws/aws-sdk-cpp` on 2026-08-26 returns 15 hits for
`HexDecode` across nine files, six of those files under `tests/`. The non-test
three:

| Site | What it passes |
|---|---|
| `HashingUtils.h:43` | the declaration |
| `UUID.cpp:42` | the de-dashed UUID string a caller handed to `UUID(const Aws::String&)` — the U-1 site |
| `AWSAuthV4Signer.cpp:239` | `payloadHash`, which `ComputePayloadHash` (`:514-537`) has just produced with `HexEncode` or read from the `EMPTY_STRING_SHA256` constant |

So nothing inside the SDK reaches `HexDecode` with a string it did not build
itself, and the signer's argument is hex by construction. A search across
GitHub finds third-party hits only in vendored copies of the SDK — which is
weak evidence, since code search indexes default branches and caps its results,
but it is what there is.

## Fix

`fix/h1-reject-non-hex.patch` — two hunks against the pristine file:

```cpp
-        if(!StringUtils::IsAlnum(str[i]) || !StringUtils::IsAlnum(str[i + 1]))
+        if(!IsHexDigit(str[i]) || !IsHexDigit(str[i + 1]))
         {
             //contains non-hex characters
             assert(0);
+            return ByteBuffer();
         }
```

plus the file-local `IsHexDigit`. The empty return is not a new convention: the
odd-length path (`HashingUtils.cpp:180-183`) already reports failure that way.
The `assert` stays, so a debug build still stops where it always did.

It closes all three consequences at once — a rejected string decodes to nothing,
so it can alias nothing, and every character that now reaches `isalpha` is in
`0x30`–`0x66`, inside the `unsigned char` range C17 7.4p1 asks for. Well-formed
input is untouched: the `0x`/`0X` prefix is still stripped, case is still
ignored, and the five well-formed contract cases pass before and after.

One caller sees a behaviour change. `UUID.cpp:43` `memcpy`s
`rawUuid.GetUnderlyingData()`, which is `nullptr` for an empty buffer
(`Array.h:45`), so a non-hex UUID string would join the odd-length one on a
`memcpy(dst, nullptr, 0)` — undefined per C17 7.24.1p2 by way of 7.1.4p1, and
UBSan says so today: `null pointer passed as argument 2` at `UUID.cpp:43` for
`"12345678-1234-1234-1234-12345678901"` under `-DNDEBUG`. That path is reachable
without this patch; the patch widens the set of inputs that take it. It belongs
to U-1, not to H-1, and is recorded in [../uuid/](../uuid/).

## Not claimed

- **No memory corruption.** No OOB read or write, no leak; ASan and UBSan are
  clean on every input in the witness table. The one UBSan diagnostic in this
  directory's evidence is `UUID.cpp`'s null `memcpy`, not `HexDecode`.
- **No exploit.** The aliasing is a property of the decoder. Whether it matters
  depends on what a caller does with the bytes, and no caller in this SDK
  passes it anything untrusted.
- **Not a new defect.** This is the code as it has always been; `git log` shows
  no relevant change, and 1.11.878 is the same as 1.11.869, where U-1 was found.
- **The `0x` prefix is not part of the finding.** Stripping it is deliberate
  upstream behaviour. It is mentioned only because it makes the empty return
  ambiguous, which is why the fix keeps the `assert` alongside it.

Findings generated with AI tools and reviewed by Lucas Cordeiro, University of
Manchester.
