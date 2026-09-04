# ESBMC vs. aws-cpp-sdk-core's hand-written stream buffers — findings

**Target:** `aws/aws-sdk-cpp` @ `acb9a0a9bcc48065bcfa71c73240c34da8deccb9`
(v1.11.884, the current release at the time of writing)
**Functions under analysis:**
`Aws::Utils::Stream::SimpleStreamBuf::{seekoff,seekpos,underflow}`
(`src/aws-cpp-sdk-core/source/utils/stream/SimpleStreamBuf.cpp:67-112,217-232`) and
`Aws::Utils::Stream::PreallocatedStreamBuf::{seekoff,seekpos}`
(`.../PreallocatedStreamBuf.cpp:25-72`)
**Cross-check:** GCC + AddressSanitizer/UBSan, and `std::stringbuf` run through the
same sequences as a reference oracle
**Status:** three defects, each ESBMC-confirmed over every offset under both
Bitwuzla and Z3 and on two ESBMC versions, each reproduced natively on the
pristine sources, and all three closed by the patch in `fix/`. Reachability
enumerated across the repository: no untrusted input reaches any of them, and no
in-SDK caller currently performs the seek T-2 and T-3 need — these are defects in
public exported API rather than remotely triggerable ones.

---

## Summary

Both classes implement `seekoff`/`seekpos` by hand. `SimpleStreamBuf` also
implements `underflow`. All three implementations disagree with the buffer they
are documented as replacing (`SimpleStreamBuf.h:21`, "a replacement for
`std::stringbuf`").

| # | Defect | Effect | Trigger |
|---|--------|--------|---------|
| **T-1** | two call sites re-point the end of the get area at `pptr()` whether or not that is behind `gptr()` — `underflow` (`:221`) and `xsputn` (`:197`) | `setg` is handed `gnext > gend`; the next multi-byte read `memcpy`s a **negative length** — SIGSEGV in a stock release build | write, read part way, `seekp` backwards, read on (`SimpleStreamBuf` only) |
| **T-2** | end-relative seeks *subtract* the offset instead of adding it | `seekg(-n, end)` fails — and **aborts** a debug build; `seekg(+n, end)` succeeds and lands inside the buffer | any non-zero end-relative seek, both buffers |
| **T-3** | `which` is compared with `==`, so the default `in\|out` matches neither the `in` branch nor the `out` branch | `seekpos` returns the requested position — success — having moved no pointer at all | `pubseekpos` / `pubseekoff` with the default openmode, both buffers |

T-1 is memory corruption. T-2 and T-3 are wrong answers: the call reports
success and the stream is somewhere other than where the caller asked.

The three are independent defects in the same 60 lines, and the fix for each is
one or two lines.

## T-1 — `underflow` leaves the get area inverted

### The defect

```cpp
int SimpleStreamBuf::underflow()
{
    if(egptr() != pptr())               // :219
    {
        setg(m_buffer, gptr(), pptr()); // :221
    }

    if(gptr() != egptr())
    {
        return std::char_traits< char >::to_int_type(*gptr());
    }
    ...
```

The intent is to extend the readable area up to whatever has been written. The
test is `!=`, so the *shrinking* case is taken too: once the put pointer has been
moved backwards — `seekp`, which `seekpos` implements at `:106-109` — `pptr()` is
behind `gptr()`, and the call sets the end of the get area behind its current
position.

`underflow` is not the only place this happens. `xsputn` ends each copy with the
same unguarded call:

```cpp
            setp(current_pptr + copySize, current_epptr);
            setg(m_buffer, gptr(), pptr());  // :197
```

so a *write* after the rewind inverts the get area without `underflow` running at
all. Both sites need the same guard, and the evidence below exercises both.

[streambuf.get.area]/5 requires the three arguments of `setg` to form valid
ranges: "`[gbeg, gnext)`, `[gbeg, gend)`, and `[gnext, gend)` are all valid
ranges". `gnext > gend` is not one, so the call is undefined behaviour before
anything reads from it.

What reads from it is `std::basic_streambuf::xsgetn`, which the SDK does not
override for this class. libstdc++ computes the available count as
`egptr() - gptr()` and passes it to `traits_type::copy`, i.e. `memcpy`, whose
third parameter is `size_t`. A negative count becomes a copy of roughly 2^64
bytes.

### Evidence

The sequence is ordinary: write 50 bytes, read up to offset 40, move the put
pointer back to 10, keep reading. Nothing in it is out of contract for
`std::iostream`, and the control row is the same sequence on `std::stringbuf`.

`./reproduce.sh sanitizer`, on the pristine sources:

| Run | Result |
|---|---|
| `std::stringbuf`, same sequence | `gcount=10`, no diagnostic |
| pointers after the read (`witness invariant`) | **`gptr=51 egptr=10 pptr=10`** — [streambuf.get.area]/5 violated |
| one-byte read past the written data (`witness stale`) | returns a heap byte the application never wrote (`0xbe` on this build) |
| 50-byte read, ASan (`witness crash`) | `AddressSanitizer: negative-size-param: (size=-41)` in `memcpy`, via `std::basic_streambuf::xsgetn` |
| the same, no sanitizer | **SIGSEGV** (exit 139) |
| the same, asserts live | identical — no assert stands on this path |
| the write path (`witness write`) | `gptr=50 egptr=15` — inverted by `xsputn:197`, with `underflow` never called |
| its read, ASan | `negative-size-param: (size=-35)` |
| `std::stringbuf`, write sequence | `gcount=0`, no diagnostic |

The uninstrumented row is the one that matters for severity: this is not a
sanitizer objecting to a technicality, it is a stock release build dying. The
copy runs before it faults, so it writes past the caller's read buffer on the
way.

`NDEBUG` changes nothing here. Neither `underflow` nor the `setg` it calls has
an assert, and the two asserts in `seekpos` are about a different thing.

## T-2 — end-relative seeks go the wrong way

### The defect

```cpp
    else if (dir == std::ios_base::end)
    {
        return seekpos((pptr() - m_buffer) - off, which);   // SimpleStreamBuf.cpp:75
    }
```

```cpp
                else if (dir == std::ios_base::end)
                {
                    return seekpos(m_lengthToRead - off, which);  // PreallocatedStreamBuf.cpp:33
                }
```

[stringbuf.virtuals] table 145 gives `newoff = high_mark - xbeg` for
`way == ios_base::end`, and p11 assigns `xbeg + newoff + off`. The offset is
**added**. Seeking to the last three bytes of a sequence is `off == -3`; `off`
positive is past the end and must fail.

Both buffers subtract, so both meanings are exchanged: the seek that should work
fails, and the seek that should fail works.

### Evidence

`./reproduce.sh tests`, ten-byte payload `"0123456789"`, so the byte read back
names the position. Every row is run against `std::stringbuf` first — it passes
all seven, which is what makes the other two columns a disagreement with the
standard rather than an expectation invented here.

| Row | `std::stringbuf` | `SimpleStreamBuf` | `PreallocatedStreamBuf` |
|---|---|---|---|
| `seekg(0,beg)` | `'0'` | `'0'` | `'0'` |
| `seekg(5,beg)` | `'5'` | `'5'` | `'5'` |
| `seekg(0,end)` | EOF | EOF | EOF |
| `seekg(-3,end)` | `'7'` | **FAIL** | **FAIL** |
| `seekg(+3,end)` | FAIL | **`'7'`** | **`'7'`** |

`seekg(0, end)` is the row that still passes, and it is not luck: zero is its own
negation. It is also the only end-relative seek the SDK performs on these
buffers, which is why the defect has survived.

In a **debug build the failing seek is not a failure but an abort**: `seekpos`
asserts `static_cast<size_t>(pos) <= maxSeek` (`:95`), the wrong-signed position
is a large `size_t`, and the process stops:

```
Assertion `static_cast<size_t>(pos) <= maxSeek' failed.
```

### Upstream's own tests encode the inversion

`tests/aws-cpp-sdk-core-tests/utils/stream/PreallocatedStreamBufTest.cpp:63-74`
and the three tests beside it seek from the end like this:

```cpp
    auto seekPos = sizeof(bufferStr) - 5;
    ioStream.seekg(seekPos, std::ios_base::end);
```

— a *positive* offset of `length - 5` to reach position 5. The tests pass
because the implementation subtracts; against a conforming buffer they would
fail. Four tests are written this way (`TestStreamReadSeekEnd` and
`TestStreamWriteSeekEnd` in each of the two test files), and a fix has to update
them. That the convention was written into the tests is the best evidence that
it was never checked against the standard.

### The same shape elsewhere in the SDK

Read, not run — outside this target's scope, and stated here because a reader
fixing T-2 will want to know:

| Site | Code |
|---|---|
| `source/utils/event/EventStreamBuf.cpp:68` | `return seekpos(m_bufferLength - 1 - off, which);` — subtracts, and off by one besides |
| `source/utils/crypto/CryptoBuf.cpp:204` | `off_type absPos = m_stream.seekg(0, std::ios_base::end).tellg() - pos;` |

## T-3 — a seek that reports success and does nothing

### The defect

```cpp
    if (which == std::ios_base::in)     // SimpleStreamBuf.cpp:101
    {
        setg(...);
    }

    if (which == std::ios_base::out)    // :106
    {
        setp(...);
    }

    return pos;                         // :111
```

`openmode` is a bitmask, and `pubseekpos` / `pubseekoff` default `which` to
`in | out`. `==` matches neither branch, so neither pointer moves — and the
function returns `pos`, which is the encoding for success. `PreallocatedStreamBuf`
is identical (`:61`, `:66`, `:71`).

[stringbuf.virtuals] table 144 is explicit about this case: with both bits set
and `way == beg` or `way == end`, **both** sequences are positioned. Not one,
not neither.

### Evidence

| Row | `std::stringbuf` | `SimpleStreamBuf` | `PreallocatedStreamBuf` |
|---|---|---|---|
| `pubseekpos(2)`, then read | `'2'` | **`'0'`** | **`'0'`** |
| `pubseekoff(4,beg)`, then read | `'4'` | **`'0'`** | **`'0'`** |

Both calls returned the position asked for. The stream stayed where it was.

The SDK's own `EventStreamBuf` gets this case right — `EventStreamBuf.cpp:104`
returns `-1` when `which` is neither `in` nor `out` alone — so the two buffers
here are not following a house convention; they are missing a case their sibling
handles.

## Symbolic confirmation (ESBMC)

### Configuration, and why each flag is there

| Flag | Why |
|---|---|
| `--std c++11` | the SDK's baseline |
| `-D NDEBUG` | release semantics — the macro state of a shipped build. **Not** `--no-assertions`: that also drops `__ESBMC_assert`, leaving the harness unable to state any property. Runs without it are the debug semantics, and one row is reported in each |
| `--unwind 4` | there is no loop in any function under test; the bound covers the harness's own construction |
| `-D ESBMC_OM_MISSING_STREAMPOS` | supplies `std::streampos` and `std::streamoff`, which ESBMC's model declares only as members of `class ios`. Described in `stubs/esbmc/streambuf_model.h` |
| `SIZE` (default 8) | the buffer the model reasons about. Every property is over every offset and every get area **of a buffer of at most 8 bytes** — the arithmetic under test is linear in the offset and has no other bound, but the proofs are that statement, not a larger one |

Input model: a symbolic data length and a symbolic seek offset, or a symbolic
get/put area, per mode (`harnesses/streambuf_esbmc.cpp`). Properties are stated
with `__ESBMC_assert`, which survives `-D NDEBUG`.

### Results

Every row run under **both Bitwuzla and Z3**, and on **both ESBMC 8.4.0 and
8.5.0**; all four combinations agree. 2–6 s each.

| Mode | Semantics | Verdict | Witness |
|---|---|---|---|
| `SEEK_ZERO` (control) | release | **SUCCESSFUL** | — |
| `SEEK_END` | release | **FAILED** | `length=8, off=+1`: returns 7, must fail |
| `SEEK_BACK` | release | **FAILED** | every backward seek lands elsewhere |
| `SEEK_BACK` | debug | **FAILED** | stops at `SimpleStreamBuf.cpp:95`, the module's own assert |
| `SEEK_BOTH` | release | **FAILED** | `pos=0`: success, nothing moved |
| `GET_AREA` | release | **FAILED** | `gptr=4, egptr=4, pptr=0` |
| `PREALLOC_END` | release | **FAILED** | `length=8, off=+7`: returns 1, must fail |
| `PREALLOC_BOTH` | release | **FAILED** | as `SEEK_BOTH` |

The control is the row that makes the rest mean something: with the offset fixed
at zero the same property **verifies**, so `FAILED` above is not a harness that
fails for every input.

`GET_AREA` assumes `gptr <= egptr` on entry — what `setg`'s own precondition
guarantees of any state the class built — so the violation is the module turning
a well-formed get area into a malformed one, not the harness handing it a
malformed one. That constraint is *necessary* for a reachable state rather than
sufficient, so the mode alone does not prove the class reaches the entry state
its witness names. What closes that gap is the native witness, which exhibits
`gptr=51 egptr=10 pptr=10` from a sequence of public calls.

### Fidelity of the model

The five functions are **sliced verbatim from the vendored sources by
`reproduce.sh` at run time**, with `awk`, into `results/streambuf_pristine.cpp`.
No hand-copied body exists in this tree, and the reachability leg diffs every
vendored file against `raw.githubusercontent.com` at the pinned commit, so the
bytes ESBMC reads are the shipped ones.

What the slice replaces is the base class, and only the base class. ESBMC's
`std::basic_streambuf` declares the ten get- and put-area members without
defining any of them (`src/cpp/library/streambuf:83-96`), so `setg` writes
nowhere and `gptr()` comes back unconstrained — `gptr() <= egptr()` is violable
on a freshly constructed buffer, before any SDK code runs. Every property here is
about those pointers, so against the stock model every verdict would be about
ESBMC rather than about the SDK. `stubs/esbmc/streambuf_model.h` supplies the
postconditions [streambuf.get.area]/6 and [streambuf.put.area]/3 state, and
nothing else; in particular it does **not** enforce `setg`'s precondition, since
whether the SDK can break it is exactly what `GET_AREA` asks.

`stubs/esbmc/streambuf_scaffold.h` holds the two class declarations and the
constructors the harness needs, and says which three things differ from the SDK
headers. The native legs use neither file: they derive from the real
`<streambuf>` and reach the functions the way an application does, through
`std::iostream`.

Two operational-model gaps, both new, both siblings of #7331-7333:

| Gap | Where it bites | Model |
|---|---|---|
| `basic_streambuf`'s `eback/gptr/egptr/gbump/setg/pbase/pptr/epptr/pbump/setp` are declared and never defined | any user-derived stream buffer — a search for `public std::streambuf` over this repository returns eight classes, seven under `aws/core` and one in the vendored `smithy` tree | `src/cpp/library/streambuf:83-96` |
| `std::streampos` and `std::streamoff` exist only as members of `class ios`, and as `int` rather than a 64-bit type | every `seekoff`/`seekpos` override, whose signatures name them at namespace scope | `src/cpp/library/ios:162-163` |

Neither is within reach of a fix in this tree; the first is why the leg needs a
stand-in base at all.

One further note on versions. The 8.5.0 binary available here is a local build 18
commits ahead of master, touching `goto-symex` and `smt_solver`. That is why
every row was re-run on a **stock master build (8.4.0, commit `54172fc905`, zero
commits ahead of `origin/master`)**, where the verdicts are identical. The
native legs depend on no ESBMC build at all.

## Reachability

Enumerated over `aws/aws-sdk-cpp` at 1.11.884.

**`PreallocatedStreamBuf`** is used unconditionally, on every platform:

| Site | What it wraps |
|---|---|
| `aws-cpp-sdk-transfer/.../TransferManager.cpp:502` | each multipart upload part's buffer |
| `.../TransferManager.cpp:618` | the single-part upload buffer |
| `.../TransferManager.cpp:1090` | each download range's buffer |
| `aws-cpp-sdk-core/.../AWSAuthEventStreamV4Signer.cpp:202` | the event-stream signing buffer |

Those streams are handed to the HTTP client as the request body, and
`CurlHttpClient.cpp:385-402` translates libcurl's seek origins straight through —
`SEEK_END` becomes `std::ios_base::end`, then `ioStream->seekg(offset, dir)`. So
the wiring for a T-2 seek on a live upload body exists. It is not currently
taken: libcurl's own documentation for `CURLOPT_SEEKFUNCTION` says the callback
"gets `SEEK_SET`, `SEEK_CUR` or `SEEK_END` as argument for origin, although
libcurl currently only passes `SEEK_SET`." The branch is dead today and wrong the
day it is not.

No other in-SDK caller performs a non-zero end-relative seek on either buffer,
and GitHub code search finds no `pubseekpos` or `pubseekoff` — T-3's entry
points — anywhere in the repository. T-3 is reachable only from application code.
Code search indexes the default branch and caps its results, so that bounds
nothing on its own; it is reported for what it is.

**`SimpleStreamBuf`**, which carries T-1, is public exported API
(`AWS_CORE_API`) on every platform, but the SDK selects it for its own use only
on one configuration:

```cpp
#if defined(_GLIBCXX_FULLY_DYNAMIC_STRING) && _GLIBCXX_FULLY_DYNAMIC_STRING == 0 && defined(__ANDROID__)
```

— `AWSStringStream.h:10` and `:25`, whose second arm makes it `Aws::StringStream`,
`Aws::StringBuf` and friends (`:28-31`), and `ResponseStream.cpp:10-15`, where it
becomes the default response-body buffer. On that configuration the transfer manager
moves a download stream's put pointer backwards while the same stream is read
(`TransferHandle.cpp:405`), which is T-1's shape — but that path depends on the
stream the caller supplies, and we have not executed it. What *is* executed here
is the public-API sequence in `harnesses/streambuf_witness.cpp`.

**Conclusion.** No path in this SDK hands either buffer input from the wire, and
no in-SDK caller currently performs the seeks T-2 and T-3 need. Like U-1 and H-1,
these are defects in public API that ships to applications — with the difference
that T-1's consequence is memory corruption rather than a wrong value.

## Suggested fix

`fix/streambuf-seek-and-get-area.patch`, ten hunks across the two files — six in
`SimpleStreamBuf.cpp`, four in `PreallocatedStreamBuf.cpp`:

```cpp
-        return seekpos((pptr() - m_buffer) - off, which);
+        return seekpos((pptr() - m_buffer) + off, which);
```
```cpp
-        else
+        else if(which == std::ios_base::out)
```
```cpp
+    if ((which & (std::ios_base::in | std::ios_base::out)) == 0)
+    {
+        return pos_type(off_type(-1));
+    }
```
```cpp
-    if (which == std::ios_base::in)
+    if ((which & std::ios_base::in) != 0)
```
```cpp
-    if(egptr() != pptr())
+    if(egptr() < pptr())
```

T-2 is the sign. T-3 is the bitmask, plus the two cases table 144 says must
fail: `cur` with both bits set, and a `which` with neither. T-1 is the last
hunk *and* the same guard wrapped around `xsputn:197`: the get area may still be
extended to what has been written, and may no longer be pulled back behind the
position the caller is reading from. Both sites need it — guarding only
`underflow` leaves the identical `memcpy` reachable by ending the sequence with a
write instead of a read, which is what `./reproduce.sh fix` now checks.

One ordering detail the patch relies on: in `seekpos` the `setg` runs before the
`setp`, so under `in|out` the get-area end is the old put position and
`gptr <= egptr` still holds. Swapping the two statements would break it.

After the patch, all six ESBMC properties verify under both solvers and both
ESBMC versions, all 21 contract rows pass, the negative `memcpy` is gone, and the
witness sequence returns the same 10 bytes `std::stringbuf` returns
(`./reproduce.sh fix`).

### What the patch does not do

`seekpos` asserts that its caller never asks for a position outside the
sequence (`SimpleStreamBuf.cpp:95`, `PreallocatedStreamBuf.cpp:52`), and
returning `-1` is how the API is required to say no. So a debug build still
aborts where a release build fails gracefully — for an out-of-range seek that
was always the behaviour, patched or not, and the fix leg pins it rather than
quietly changing it. It is the same assert-instead-of-return shape as H-1 and is
reported here rather than fixed, because a caller relying on the abort is easier
to imagine than a caller relying on the sign.

It also keeps `pptr()` as the notion of "the end" — in `seekoff`'s end branch and
as `seekpos`'s `maxSeek` — where table 145 uses the high-water mark. After a
backward `seekp`, `seekg(0, end)` therefore lands at the put position rather than
after the last byte written. That is pre-existing, it is the same
`pptr()`-is-not-the-high-water-mark confusion T-1 comes out of, and fixing it
means giving the class a high-water mark it does not currently have — a larger
change than this patch, and one that would alter `str()` as well.

The patch also does not touch `EventStreamBuf` or `CryptoBuf`, which carry T-2's
shape in code this target did not analyse.

## Not claimed

- **No untrusted input.** Nothing from the wire reaches these functions. T-1
  needs an application that interleaves reads with a backward `seekp`; T-2 and
  T-3 need an application that seeks these buffers directly.
- **No exploit.** T-1 is a `memcpy` of a length the caller does not control to a
  destination the caller supplies; the process dies. Whether anything more is
  available from it depends on the application, and we did not investigate.
- **Nothing about the SDK's other stream buffers.** `EventStreamBuf`,
  `CryptoBuf`, `ConcurrentStreamBuf`, `HttpWriteDataStreamBuf` and
  `StreamBufProtectedWriter` were read, not analysed. The two lines quoted under
  T-2 are quotations, not results.
- **The Android path is argued, not executed.** The configuration that makes
  `SimpleStreamBuf` the SDK's own string stream was not built or run here.
- **Not a regression.** Both files are byte-identical between 1.11.878, where H-1
  was found, and 1.11.884.

## Reproducing

```sh
./reproduce.sh              # 70 checks, ~1 min
./reproduce.sh esbmc        # or one leg at a time: esbmc, sanitizer, tests,
                            # reachability, fix
```

Everything ESBMC and the native builds analyse is byte-for-byte upstream
1.11.884, pinned by `vendor/UPSTREAM_VERSION` and `vendor/UPSTREAM_COMMIT` and
re-checked file by file — all 18 — against `raw.githubusercontent.com` by the
reachability leg, which fetches by commit rather than by the movable tag.
`stubs/` holds only verification-only substitutes, each documenting what it
stands in for.

Findings generated with AI tools and reviewed by Lucas Cordeiro, University of
Manchester.
