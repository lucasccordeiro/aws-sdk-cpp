# Three defects in the SDK's hand-written stream buffers — T-1, T-2, T-3

`Aws::Utils::Stream::SimpleStreamBuf` and
`Aws::Utils::Stream::PreallocatedStreamBuf` implement `seekoff`, `seekpos` and
(for the first) `underflow` by hand. All three implementations disagree with the
buffer `SimpleStreamBuf.h:21` says it replaces, `std::stringbuf`. Pinned here at
**1.11.884** (`acb9a0a9bcc48065bcfa71c73240c34da8deccb9`), the current release on
2026-09-02; `vendor/` holds both files unmodified.

**T-1 — a read after a backward `seekp` `memcpy`s a negative length.**
Two call sites re-point the end of the get area at the put pointer without
checking which is ahead — `underflow`:

```cpp
if(egptr() != pptr())               // SimpleStreamBuf.cpp:219
{
    setg(m_buffer, gptr(), pptr()); // :221
}
```

and `xsputn`, which ends every copy with the same unguarded call (`:197`). Once
`seekp` has moved the put pointer back, `pptr()` is *behind* `gptr()`, and either
site hands `setg` a `gnext` past its `gend` — which [streambuf.get.area]/5
forbids. `std::basic_streambuf::xsgetn`, which this class does not override,
then computes `egptr() - gptr()` as the available count and passes it to
`memcpy`, whose third parameter is `size_t`:

```
$ ./results/witness_ndebug invariant
after underflow: gptr=51 egptr=10 pptr=10
setg precondition [streambuf.get.area]/5 holds: no

$ ./results/witness_ndebug crash
AddressSanitizer: negative-size-param: (size=-41)   in memcpy, via xsgetn

$ ./results/witness_plain crash                      # no sanitizer at all
Segmentation fault (core dumped)

$ ./results/witness_ndebug write                     # the xsputn site instead
after the write: gptr=50 egptr=15 pptr=15
AddressSanitizer: negative-size-param: (size=-35)
```

The sequence that gets there is write, read part way, `seekp` backwards, then
read on — or write on, for the second site — all of it in contract for
`std::iostream`, and all of it clean on `std::stringbuf`. A debug build behaves
identically: nothing on this path asserts.

**T-2 — end-relative seeks go the wrong way.** Both buffers *subtract* the
offset (`SimpleStreamBuf.cpp:75`, `PreallocatedStreamBuf.cpp:33`) where
[stringbuf.virtuals] table 145 and p11 add it. So the two meanings are
exchanged:

```
                     std::stringbuf   SimpleStreamBuf   PreallocatedStreamBuf
seekg(-3, end)            '7'             FAIL                FAIL
seekg(+3, end)           FAIL             '7'                 '7'
```

`seekg(-3, end)` — the idiomatic "last three bytes" — fails; in a **debug build
it aborts**, at `seekpos`'s own `assert(static_cast<size_t>(pos) <= maxSeek)`.
`seekg(+3, end)`, which is past the end and must fail, quietly lands inside the
buffer. `seekg(0, end)` still works, because zero is its own negation — and that
is the only end-relative seek the SDK performs on these buffers, which is how
this has survived.

**T-3 — a seek that reports success and moves nothing.** `which` is a bitmask,
and `pubseekpos`/`pubseekoff` default it to `in | out`. Both buffers test it with
`==` (`SimpleStreamBuf.cpp:101,106`, `PreallocatedStreamBuf.cpp:61,66`), so
neither branch runs — and the function still returns the position, which means
success. [stringbuf.virtuals] table 144 requires **both** sequences to be
positioned in exactly this case. The SDK's own `EventStreamBuf.cpp:104` returns
`-1` here, so this is a missing case rather than a house convention.

**No untrusted input reaches any of this.** `PreallocatedStreamBuf` carries every
multipart upload part, but nothing in the SDK performs a non-zero end-relative
seek on it, and GitHub code search finds no `pubseekpos` or `pubseekoff` anywhere
in the repository — which bounds nothing on its own, since code search indexes
the default branch and caps its results. `SimpleStreamBuf` is
public exported API everywhere but is wired into the SDK's own types only on
Android with gnustl. These are defects in public API, with the difference from
H-1 that T-1's consequence is memory corruption rather than a wrong value. Full
enumeration in [REPORT.md](REPORT.md) "Reachability".

## Run it

```sh
./reproduce.sh          # 70 checks, ~1 min
```

Needs ESBMC 8.4.0 or 8.5.0 (Bitwuzla and Z3), a C++11 compiler and curl. Each leg
also runs alone: `./reproduce.sh esbmc | sanitizer | tests | reachability | fix`.
Set `CXX` to choose the compiler. Expect **70 passed, 0 failed**; a failure is
what would need explaining, and so is a skip — a leg that cannot run counts
against the total rather than silently shrinking it.

| Leg | What it establishes |
|---|---|
| **ESBMC** | Over *every* seek offset and *every* well-formed get area: where the seek lands, what the return value promises, and that `underflow` can invert the get area |
| **Sanitizers** | T-1 end to end from a public sequence, at both of its sites — the inverted pointers, the unwritten heap byte, the negative `memcpy`, and the SIGSEGV without any sanitizer at all |
| **Tests** | 21 contract rows, 7 of them against `std::stringbuf` as the control: it passes all 7, each AWS buffer fails 4 |
| **Reachability** | The vendored bytes against upstream, and the three call sites that decide who can reach this |
| **Fix** | `fix/streambuf-seek-and-get-area.patch`: every contract row and every ESBMC property goes green |

### ESBMC — proved over every offset, not sampled

Every row agrees under **Bitwuzla and Z3**, and on **ESBMC 8.4.0 and 8.5.0**;
each takes 2–6 s. Each is checked twice — once for the verdict, once for *which*
property the verdict broke, since an unrelated memory-safety check would also
print FAILED. The model's buffer is 8 bytes, so "every offset" below means every
offset of a buffer that size.

| Property, over all inputs of the model | Semantics | Verdict |
|---|---|---|
| `seekg(0, end)` lands one past the last byte (control) | release | **SUCCESSFUL** |
| An end-relative seek lands at `length + off`, or fails | release | **FAILED** — `length=8, off=+1` returns 7 |
| The same, restricted to offsets inside the sequence | release | **FAILED** |
| The same | **debug** | **FAILED** — stops at `SimpleStreamBuf.cpp:95`, the module's assert |
| A successful `seekpos(pos, in\|out)` positioned both sequences | release | **FAILED** — `pos=0`, nothing moved |
| `underflow` leaves `gptr <= egptr` | release | **FAILED** — `gptr=4, egptr=4, pptr=0` |
| Both properties again, on `PreallocatedStreamBuf` | release | **FAILED** |

The control matters twice over. Fix the offset at zero and the same property
verifies, so the failures are not a harness that fails for everything — and
deleting a function body from the slice flips that row from SUCCESSFUL to FAILED,
so it also catches a slice that silently lost the code under test.

The `underflow` row assumes `gptr <= egptr` on entry — what `setg`'s own
precondition guarantees of any state the class built. That is necessary for a
reachable state rather than sufficient, so the row reports that the module can
turn a well-formed get area into a malformed one; the native witness is what
shows it reaching that state from public calls.

Release semantics is `-D NDEBUG`, the macro state of an actual release build, not
ESBMC's `--no-assertions`: that flag also drops `__ESBMC_assert`, so the harness
could not state a property under it.

### Why a slice, and why a stand-in base class

The ESBMC leg analyses the five functions **sliced out of the pristine files at
run time** by `reproduce.sh` — upstream bytes, never a hand-written copy, and the
same leg re-slices the patched files for the fix.

What it cannot use is ESBMC's `std::basic_streambuf`, which declares the ten get-
and put-area members and defines none of them
(`src/cpp/library/streambuf:83-96`). Under that model `setg` writes nowhere and
`gptr()` returns an unconstrained value, so `gptr() <= egptr()` is already
violable on a freshly built buffer — every property here would be about ESBMC
instead of about the SDK. `stubs/esbmc/streambuf_model.h` supplies exactly the
postconditions the standard states for those members, and deliberately not
`setg`'s *precondition*, which is the thing under test.

Two operational-model gaps, both now filed:

| Gap | Where | Issue |
|---|---|---|
| `basic_streambuf`'s `eback`/`gptr`/`egptr`/`gbump`/`setg`/`pbase`/`pptr`/`epptr`/`pbump`/`setp` are declared, never defined | `src/cpp/library/streambuf:83-96` | [esbmc#7539](https://github.com/esbmc/esbmc/issues/7539) |
| `std::streampos` and `std::streamoff` exist only as members of `class ios`, and as `int` | `src/cpp/library/ios:162-163` | [esbmc#7540](https://github.com/esbmc/esbmc/issues/7540) |

They are the successors to esbmc/esbmc#7331-7333 and are why any user-derived
stream buffer is currently unverifiable as written — a search for
`public std::streambuf` over this repository returns eight classes, seven under
`aws/core` and one in the vendored `smithy` tree. The
native legs have no such restriction: they derive from the real `<streambuf>` and
drive the buffers through `std::iostream`, the way an application does.

### Upstream's tests encode T-2

```cpp
    auto seekPos = sizeof(bufferStr) - 5;
    ioStream.seekg(seekPos, std::ios_base::end);
```

— `tests/aws-cpp-sdk-core-tests/utils/stream/PreallocatedStreamBufTest.cpp:68-69`,
and three more like it. A *positive* offset of `length - 5` to reach position 5
is the inverted convention written down. Those four tests pass because the
implementation subtracts, and a fix has to update them.

## Fix

`fix/streambuf-seek-and-get-area.patch` — ten hunks across the two files: the
sign on the end-relative branch, `&` instead of `==` on `which`, the two cases
table 144 says must fail, and

```cpp
-    if(egptr() != pptr())
+    if(egptr() < pptr())
```

at **both** places that hand `setg` an unchecked `pptr()` — `underflow:221` and
`xsputn:197`. The get area may still grow to what has been written and may no
longer shrink behind the position being read from. Guarding only `underflow`
leaves the identical `memcpy` reachable by ending the sequence with a write, so
the fix leg checks both. After the patch, all six ESBMC properties verify under
both solvers and both ESBMC versions, all 21 contract rows pass, and both witness
sequences return what `std::stringbuf` returns.

What it deliberately leaves alone: `seekpos` still aborts a debug build for a
seek that really is out of range, instead of returning `-1` as the API requires.
That was true before the patch too, the fix leg pins it rather than changing it
quietly, and it is the same assert-instead-of-return shape as H-1. The patch also
keeps `pptr()` as "the end", where the standard uses the high-water mark — see
[REPORT.md](REPORT.md) "What the patch does not do".

## Not claimed

- **No untrusted input, and no exploit.** T-1 dies in a `memcpy` whose length the
  caller does not control; what else might be available from it depends on the
  application, and we did not investigate.
- **Nothing about the SDK's other stream buffers.** `EventStreamBuf`,
  `CryptoBuf`, `ConcurrentStreamBuf`, `HttpWriteDataStreamBuf` and
  `StreamBufProtectedWriter` were read, not analysed; the two lines quoted from
  them in [REPORT.md](REPORT.md) are quotations, not results.
- **The Android path is argued, not executed.**
- **Not a regression.** Both files are byte-identical between 1.11.878, where H-1
  was found, and 1.11.884.

Findings generated with AI tools and reviewed by Lucas Cordeiro, University of
Manchester.
