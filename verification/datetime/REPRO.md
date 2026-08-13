# Reproducing D-1 and D-2

**Target:** `aws/aws-sdk-cpp` @ `c84017197daa00de9cc05b1166e9106e1079f7f3` (v1.11.869),
`src/aws-cpp-sdk-core/source/utils/DateTimeCommon.cpp`. `vendor/` holds that file
byte-identical to the tag; `main` is unchanged for it, so HEAD is affected too.

**Everything at once — 11 checks, ~1 min:**

```sh
cd verification/datetime && ./reproduce.sh
```

Needs ESBMC 8.4.0, g++ 13 with libstdc++, and curl. Each leg also runs alone:
`./reproduce.sh esbmc | sanitizer | reachability`.

Both defects are signed-integer overflow (CWE-190). Neither is memory corruption
— see *Not claimed* at the end.

---

## 1. Find it with ESBMC

ESBMC 8.4 cannot parse the real translation unit — its C++ frontend has no
operational model for `std::chrono::system_clock` or `tm`, so `DateTime.h:66`
is a `PARSING ERROR`. The harnesses are therefore line-faithful extractions of
the two arithmetic sites, each cited back to the source line it models.

```sh
cd harnesses
esbmc --overflow-check --unwind 101                     d1_accumulator_esbmc.c
esbmc --overflow-check --unwind 101 -DBOUND_DIGITS=9    d1_accumulator_esbmc.c
esbmc --overflow-check --unwind 2                       d2_time_point_esbmc.c
esbmc --overflow-check --unwind 2 -DASSUME_IN_WINDOW    d2_time_point_esbmc.c
```

| Obligation | Verdict | Meaning |
|---|---|---|
| D-1 unbounded digits | **FAILED** — `!overflow("*", tm_mday, 10)` | a digit run the parser accepts overflows |
| D-1 `-DBOUND_DIGITS=9` | **SUCCESSFUL** | ≤9 digits is safe: 10 is the exact threshold |
| D-2 any in-spec year | **FAILED** — `!overflow("*", seconds, 1000000000)` | witness `seconds=203605488000`, i.e. 8422-01-01 |
| D-2 `-DASSUME_IN_WINDOW` | **SUCCESSFUL** | `\|seconds\| ≤ 9223372036` is exactly the safe range |

Each pair is the finding: the FAILED run shows the overflow is reachable, the
SUCCESSFUL run pins the boundary as a proof rather than a measurement. Both
SUCCESSFUL results were cross-checked under Z3 (`--z3`) as well as Bitwuzla.

## 2. Confirm with sanitizers

Against the unmodified 1.11.869 file, no extraction involved:

```sh
g++ -std=c++11 -g -O0 -fsanitize=undefined -fno-sanitize-recover=all \
    -Istubs -Ivendor -Ivendor/include \
    harnesses/datetime_parse_asan.cpp vendor/source/utils/DateTimeCommon.cpp \
    stubs/aws_platform_time_stub.cpp -o results/dt_trap

./results/dt_trap rfc822 "Wed, 99999999999999999999 Oct 2002 08:00:00 GMT"
# DateTimeCommon.cpp:482:79: runtime error: signed integer overflow:
#     999999999 * 10 cannot be represented in type 'int'
```

Same build line with `datetime_range_ubsan.cpp` for D-2. It prints three in-range
dates, then traps on 2262-04-12:

```
2262-04-11T00:00:00Z    past_boundary=0 valid=1 millis=9223286400000
/usr/include/c++/13/bits/chrono.h:225:38: runtime error: signed integer overflow:
    9223372800 * 1000000000 cannot be represented in type 'long int'
```

That harness doubles as the regression: it exits 0 on fixed sources and aborts
on unfixed ones.

## 3. Confirm reachability

Both parsers take HTTP **response** headers straight off the wire. Checked
against the pinned commit, not inferred:

| Site | Why it matters |
|---|---|
| `AWSClient.cpp:219,223` | `x-amz-date` / `Date` response headers → `AutoDetect`, on the `AdjustClockSkew` error path |
| `DateTimeCommon.cpp` `case AutoDetect` | tries **RFC822 first**, so it hits the one escaping accumulator |
| `GetObjectResult.cpp:53,189` | S3 `Last-Modified` and `Expires` → `RFC822` directly; other generated result types repeat the pattern (`HeadObjectResult` has two such sites) |
| `PutObjectRequest.h:610` | `SetExpires` — in a shared bucket the `Expires` value is chosen by *another user*, not by the endpoint you trust |

`AdjustClockSkew` gates on `WasParseSuccessful()`, which returns true here, so the
wrong `DateTime` is used rather than discarded.

---

## The two defects

**D-1** — `DateTimeCommon.cpp:482`, `tm_mday = tm_mday * 10 + (c - '0')`, with no
bound on digit count; the only guard is `len > MAX_LEN` at 100. 12 of the 17
accumulators are delimiter-driven and overflow; only RFC822 state 2 leaves the
field on *any* space, so it alone lets the corrupted value escape a successful
parse. The two ISO parsers overflow but always return `valid=0`.

**D-2** — `DateTime` converts a parsed `tm` to `system_clock::time_point` with no
range check. libstdc++'s clock is nanoseconds, so int64 saturates ≈292 years out.
Anything outside **1677-09-22 … 2262-04-11** overflows. No malformed input is
needed:

```
Thu, 31 Dec 9999 23:59:59 GMT  ->  valid=1, 1816-03-30T05:56:08Z
```

That is the conventional HTTP "never expires" sentinel, and "never expires"
becomes "expired 210 years ago", reported as a successful parse.

## Fix

`fix/d1-bound-field-widths.patch` bounds each delimiter-driven accumulator by its
field width; 12 hunks, applies clean to the pristine file. Validated both ways on
2026-08-13: all D-1 reproducers stop overflowing and return `valid=0`, and a
19-case corpus of valid input gives byte-identical `valid`/`millis` against
patched and pristine sources.

No patch for D-2 — the remedy is a compatibility decision (reject, clamp, or
widen the representation, the last being an ABI change) that belongs to AWS.

## Not claimed

- **No memory corruption.** No OOB read or write; ASan is clean. Arithmetic UB only.
- **No demonstrated downstream security decision.** The 1816 value is
  application-dependent; we show the UB, the sign inversion, and the reachability.
- **Ordinary builds do not crash.** At `-O2` the overflow wraps silently and the
  effect is a wrong `DateTime`. Aborting needs `-ftrapv` or
  `-fno-sanitize-recover`, i.e. a hardened build — there it is a remote abort.
- **A wrong date alone is not the defect** — `day=99` already normalises to
  2003-01-07 with no UB. What overflow adds is that the value is UB-dependent.
- **The clock-skew path is not an escalation.** It does take the bad branch, but a
  valid `Date` header already grants the same power by design.
- **D-2 is libstdc++-specific.** libc++'s `system_clock` is microseconds and does
  not saturate until ≈294247. The boundary is a property of the standard library.
