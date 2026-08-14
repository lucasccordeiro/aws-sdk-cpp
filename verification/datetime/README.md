# Integer-overflow UB in `Aws::Utils::DateTime` — D-1 and D-2

Two signed-integer-overflow defects (CWE-190) in
`src/aws-cpp-sdk-core/source/utils/DateTimeCommon.cpp`, at v1.11.869
(`c84017197daa00de9cc05b1166e9106e1079f7f3`). `main` is byte-identical for that
file, so HEAD is affected. `vendor/` holds it unmodified; nothing here patches
the SDK before testing it.

**D-2 — the one we would prioritise.** `DateTime` converts a parsed timestamp to
`std::chrono::system_clock::time_point` with no range check. On libstdc++ that
clock counts nanoseconds, so `int64` overflows for any date outside
**1677-09-22 … 2262-04-11**. No malformed input is involved:

```
Thu, 31 Dec 9999 23:59:59 GMT  ->  valid=1, 1816-03-30T05:56:08Z
```

That is the conventional HTTP *never expires* value. It reaches
`GetObjectResult`'s `Expires` from a value another user set via
`PutObjectRequest::SetExpires`, and "never expires" is reported as "expired 210
years ago" — as a *successful* parse. Hardened builds (`-ftrapv`,
`-fno-sanitize-recover`) abort instead.

**D-1.** `DateTimeCommon.cpp:482` accumulates the RFC822 day digit by digit with
no bound on digit count; the only guard is `len > MAX_LEN` at 100. 12 of the 17
accumulators overflow, but only RFC822 state 2 advances on *any* space, so it
alone lets the corrupted value escape a successful parse. Input arrives from a
response header. A validated patch is in `fix/`.

## Run it

```sh
./reproduce.sh          # 17 checks, ~1 min
```

Needs ESBMC 8.4.0, a C++11 compiler and curl. Each leg also runs alone:
`./reproduce.sh esbmc | sanitizer | tests | reachability`. Set `CXX` to choose
the compiler.

**Platform.** D-2's *runtime* legs need a nanosecond `system_clock`, i.e.
libstdc++. On libc++ — the default on macOS — that clock counts microseconds and
does not saturate until ≈294247, so these dates are in range and the D-2 checks
report SKIP rather than a spurious failure. D-1 traps everywhere: it overflows an
`int`. The ESBMC leg proves D-2 on any host, because it models the
seconds-to-nanoseconds conversion explicitly rather than inheriting the host's
clock. Expect **17 passed, 0 failed** on libstdc++ and **14 passed, 0 failed**
with two skips on libc++; either way the script exits 0, and a *failure* is what
would need explaining.

| Leg | What it establishes |
|---|---|
| **ESBMC** | Both overflows are reachable, and the safe boundary is exact |
| **UBSan** | Both trap on the pristine 1.11.869 file — `DateTimeCommon.cpp:482` and `bits/chrono.h:225` |
| **Tests** | Ordinary `-O0` build, no sanitizer: on libstdc++ 6 of 10 contract cases fail, printing the wrong dates |
| **Reachability** | The response-header paths that carry attacker-influenced input, read off the pinned commit |

### ESBMC — the boundaries are proved, not measured

| Obligation | Verdict |
|---|---|
| D-1, unbounded digits | **FAILED** — `!overflow("*", tm_mday, 10)` |
| D-1, `-DBOUND_DIGITS=9` | **SUCCESSFUL** — ≤9 digits is safe, so 10 is the exact threshold |
| D-2, any in-spec year | **FAILED** — witness `seconds=203605488000` (8422-01-01) |
| D-2, `-DASSUME_IN_WINDOW` | **SUCCESSFUL** — `\|seconds\| ≤ 9223372036` is exactly the safe range |

Each pair is the finding: FAILED shows the overflow is reachable, SUCCESSFUL
pins the boundary. Both SUCCESSFUL runs agree under Bitwuzla and Z3.

### Reachability, read off the pinned commit

| Site | Why it matters |
|---|---|
| `AWSClient.cpp:219,223` | `x-amz-date` / `Date` **response** headers → `AutoDetect`, on the `AdjustClockSkew` path |
| `DateTimeCommon.cpp` `case AutoDetect` | tries **RFC822 first**, so it hits the one escaping accumulator |
| `GetObjectResult.cpp:53,189` | S3 `Last-Modified` and `Expires` → `RFC822`; ~60 other generated result types repeat the shape |
| `PutObjectRequest.h:610` | `SetExpires` — in a shared bucket the `Expires` value is chosen by another *user* |

## Fix

`fix/d1-bound-field-widths.patch` bounds each delimiter-driven accumulator by
its field width; 12 hunks, applies clean to the pristine file. It turns the two
day-field test cases green and leaves the four D-2 cases failing. Validated on
2026-08-13: all D-1 reproducers stop overflowing and return `valid=0`, and a
19-case corpus of valid input gives byte-identical `valid`/`millis` against
patched and pristine sources.

No patch for D-2: the remedy is a compatibility decision — reject, clamp, or
widen the representation (an ABI change) — that belongs to AWS.

## Not claimed

- **No memory corruption.** No OOB read or write; ASan is clean. Arithmetic UB only.
- **No downstream security decision demonstrated.** We show the UB, the
  inversion, and the reachability; what a caller does with the 1816 value is
  application-dependent.
- **Ordinary builds do not crash.** At `-O2` the overflow wraps silently and the
  effect is a wrong `DateTime`; aborting needs a hardened build.
- **D-2 is libstdc++-specific.** libc++'s `system_clock` is microseconds and
  does not saturate until ≈294247. The boundary is a property of the standard
  library, not of the SDK.

Findings generated with AI tools and reviewed by Lucas Cordeiro, University of
Manchester.
