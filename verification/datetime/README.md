# Integer-overflow UB in `Aws::Utils::DateTime` — D-1 and D-2

Two signed-integer-overflow defects (CWE-190) in
`src/aws-cpp-sdk-core/source/utils/DateTimeCommon.cpp`, found at v1.11.869
(`c84017197daa00de9cc05b1166e9106e1079f7f3`) and present in every release up to
1.11.876. `vendor/` holds that file unmodified; nothing here patches the SDK
before testing it.

**Fixed upstream in [1.11.877](https://github.com/aws/aws-sdk-cpp/releases/tag/1.11.877).**
Reported to AWS Security on 2026-08-18 and closed by
[PR #3896](https://github.com/aws/aws-sdk-cpp/pull/3896), merged 2026-08-24. AWS
took the D-1 patch in `fix/` verbatim and added its own range check for D-2. No
CVE was assigned — AWS classed the change as defense in depth — and the merge
commit credits Lucas Carvalho Cordeiro and Rafael Sa Menezes, University of
Manchester. `./reproduce.sh fix` re-runs both findings against the shipped file.

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
./reproduce.sh          # 22 checks, ~1 min
```

Needs ESBMC 8.4.0, a C++11 compiler and curl. Each leg also runs alone:
`./reproduce.sh esbmc | sanitizer | tests | reachability | fix`. Set `CXX` to
choose the compiler. A sixth leg, `module`, re-runs the two ESBMC obligations
against the whole translation unit instead of the extracted models; it is
minutes per obligation rather than seconds, so `all` leaves it out.

**Platform.** D-2's *runtime* legs need a nanosecond `system_clock`, i.e.
libstdc++. On libc++ — the default on macOS — that clock counts microseconds and
does not saturate until ≈294247, so these dates are in range and the D-2 checks
report SKIP rather than a spurious failure. D-1 traps everywhere: it overflows an
`int`. The ESBMC leg proves D-2 on any host, because it models the
seconds-to-nanoseconds conversion explicitly rather than inheriting the host's
clock. Expect **22 passed, 0 failed** on libstdc++ and **18 passed, 0 failed**
with three skips on libc++; either way the script exits 0, and a *failure* is
what would need explaining.

| Leg | What it establishes |
|---|---|
| **ESBMC** | Both overflows are reachable, and the safe boundary is exact |
| **UBSan** | Both trap on the pristine 1.11.869 file — `DateTimeCommon.cpp:482` and `bits/chrono.h:225` |
| **Tests** | Ordinary `-O0` build, no sanitizer: on libstdc++ 6 of 10 contract cases fail, printing the wrong dates |
| **Reachability** | The response-header paths that carry attacker-influenced input, read off the pinned commit |
| **Fix** | The same reproducers against 1.11.877: both defects gone, and the parser hunks are ours unchanged |
| **Module** (opt-in) | The two ESBMC obligations against the real `DateTimeCommon.cpp`, both versions |

### ESBMC — the boundaries are proved, not measured

| Obligation | Verdict |
|---|---|
| D-1, unbounded digits | **FAILED** — `!overflow("*", tm_mday, 10)` |
| D-1, `-DBOUND_DIGITS=9` | **SUCCESSFUL** — ≤9 digits is safe, so 10 is the exact threshold |
| D-2, any in-spec year | **FAILED** — witness `seconds=203605488000` (8422-01-01) |
| D-2, `-DASSUME_IN_WINDOW` | **SUCCESSFUL** — `\|seconds\| ≤ 9223372036` is exactly the safe range |

Each pair is the finding: FAILED shows the overflow is reachable, SUCCESSFUL
pins the boundary. Both SUCCESSFUL runs agree under Bitwuzla and Z3.

### The same properties, on the module itself

The obligations above run against line-faithful *extractions*
(`d1_accumulator_esbmc.c`, `d2_time_point_esbmc.c`) — which is what ESBMC could
manage when they were written, because the real translation unit did not parse.
It does now: esbmc/esbmc#7141 modelled `timegm`, and #7138-7140 removed the
`basic_string` false positives. So `./reproduce.sh module` puts the same two
properties to `vendor/source/utils/DateTimeCommon.cpp` itself, with 1.11.877
beside it.

| Obligation | Source | Verdict |
|---|---|---|
| D-1, 20-digit RFC822 day | 1.11.869 | **FAILED** — `!overflow("*", …tm_mday, 10)` at `DateTimeCommon.cpp:482` |
| D-1, same input | 1.11.877 | **SUCCESSFUL** — 362 properties, unwinding assertions passed |
| D-2, ordinary ISO 8601 date | 1.11.869 | **FAILED** — `arithmetic overflow on mul` in `<chrono>` |
| D-2, same input | 1.11.877 | **SUCCESSFUL** — 232 properties, unwinding assertions passed |

Two things make the SUCCESSFUL rows worth more than the ten contract cases. The
unwind is **complete** — the unwinding assertions pass rather than being
suppressed, so no truncated loop is being read as a proof — and ESBMC models
`timegm` as returning an unconstrained `time_t`, so the range check is shown to
hold for *every* seconds value a parse could yield rather than for the dates
someone thought to try. Only the SUCCESSFUL direction needs the full unwind; a
counterexample is sound at any depth, which is why the two directions run at
different bounds.

**Cost**, measured with `/usr/bin/time -v` on 2026-08-25 (ESBMC 8.4.0,
Bitwuzla, 32 cores):

| Obligation | Peak RSS | Wall |
|---|---|---|
| D-2, either source | 0.6 GB | 18–28 s |
| D-1, either source | 1.7 GB | ~5m45s |

D-1 is the expensive half because `strlen` unwinds once per character, so its
46-character input needs ~47 iterations before the parse loop is even entered.
There is no cheaper bound — dropping to `--unwind 20` does not find the overflow
sooner, it just truncates `strlen` and reaches nothing. The leg checks free
memory before starting the D-1 pair and skips below 4 GB, so that a host with no
headroom cannot OOM-kill a proof and leave a half-finished log that reads like a
clean run.

`--include-file cctype` is needed throughout: ESBMC's `<iostream>` and
`<cstring>` do not pull in `<cctype>` transitively, and the standard does not
require them to. A forced include keeps `vendor/` pristine where an edit would
not.

Solver coverage is uneven, and the table should be read with that in mind. Both
D-2 rows agree under Bitwuzla and Z3. The D-1 SUCCESSFUL row is **Bitwuzla
only** — Z3 was still unwinding after 40 minutes on a host at load 38 and never
reached a verdict, so that row is single-solver until it is re-run somewhere
quiet. All four rows were measured through the `-D` wiring the leg uses, not
with the input inlined in the harness.

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

We proposed no patch for D-2, because the remedy is a compatibility decision —
reject, clamp, or widen the representation (an ABI change) — that belonged to
AWS.

### What 1.11.877 shipped

The D-1 patch went in unchanged: the parser side of `DateTimeCommon.cpp` at
1.11.877 is byte-identical to the pristine file with `fix/` applied, which
`./reproduce.sh fix` checks by diffing the two. AWS chose **reject** for D-2:

```cpp
if (IsSecondsSinceEpochRepresentable(tt))
    m_time = std::chrono::system_clock::from_time_t(tt);
else
    m_valid = false;   // and log a warning
```

The window is read off `system_clock::time_point::min()/max()` rather than
hard-coded, so each platform gets its own — on libstdc++ exactly the
`|seconds| ≤ 9223372036` bound the ESBMC leg proved, and ~1000× wider on libc++.
Rebuilding the harnesses against that file under `-fno-sanitize-recover=all`:
all 10 contract cases hold where 6 failed before, the never-expires sentinel
comes back `valid=0` instead of 1816, and neither overflow trips. PR #3896 also
carries 12 GTest cases of its own covering the same boundaries.

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
