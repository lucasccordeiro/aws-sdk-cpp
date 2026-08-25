# DateTime — findings

**Target:** `aws/aws-sdk-cpp` @ `c84017197daa00de9cc05b1166e9106e1079f7f3` (v1.11.869)
**Under analysis:** the three `DateParser` state machines and the
timestamp→`time_point` conversion in
`src/aws-cpp-sdk-core/source/utils/DateTimeCommon.cpp`
**Tool:** GCC 13 + UndefinedBehaviorSanitizer
**Provenance:** `vendor/source/utils/DateTimeCommon.cpp` is byte-identical to the
1.11.869 tag (`diff` against `raw.githubusercontent.com`, re-checked 2026-08-13).

---

## Disclosure and upstream status

Both defects were reported to AWS Security on **2026-08-18** under coordinated
disclosure. AWS fixed them in
[PR #3896](https://github.com/aws/aws-sdk-cpp/pull/3896) — "Validate DateTime
range and bound parser field widths (defense in depth)" — merged **2026-08-24**
as `70836bcd62c7fdc907b28e28f5f4e825806e78f2` and first tagged in
**[1.11.877](https://github.com/aws/aws-sdk-cpp/releases/tag/1.11.877)**.
Everything up to and including 1.11.876 is affected: `vendor/` is pinned at
1.11.869 and that file is byte-identical at 1.11.876.

| Here | How it was fixed |
|---|---|
| **D-1** unbounded digit accumulators | `fix/d1-bound-field-widths.patch` taken verbatim — 12 sites bounded by field width |
| **D-2** `time_point` conversion overflow | `IsSecondsSinceEpochRepresentable`, a range check before `from_time_t`; out-of-range input now fails the parse |

Unlike B-1/B-2 this shipped as a **defense-in-depth** change: no GitHub
advisory, no CVE, no security bulletin. That matches what was reported —
neither defect is memory corruption, and no downstream security decision was
demonstrated (see *What this is not*). The merge commit credits Lucas Carvalho
Cordeiro and Rafael Sa Menezes of the University of Manchester, "who reported
these issues and supplied the field-width patch, via the coordinated
vulnerability disclosure process."

`./reproduce.sh fix` re-runs the reproducers against the 1.11.877 file: the
parser side is our patch unchanged, and all 10 contract cases hold — 6 of them
failed on 1.11.869 — with no UB under `-fno-sanitize-recover=all`.

---

## D-1 — signed integer overflow in the digit accumulators

Every state machine accumulates digits into an `int` field of `m_parsedTimestamp`
with no bound on the digit count:

```cpp
m_parsedTimestamp.tm_mday = m_parsedTimestamp.tm_mday * 10 + (c - '0');
```

The only input-length guard is `len > MAX_LEN` with `MAX_LEN == 100`
(`DateTimeCommon.cpp:409`), and a ten-digit run fits inside that comfortably.
Signed overflow is UB — C++ [expr.arith.conv]/[basic.fundamental]; `int` is not
required to wrap.

Of the 17 accumulation sites, 12 sit in states that advance on a **delimiter**
and can therefore be fed unlimited digits — RFC822 `:482,530,545,560,575`,
ISO_8601 `:751,767,783,799,815,837`, ISO_8601_BASIC `:988`. The other 5 —
ISO_8601_BASIC `:949,966,999,1015,1031` — advance on a **digit count**
(`if (index - stateStartIndex == N) { m_state++; }`), are self-bounding, and do
not overflow.

### Two distinct overflows, with different trigger thresholds

| # | Site | Digits needed | Escapes? |
|---|---|---|---|
| D-1a | `DateTimeCommon.cpp:482` — `tm_mday` in RFC822 | ≥ 10 | **yes** |
| D-1b | `bits/chrono.h:225` — seconds→nanoseconds, `int64` | ≥ 9 | **yes** |

D-1b is the more easily reached of the two: a nine-digit day (`999999999`) fits
in an `int` without overflowing the accumulator, but the resulting out-of-range
`tm_mday` overflows `long int` in the `chrono` duration conversion. No
accumulator overflow is required to reach it.

### Only RFC822 lets the corrupted value escape

ISO_8601 and ISO_8601_BASIC overflow too, but every state transition in those two
is gated on a delimiter at a fixed offset (`index - stateStartIndex == 2` or `== 4`),
so an input long enough to overflow can never reach the final state — those parses
always return `valid=0`. The UB happens, but no value escapes.

RFC822 state 2 is the exception: it leaves the day field on *any* `isspace(c)`
with no offset check (`:484`), so an arbitrarily long digit run overflows and
then transitions normally. RFC822 states 4–7 are offset-bound like the others.
`tm_mday` at `:482` is the single escaping accumulator in the file.

Consequence — the parse **succeeds** and yields a wrong date:

```
input                                        valid  result
Wed, 02 Oct 2002 08:00:00 GMT                  1    2002-10-02T08:00:00Z   (baseline)
Wed, 999999999 Oct 2002 08:00:00 GMT           1    1858-08-02T01:52:25Z   (D-1b)
Wed, 99999999999999999999 Oct 2002 ... GMT     1    2216-03-12T20:10:44Z   (D-1a + D-1b)
```

Note that a *wrong date* on its own is not the finding: `day=99` already
normalises to 2003-01-07 through ordinary `timegm` behaviour, with no UB. What
overflow adds is that the resulting value is UB-dependent and therefore not
predictable across compilers or optimisation levels.

## Reachability — confirmed against upstream, not inferred

Both parsers take HTTP **response** header values straight from the wire.
Verified by reading the 1.11.869 sources, not from recall:

- `src/aws-cpp-sdk-core/source/client/AWSClient.cpp:219,223` —
  `GetServerTimeFromError` parses the `x-amz-date` / `Date` response header with
  `DateFormat::AutoDetect`, on the `AdjustClockSkew` path taken for error
  responses. `AutoDetect` tries **RFC822 first** (`DateTimeCommon.cpp:1458`), so
  it reaches the one escaping accumulator.
- `generated/src/aws-cpp-sdk-s3/source/model/GetObjectResult.cpp:53,189` —
  `Last-Modified` and `Expires` parsed with `DateFormat::RFC822` directly. The
  same pattern appears in `HeadObjectResult`, `ListPartsResult`,
  `GetObjectAttributesResult`, and 60-odd other generated result types.

Because `AdjustClockSkew` checks `WasParseSuccessful()` and that returns true
here, the garbage `DateTime` is passed on to `DateTime::Diff` rather than being
discarded.

## What this is not

- **No memory corruption.** No out-of-bounds read or write; ASan is clean. This
  is arithmetic UB only, not the class of defect B-1/B-2 or U-1 were.
- **Server→client only.** The trust boundary crossed is a response from a
  malicious, compromised, or MITM'd endpoint — not ordinary client input.
- **Silent in ordinary builds.** At `-O2` the overflow wraps and the only effect
  is a wrong `DateTime`. The crash requires `-fsanitize=undefined
  -fno-sanitize-recover` or `-ftrapv`, i.e. a hardened build, where it is a
  remote abort.

## Reproducing

```sh
cd verification/datetime
g++ -std=c++11 -g -O0 -fsanitize=undefined -fno-sanitize-recover=all \
    -Istubs -Ivendor -Ivendor/include \
    harnesses/datetime_parse_asan.cpp vendor/source/utils/DateTimeCommon.cpp \
    stubs/aws_platform_time_stub.cpp -o results/dt_trap

results/dt_trap rfc822 "Wed, 99999999999999999999 Oct 2002 08:00:00 GMT"
results/dt_trap autodetect "99999999999999999999-01-01T00:00:00Z"
```

Observed (2026-08-13, GCC 13, clean rebuild):

```
DateTimeCommon.cpp:482:79: runtime error: signed integer overflow:
    999999999 * 10 cannot be represented in type 'int'
chrono.h:225:38: runtime error: signed integer overflow:
    143597225030400 * 1000000000 cannot be represented in type 'long int'
```

## Correction to the 2026-08-13 working notes

An earlier pass recorded two claims that this run refutes:

1. *"ISO_8601_BASIC rejects the same input without overflowing"* — false. It
   overflows at `:988`; it merely does not let the value escape.
2. *"No wrong date is ever accepted"* — false for RFC822, which is precisely the
   wire-reachable format. It holds only for the two ISO formats.

Both errors understated the finding.

---

## D-2 — int64 overflow converting an in-spec date to a `time_point`

Investigating whether bounding the accumulators would also fix the `chrono`
overflow showed that it would not, because that overflow **is not a malformed-input
bug at all**. It fires on well-formed, in-spec timestamps that every parser
accepts by design.

`libstdc++`'s `system_clock::duration` is nanoseconds, so its `int64`
representation saturates ≈292 years after the epoch. `DateTime` converts a parsed
`tm` into a `time_point` with no range check, so the seconds→nanoseconds
`duration_cast` (`bits/chrono.h:225`) overflows for any date past the boundary.

The representable window was measured from both ends —
**1677-09-22 through 2262-04-11**. Anything outside it overflows:

```
1677-09-21T00:00:00Z   signed integer overflow
1677-09-22T00:00:00Z   clean
2262-04-11T23:47:16Z   clean
2262-04-12T00:00:00Z   signed integer overflow
```

The lower bound matters as well as the upper: historical timestamps before 1677
— a plausible `Last-Modified` or an archival date in a JSON/XML body — overflow
just as readily. `0001-01-01T00:00:00Z` parses "successfully" to a wrapped value.

### Why this matters more than D-1

No malformed input and no malicious actor is required. `Thu, 31 Dec 9999
23:59:59 GMT` is the conventional HTTP "never expires" sentinel, and S3 returns
an `Expires` header whose value an **uploader** chooses via
`PutObjectRequest::SetExpires` (`PutObjectRequest.h:610`). So in a shared bucket
the value is cross-user attacker-settable, and it is also a value ordinary
well-behaved software emits on purpose.

Parsed on the `GetObjectResult.cpp:189` `Expires` path — which is not behind any
feature flag — the result is:

```
Thu, 31 Dec 9999 23:59:59 GMT  ->  valid=1, 1816-03-30T05:56:08Z
```

"Never expires" becomes "expired 210 years ago" — a sign inversion, reported as a
successful parse. In a `-ftrapv` / `-fno-sanitize-recover` build the same input
aborts the client instead.

I have **not** shown that any specific caller makes a security decision on that
1816 value; what happens downstream is application-dependent, and that claim
should not be made without evidence. The demonstrated facts are the UB, the
inversion, and the reachability.

### The clock-skew path is *not* an escalation — negative result

`AdjustClockSkew` was the obvious place to look for downstream impact, and it
does take the bad branch: `WasParseSuccessful()` returns true, `Diff` against the
signing timestamp yields ≈-186 years, that clears the ±4 minute
`TIME_DIFF_MAX`/`MIN` gate (`AWSClient.cpp:72-74,250`), and `SetClockSkew` stores
the garbage offset for subsequent signing.

It is still not worth reporting as an escalation, because **a perfectly valid
`Date` header already grants the same power by design** — trusting the server's
clock is what the feature is for, and a valid in-range date can move the skew by
up to ~236 years anyway. The overflow buys an attacker nothing here.

`DateTime::Diff` itself was checked separately and adds no UB of its own
(`DateTimeCommon.cpp:1412`): it subtracts two already-wrapped `time_point`s and
the result stays in range. Do not re-litigate either of these.

What distinguishes D-2 from ordinary designed trust is therefore narrower and
should be stated as such: the abort in hardened builds, and the sign inversion on
`Expires`, where the value comes from another *user* rather than from the
endpoint the client has chosen to trust.

### Platform caveat

This is a **Linux/libstdc++ finding**. `libc++` uses a microsecond
`system_clock`, whose `int64` does not saturate until ≈294247, so these inputs do
not overflow there. The boundary is a property of the standard library, not of
the SDK.

### Regression

`harnesses/datetime_range_ubsan.cpp` covers three in-range cases (which a fix
must keep working) and five past the boundary. Built with
`-fsanitize=undefined -fno-sanitize-recover=all` it exits 0 on fixed sources and
aborts on unfixed ones — confirmed aborting against 1.11.869 on 2026-08-13, and
exiting 0 against the fixed 1.11.877 file on 2026-08-25.

---

## Suggested fixes

**D-1 — written and validated: `fix/d1-bound-field-widths.patch`.** Bounds each
of the 12 delimiter-driven accumulators by its field width
(`isdigit(c) && index - stateStartIndex < N`), so a digit past the field falls
through to the existing `else` and sets `m_error`. Widths are 4 for the ISO year
and the RFC822 4-digit year, 2 elsewhere — RFC 5322 §3.3 gives the RFC822 day as
1–2 digits. The 5 count-driven states are untouched. 12 hunks; applies clean to
the pristine 1.11.869 file.

Validated two ways, both on 2026-08-13:

- **UB removed.** All D-1 reproducers (RFC822 10- and 20-digit day, ISO_8601,
  ISO_8601_BASIC, AutoDetect) run clean under `-fno-sanitize-recover=all` and
  now return `valid=0` instead of overflowing.
- **No over-rejection.** A 19-case corpus of valid input — 1- and 2-digit RFC822
  days, 2- and 4-digit RFC822 years, fractional seconds to 9 places, `+05:30` /
  `-08:00` offsets, ISO_8601_BASIC, AutoDetect, epoch, year 0001 — produces
  byte-identical `valid`/`millis` against patched and pristine sources. A fix
  that tightened parsing would be worse than the bug; this one does not.

This patch does **not** address D-2, which is a separate defect.

**D-2** — range-check before converting to `time_point`. The remedy is a
compatibility decision that belongs to AWS, not to this report: rejecting
post-2262 dates changes `WasParseSuccessful()` for input that currently
"succeeds"; clamping to `time_point::max()` preserves the parse but still yields
a wrong value; widening the internal representation avoids both but is an ABI
change. No patch is proposed here for that reason.

## What AWS shipped

**D-1: the patch above, unchanged.** Confirmed by construction — applying
`fix/d1-bound-field-widths.patch` to the pristine file and diffing against
1.11.877 leaves no difference anywhere in the three parsers. The only additions
are on the D-2 side.

**D-2: reject**, the first of the three options weighed above.
`IsSecondsSinceEpochRepresentable` derives the window from
`system_clock::time_point::min()/max()`, and `ConvertTimestampStringToTimePoint`
sets `m_valid = false` and logs a warning rather than converting when the parsed
`time_t` falls outside it. Deriving the bound instead of hard-coding it keeps
libc++ builds on their own wider window, so nothing that already parsed there
stops parsing.

The compatibility cost is the one anticipated: `WasParseSuccessful()` now
returns false for input that used to "succeed", including the HTTP never-expires
sentinel on any nanosecond-clock build. A caller that treated a parsed `Expires`
as authoritative now sees an invalid `DateTime` rather than a 1816 timestamp —
which is the point, but it is a behaviour change on valid wire input.

PR #3896 also adds 12 GTest cases to
`tests/aws-cpp-sdk-core-tests/utils/DateTimeTest.cpp`: both boundaries and one
day past each, the sentinel through RFC822, ISO-8601 and AutoDetect, and the
9- and 20-digit day inputs — the same shapes as `harnesses/datetime_cases.cpp`,
guarded the same way on `system_clock::period` so they skip rather than fail
where the window is wider.
