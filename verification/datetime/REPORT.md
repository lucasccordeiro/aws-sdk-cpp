# DateTime parsers — findings

**Target:** `aws/aws-sdk-cpp` @ `c84017197daa00de9cc05b1166e9106e1079f7f3` (v1.11.869)
**Under analysis:** the three `DateParser` state machines in
`src/aws-cpp-sdk-core/source/utils/DateTimeCommon.cpp`
**Tool:** GCC 13 + UndefinedBehaviorSanitizer
**Provenance:** `vendor/source/utils/DateTimeCommon.cpp` is byte-identical to the
1.11.869 tag (`diff` against `raw.githubusercontent.com`, re-checked 2026-08-13).

**Status: HELD — not reported upstream, not published.**

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

## Suggested fix

Bound each accumulator by digit count before multiplying — the ISO parsers
already know the expected field width, and RFC822 day is 1–2 digits per RFC 5322
§3.3. Rejecting a field that exceeds its width both removes the UB and makes
RFC822 agree with the ISO parsers on rejecting malformed input.
