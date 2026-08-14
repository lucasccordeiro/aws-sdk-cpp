/**
 * Executable test cases for D-1 and D-2 -- ordinary build, no sanitizer.
 *
 * Each case states the contract a correct DateTime must meet; the runner prints
 * what 1.11.869 actually returns and exits non-zero on any mismatch. It fails
 * on unfixed sources and passes once the conversion is range-checked, so it
 * doubles as the regression test for a fix.
 *
 * D-2's window is set by system_clock::period, which is implementation-defined:
 * libstdc++ counts nanoseconds (int64 saturates ~292 years from the epoch),
 * libc++ microseconds (~292,000 years). Cases whose input falls inside the
 * running platform's window are reported SKIP, not PASS -- their contract holds
 * there for a reason that says nothing about the defect.
 *
 * Build at -O0: the wrapped values below are the result of signed-overflow UB,
 * so they are what this compiler produces, not values the standard guarantees.
 */

#include <aws/core/utils/DateTime.h>

#include <chrono>
#include <cstdint>
#include <cstdio>

namespace
{
using Aws::Utils::DateFormat;

// 2262-04-11T00:00:00Z, the last instant libstdc++'s nanosecond system_clock
// represents. Anything later overflows the seconds-to-nanoseconds conversion.
const int64_t BOUNDARY_MS = 9223286400000LL;

enum Rule
{
  EXACT,      // must parse to this instant
  NOT_PAST,   // a future timestamp must not come back as a past one
  NOT_FUTURE, // a pre-epoch timestamp must not come back as a future one
  REJECT      // not a date: must fail the parse
};

struct Case
{
  const char *input;
  DateFormat format;
  const char *format_name;
  Rule rule;
  int64_t expected_ms;
  bool needs_ns_clock; // input is inside the microsecond window
  const char *contract;
};

const Case CASES[] = {
  {"2002-10-02T08:00:00Z", DateFormat::ISO_8601, "iso8601", EXACT,
   1033545600000LL, false, "an ordinary ISO 8601 timestamp round-trips"},
  {"Wed, 02 Oct 2002 08:00:00 GMT", DateFormat::RFC822, "rfc822", EXACT,
   1033545600000LL, false, "an ordinary RFC 822 timestamp round-trips"},
  {"2262-04-11T00:00:00Z", DateFormat::ISO_8601, "iso8601", EXACT, BOUNDARY_MS,
   false, "the last instant libstdc++ represents still parses"},
  {"1677-09-22T00:00:00Z", DateFormat::ISO_8601, "iso8601", EXACT,
   -BOUNDARY_MS, false, "so does the first one"},

  {"2262-04-12T00:00:00Z", DateFormat::ISO_8601, "iso8601", NOT_PAST, 0, true,
   "one day past the boundary: reject or stay in the future"},
  {"Thu, 31 Dec 9999 23:59:59 GMT", DateFormat::RFC822, "rfc822", NOT_PAST, 0,
   true, "the HTTP never-expires sentinel: reject or stay in the future"},
  {"Thu, 31 Dec 9999 23:59:59 GMT", DateFormat::AutoDetect, "autodetect",
   NOT_PAST, 0, true, "same sentinel through AutoDetect, as AWSClient uses it"},
  {"1600-01-01T00:00:00Z", DateFormat::ISO_8601, "iso8601", NOT_FUTURE, 0, true,
   "an archival timestamp: reject or stay in the past"},

  // Beyond every platform's window: ~2.7 million years of days, so the
  // conversion overflows on a microsecond clock too.
  {"Wed, 999999999 Oct 2002 08:00:00 GMT", DateFormat::RFC822, "rfc822",
   NOT_PAST, 0, false, "a nine-digit day: reject or normalise into the future"},
  {"Wed, 99999999999999999999 Oct 2002 08:00:00 GMT", DateFormat::RFC822,
   "rfc822", REJECT, 0, false, "a twenty-digit day is not a date"},
};

bool holds(const Case &c, bool valid, int64_t millis)
{
  switch (c.rule)
  {
  case EXACT:
    return valid && millis == c.expected_ms;
  case NOT_PAST:
    return !valid || millis >= BOUNDARY_MS;
  case NOT_FUTURE:
    return !valid || millis <= 0;
  case REJECT:
    return !valid;
  }
  return false;
}
} // namespace

int main()
{
  const long long den = (long long)std::chrono::system_clock::period::den;
  const bool ns_clock = den == 1000000000LL;

  std::printf("system_clock::period = 1/%lld s -- %s\n\n", den,
              ns_clock ? "nanoseconds, D-2's window is +-292 years"
                       : "not nanoseconds, D-2's window is wider here");

  int failures = 0, skipped = 0;

  for (const Case &c : CASES)
  {
    if (c.needs_ns_clock && !ns_clock)
    {
      ++skipped;
      std::printf("RESULT SKIP %-10s %s | inside this platform's window\n",
                  c.format_name, c.input);
      continue;
    }

    const Aws::Utils::DateTime parsed(c.input, c.format);
    const bool valid = parsed.WasParseSuccessful();
    const int64_t millis = parsed.Millis();
    const bool ok = holds(c, valid, millis);

    if (!ok)
      ++failures;

    std::printf("RESULT %s %-10s %s | valid=%d millis=%lld iso=%s\n",
                ok ? "PASS" : "FAIL", c.format_name, c.input, valid ? 1 : 0,
                (long long)millis,
                parsed.ToGmtString(DateFormat::ISO_8601).c_str());
    if (!ok)
      std::printf("       contract: %s\n", c.contract);
  }

  const int total = (int)(sizeof(CASES) / sizeof(CASES[0]));
  std::printf("\nSUMMARY failed=%d checked=%d skipped=%d clock_den=%lld\n",
              failures, total - skipped, skipped, den);
  return failures == 0 ? 0 : 1;
}
