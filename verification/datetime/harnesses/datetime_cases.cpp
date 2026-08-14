/**
 * Executable test cases for D-1 and D-2 -- ordinary build, no sanitizer.
 *
 * Each case states the contract a correct DateTime must meet; the runner prints
 * what 1.11.869 actually returns and exits non-zero on any mismatch. It fails
 * on unfixed sources and passes once the conversion is range-checked, so it
 * doubles as the regression test for a fix.
 *
 * Build at -O0: the wrapped values below are the result of signed-overflow UB,
 * so they are what this compiler produces, not values the standard guarantees.
 */

#include <aws/core/utils/DateTime.h>

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
  const char *contract;
};

const Case CASES[] = {
  {"2002-10-02T08:00:00Z", DateFormat::ISO_8601, "iso8601", EXACT,
   1033545600000LL, "an ordinary ISO 8601 timestamp round-trips"},
  {"Wed, 02 Oct 2002 08:00:00 GMT", DateFormat::RFC822, "rfc822", EXACT,
   1033545600000LL, "an ordinary RFC 822 timestamp round-trips"},
  {"2262-04-11T00:00:00Z", DateFormat::ISO_8601, "iso8601", EXACT, BOUNDARY_MS,
   "the last representable instant still parses"},
  {"1677-09-22T00:00:00Z", DateFormat::ISO_8601, "iso8601", EXACT,
   -BOUNDARY_MS, "so does the first one"},

  {"2262-04-12T00:00:00Z", DateFormat::ISO_8601, "iso8601", NOT_PAST, 0,
   "one day past the boundary: reject or stay in the future"},
  {"Thu, 31 Dec 9999 23:59:59 GMT", DateFormat::RFC822, "rfc822", NOT_PAST, 0,
   "the HTTP never-expires sentinel: reject or stay in the future"},
  {"Thu, 31 Dec 9999 23:59:59 GMT", DateFormat::AutoDetect, "autodetect",
   NOT_PAST, 0, "same sentinel through AutoDetect, as AWSClient uses it"},
  {"1600-01-01T00:00:00Z", DateFormat::ISO_8601, "iso8601", NOT_FUTURE, 0,
   "an archival timestamp: reject or stay in the past"},

  {"Wed, 999999999 Oct 2002 08:00:00 GMT", DateFormat::RFC822, "rfc822",
   NOT_PAST, 0, "a nine-digit day: reject or normalise into the future"},
  {"Wed, 99999999999999999999 Oct 2002 08:00:00 GMT", DateFormat::RFC822,
   "rfc822", REJECT, 0, "a twenty-digit day is not a date"},
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
  int failures = 0;

  for (const Case &c : CASES)
  {
    const Aws::Utils::DateTime parsed(c.input, c.format);
    const bool valid = parsed.WasParseSuccessful();
    const int64_t millis = parsed.Millis();
    const bool ok = holds(c, valid, millis);

    if (!ok)
      ++failures;

    std::printf("  %s  %s [%s]\n", ok ? "PASS" : "FAIL", c.input,
                c.format_name);
    if (!ok)
      std::printf("        contract: %s\n        observed: valid=%d millis=%lld"
                  " -> %s\n",
                  c.contract, valid ? 1 : 0, (long long)millis,
                  parsed.ToGmtString(DateFormat::ISO_8601).c_str());
  }

  std::printf("\n%d of %d cases failed\n", failures,
              (int)(sizeof(CASES) / sizeof(CASES[0])));
  return failures == 0 ? 0 : 1;
}
