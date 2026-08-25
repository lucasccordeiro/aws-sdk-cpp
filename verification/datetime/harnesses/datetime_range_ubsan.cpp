/**
 * Regression harness for D-2: DateTime converts a parsed timestamp into a
 * system_clock::time_point without range-checking it against that clock's
 * representable range.
 *
 * libstdc++'s system_clock::duration is nanoseconds, so its int64 saturates
 * ~292 years after the epoch -- 2262-04-11T23:47:16Z. Any later date overflows
 * in the seconds-to-nanoseconds duration_cast (bits/chrono.h:225). The parsers
 * accept these dates: they are well-formed and in spec, so nothing upstream of
 * the conversion rejects them.
 *
 * Build with -fsanitize=undefined -fno-sanitize-recover=all: on unfixed sources
 * this aborts on the first post-2262 case. A fixed DateTime should either clamp
 * or mark the parse invalid, but must not execute the overflowing multiply.
 *
 * NOTE: the boundary is libstdc++-specific. libc++ uses a microsecond
 * system_clock, whose int64 does not saturate until ~294247, so these cases do
 * not overflow there. This is a Linux/libstdc++ finding.
 */

#include <aws/core/utils/DateTime.h>

#include <cstdio>

namespace
{
struct Case
{
  const char *timestamp;
  Aws::Utils::DateFormat format;
  bool pastBoundary;
};

const Case CASES[] = {
    // In range -- must stay working, guards against a fix that over-rejects.
    {"2002-10-02T08:00:00Z", Aws::Utils::DateFormat::ISO_8601, false},
    {"2262-04-11T00:00:00Z", Aws::Utils::DateFormat::ISO_8601, false},
    {"Wed, 02 Oct 2002 08:00:00 GMT", Aws::Utils::DateFormat::RFC822, false},

    // Past the int64-nanosecond boundary -- each one overflows on unfixed code.
    {"2262-04-12T00:00:00Z", Aws::Utils::DateFormat::ISO_8601, true},
    {"2500-01-01T00:00:00Z", Aws::Utils::DateFormat::ISO_8601, true},
    {"9999-01-01T00:00:00Z", Aws::Utils::DateFormat::ISO_8601, true},

    // The HTTP "never expires" sentinel, as S3 returns it from an Expires
    // header an uploader set via PutObjectRequest::SetExpires.
    {"Thu, 31 Dec 9999 23:59:59 GMT", Aws::Utils::DateFormat::RFC822, true},
    {"Thu, 31 Dec 9999 23:59:59 GMT", Aws::Utils::DateFormat::AutoDetect, true},
};
} // namespace

int main()
{
  // -fno-sanitize-recover aborts mid-run; unbuffered stdout keeps the cases
  // that already passed visible, so the abort point is identifiable.
  std::setvbuf(stdout, nullptr, _IONBF, 0);

  for (const Case &c : CASES)
  {
    const Aws::Utils::DateTime parsed(c.timestamp, c.format);
    std::printf("%-32s past_boundary=%d valid=%d millis=%lld\n", c.timestamp,
                c.pastBoundary ? 1 : 0, parsed.WasParseSuccessful() ? 1 : 0,
                (long long)parsed.Millis());
  }

  std::printf("no overflow trapped\n");
  return 0;
}
