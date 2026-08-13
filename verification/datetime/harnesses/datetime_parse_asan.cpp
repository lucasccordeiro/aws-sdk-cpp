/**
 * Concrete reproducer for the DateTime parsers, argv-driven, for ASan/UBSan.
 *
 *   datetime_parse_asan <format> <string>
 *
 * where <format> is iso8601 | iso8601basic | rfc822 | autodetect.
 *
 * The property of interest is UBSan's signed-integer-overflow check on the
 * digit accumulators in the DateParser state machines, e.g. ISO_8601DateParser
 * state 0:
 *
 *     m_parsedTimestamp.tm_year = m_parsedTimestamp.tm_year * 10 + (c - '0');
 *
 * tm_year is an int and nothing bounds the digit count -- the state only leaves
 * the year on a '-' at offset 4, and any other non-digit sets m_error, but the
 * accumulation has already happened by then. The parsers' only length guard is
 * `len > MAX_LEN` with MAX_LEN == 100, which a ten-digit run fits inside.
 */

#include <aws/core/utils/DateTime.h>

#include <cstdio>
#include <cstring>

int main(int argc, char **argv)
{
  if (argc != 3)
  {
    std::fprintf(stderr, "usage: %s <iso8601|iso8601basic|rfc822|autodetect> <string>\n", argv[0]);
    return 2;
  }

  Aws::Utils::DateFormat format;
  if (std::strcmp(argv[1], "iso8601") == 0)
    format = Aws::Utils::DateFormat::ISO_8601;
  else if (std::strcmp(argv[1], "iso8601basic") == 0)
    format = Aws::Utils::DateFormat::ISO_8601_BASIC;
  else if (std::strcmp(argv[1], "rfc822") == 0)
    format = Aws::Utils::DateFormat::RFC822;
  else if (std::strcmp(argv[1], "autodetect") == 0)
    format = Aws::Utils::DateFormat::AutoDetect;
  else
  {
    std::fprintf(stderr, "unknown format %s\n", argv[1]);
    return 2;
  }

  const Aws::Utils::DateTime parsed(argv[2], format);

  std::printf("input_len=%zu valid=%d\n", std::strlen(argv[2]), parsed.WasParseSuccessful() ? 1 : 0);
  return 0;
}
