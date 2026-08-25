/**
 * Concrete reproducer for the formatting side of DateTime, argv-driven.
 *
 *   datetime_format_asan <repeat-count>
 *
 * builds a format string of <repeat-count> literal characters and hands it to
 * DateTime::ToGmtString(const char*).
 *
 * DateTimeCommon.cpp:1269-1271 is
 *
 *     char formattedString[100];
 *     std::strftime(formattedString, sizeof(formattedString), formatStr, &gmtTimeStamp);
 *     return formattedString;
 *
 * strftime returns 0 and leaves the array contents INDETERMINATE when the
 * result including the terminating null would not fit (C17 7.27.3.5p3). The
 * return value is not checked, so `return formattedString` runs strlen over an
 * array the standard does not promise contains a null at all.
 *
 * RESULT: NOT a defect on this platform, and this harness is what establishes
 * that rather than an argument. Under glibc the oversized cases report
 * result_len=99 with no sanitizer diagnostic at any format length tried
 * (100/150/400) -- glibc truncates to 99 characters and still writes the null
 * even on the failure return, so the strlen stays in bounds. What is left is a
 * portability/standards wart, not a live bug: the code relies on behaviour the
 * C standard explicitly leaves indeterminate, and would read out of bounds on
 * an implementation that takes the standard at its word. It also truncates
 * silently, since the ignored return value is the only signal that the output
 * did not fit.
 *
 * Keep this harness: it is the regression that would catch the OOB read if the
 * platform libc ever stopped being generous.
 */

#include <aws/core/utils/DateTime.h>

#include <cstdio>
#include <cstdlib>
#include <string>

int main(int argc, char **argv)
{
  if (argc != 2)
  {
    std::fprintf(stderr, "usage: %s <repeat-count>\n", argv[0]);
    return 2;
  }

  const int repeat = std::atoi(argv[1]);
  if (repeat < 0)
  {
    std::fprintf(stderr, "repeat-count must be non-negative\n");
    return 2;
  }

  /* Literal characters: strftime copies them through unchanged, so the output
   * length is exactly `repeat` and the 100-byte buffer overflows at 100. */
  const std::string formatStr(static_cast<size_t>(repeat), 'a');

  const Aws::Utils::DateTime now = Aws::Utils::DateTime::Now();
  const Aws::String formatted = now.ToGmtString(formatStr.c_str());

  std::printf("format_len=%d result_len=%zu\n", repeat, formatted.length());
  return 0;
}
