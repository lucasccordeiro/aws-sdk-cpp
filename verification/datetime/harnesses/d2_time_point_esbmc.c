/**
 * D-2, symbolic: converting a parsed timestamp to a libstdc++
 * system_clock::time_point overflows int64 for in-spec dates.
 *
 * DateTime stores std::chrono::system_clock::time_point (DateTime.h:262) and
 * assigns it from the parsed tm with no range check
 * (DateTimeCommon.cpp:1104-1116). On libstdc++ that clock's duration is
 * nanoseconds, so the seconds->nanoseconds duration_cast multiplies by 1e9 in
 * bits/chrono.h:225. That multiply is what overflows.
 *
 * Extracted for the same reason as D-1: no chrono operational model in ESBMC
 * 8.4. What is modelled is the multiply and its input range; days_from_civil is
 * the standard Howard Hinnant algorithm, matching timegm on the inputs used.
 *
 *   Reachability : esbmc --overflow-check --unwind 2 d2_time_point_esbmc.c
 *                  -> VERIFICATION FAILED, arithmetic overflow on mul
 *   Window proof : same, -DASSUME_IN_WINDOW -> VERIFICATION SUCCESSFUL
 *
 * The window proof pins the boundary as a theorem rather than a measurement:
 * |seconds| <= 9223372036 is exactly the safe range, i.e.
 * 1677-09-21T00:12:44Z through 2262-04-11T23:47:16Z.
 */

#define NANOS_PER_SEC 1000000000LL
#define MAX_SAFE_SECONDS (9223372036854775807LL / NANOS_PER_SEC) /* 9223372036 */

extern int nondet_int(void);

static long long days_from_civil(long long y, unsigned m, unsigned d)
{
  y -= m <= 2;
  const long long era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = (unsigned)(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + (long long)doe - 719468;
}

int main(void)
{
  /* Any year the parsers accept. 9999 is not malformed: it is the conventional
     HTTP "never expires" sentinel and a value PutObjectRequest::SetExpires
     lets an uploader choose. */
  const int year = nondet_int();
  __ESBMC_assume(year >= 1 && year <= 9999);

  const long long seconds = days_from_civil(year, 1, 1) * 86400LL;

#ifdef ASSUME_IN_WINDOW
  __ESBMC_assume(seconds >= -MAX_SAFE_SECONDS && seconds <= MAX_SAFE_SECONDS);
#endif

  const long long nanos = seconds * NANOS_PER_SEC; /* bits/chrono.h:225 */

  return (int)(nanos & 1);
}
