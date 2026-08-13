/**
 * D-1, symbolic: the RFC822 day accumulator overflows on a digit run that the
 * parser's only length guard permits.
 *
 * Extracted from RFC822DateParser::operator() state 2,
 * DateTimeCommon.cpp:478-492 (v1.11.869). The extraction is line-faithful:
 * the accumulate-on-digit / leave-on-space / error-otherwise structure and the
 * len > MAX_LEN guard (:409, :1063) are the whole of the relevant logic.
 * isdigit/isspace are spelled as their ASCII ranges so the result does not
 * depend on ESBMC's ctype model.
 *
 * Extraction is necessary, not preference: ESBMC 8.4's <chrono> operational
 * model has no time_point and no clocks, so the real translation unit does not
 * parse (PARSING ERROR on DateTime.h:66, std::chrono::system_clock).
 *
 *   Reachability : esbmc --overflow-check --unwind 101 d1_accumulator_esbmc.c
 *                  -> VERIFICATION FAILED, arithmetic overflow on mul
 *   Tight bound  : same, -DBOUND_DIGITS=9 -> VERIFICATION SUCCESSFUL
 *
 * The pair is the finding: >=10 digits overflows, <=9 cannot, and MAX_LEN==100
 * is the only thing standing in the way.
 */

#define MAX_LEN 100

#ifndef BOUND_DIGITS
#  define BOUND_DIGITS MAX_LEN
#endif

extern char nondet_char(void);
extern int nondet_int(void);

static int parse_day_field(const char *s, int len)
{
  int tm_mday = 0;

  for (int index = 0; index < len; ++index)
  {
    const char c = s[index];

    if (c >= '0' && c <= '9')
      tm_mday = tm_mday * 10 + (c - '0'); /* DateTimeCommon.cpp:482 */
    else if (c == ' ' || c == '\t')
      break; /* :484 -- leaves on any space, at any offset */
    else
      return -1; /* :488 -- m_error = true */
  }

  return tm_mday;
}

int main(void)
{
  char buf[MAX_LEN];

  const int len = nondet_int();
  __ESBMC_assume(len > 0 && len <= BOUND_DIGITS);

  for (int i = 0; i < len; ++i)
  {
    buf[i] = nondet_char();
    __ESBMC_assume(buf[i] >= '0' && buf[i] <= '9');
  }

  return parse_day_field(buf, len);
}
