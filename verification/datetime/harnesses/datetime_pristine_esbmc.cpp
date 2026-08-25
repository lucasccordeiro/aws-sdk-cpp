/**
 * ESBMC over the whole pristine DateTimeCommon.cpp translation unit.
 *
 * The obligations in d1_accumulator_esbmc.c and d2_time_point_esbmc.c are
 * line-faithful extractions, written when ESBMC could not parse this TU at all.
 * It can now -- esbmc/esbmc#7141 modelled timegm, and #7138-7140 removed the
 * basic_string false positives -- so the same two properties can be discharged
 * against the module itself rather than against a copy of it.
 *
 * `--include-file cctype` stands in for the one gap left: ESBMC's <iostream>
 * and <cstring> do not pull in <cctype> transitively. Neither does the
 * standard require them to, so this is a fidelity gap rather than a defect,
 * and a forced include is preferable to editing vendor/.
 *
 * timegm is modelled as returning an unconstrained time_t. That is the right
 * abstraction for D-2, and a stronger one than any date: the obligation
 * becomes "the conversion is guarded for every seconds value a parse could
 * yield", which is what the fix has to be true of.
 *
 * The harness asserts nothing itself -- every property comes from
 * --overflow-check, so a verdict cannot be an artefact of how it was phrased.
 * Pair each input with both sources: FAILED on 1.11.869 says the overflow is
 * reachable, SUCCESSFUL on 1.11.877 says the fix closes it.
 */

#include <aws/core/utils/DateTime.h>

#ifndef DT_INPUT
#define DT_INPUT "2002-10-02T08:00:00Z"
#endif

#ifndef DT_FORMAT
#define DT_FORMAT ISO_8601
#endif

int main()
{
  Aws::Utils::DateTime parsed(DT_INPUT, Aws::Utils::DateFormat::DT_FORMAT);
  (void)parsed.WasParseSuccessful();
  return 0;
}
