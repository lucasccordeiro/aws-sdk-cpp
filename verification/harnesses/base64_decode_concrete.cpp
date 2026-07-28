/**
 * Concrete ESBMC confirmations of the two defects in REPORT.md, on the exact
 * inputs the ASan cross-check uses. These pin the findings to a named input, so
 * a regression shows up as a verdict flip rather than a change in a symbolic
 * counterexample.
 *
 *   CASE_B1 (default)  "AAAA="            -> sizing computes 2, fill writes 3.
 *                                            Expect: assertion GetItem, i.e.
 *                                            index < m_length violated.
 *   CASE_B2            "\xff\xff\xff\xff"  -> (char)-1 sign-extends to UINT32_MAX
 *                                            as a decoding-table index.
 *                                            Expect: dereference failure,
 *                                            access to object out of bounds.
 *
 * Each literal used to carry a trailing filler byte, excluded from the string by
 * the explicit length, purely to pad the backing array so the OM's
 * basic_string(const char*, n) precondition n < strlen(s) held -- see
 * esbmc/esbmc#6199. #6225 fixed that constructor to copy exactly n characters
 * without consulting strlen, so the fillers are gone and each literal is now
 * exactly the input under test.
 */

#include "esbmc_compat.h"

#include "source/utils/base64/Base64.cpp"

int main()
{
#ifdef CASE_B2
  const Aws::String input("\xff\xff\xff\xff", 4);
  __ESBMC_assert(input.length() == 4, "input is the four 0xFF bytes");
#else
  const Aws::String input("AAAA=", 5);
  __ESBMC_assert(input.length() == 5, "input is \"AAAA=\"");
#endif

  const Aws::Utils::Base64::Base64 codec;
  const Aws::Utils::ByteBuffer out = codec.Decode(input);
  return out.GetLength() == 0 ? 0 : 1;
}
