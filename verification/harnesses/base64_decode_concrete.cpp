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
 * The trailing filler byte in each literal is NOT part of the input: the string
 * is built with an explicit length that excludes it. It only pads the backing
 * array so the OM's basic_string(const char*, n) precondition n < strlen(s)
 * holds -- see esbmc/esbmc#6199. Without it the constructor fails before Decode
 * is reached, which is an artefact of the model, not a finding.
 */

#include "esbmc_compat.h"

#include "source/utils/base64/Base64.cpp"

int main()
{
#ifdef CASE_B2
  const Aws::String input("\xff\xff\xff\xff" "A", 4);
  __ESBMC_assert(input.length() == 4, "input is the four 0xFF bytes");
#else
  const Aws::String input("AAAA=" "X", 5);
  __ESBMC_assert(input.length() == 5, "input is \"AAAA=\"");
#endif

  const Aws::Utils::Base64::Base64 codec;
  const Aws::Utils::ByteBuffer out = codec.Decode(input);
  return out.GetLength() == 0 ? 0 : 1;
}
