/**
 * Step-1 smoke harness: does ESBMC ingest and symex the real Base64 TU at all?
 *
 * No properties of interest here -- this exists purely to separate "the
 * frontend/OM cannot handle Aws::String and ByteBuffer" from "the codec has a
 * bug". Run this green before trusting anything the real harnesses report.
 *
 * Concrete input only: a fixed well-formed 4-char block that decodes to 3
 * bytes with no padding. If this reports a violation, the model is broken, not
 * the codec.
 */

#include "esbmc_compat.h"

#include "source/utils/base64/Base64.cpp"

int main()
{
  const Aws::Utils::Base64::Base64 codec;

  const Aws::String input("QUJD"); /* base64("ABC") */
  const Aws::Utils::ByteBuffer out = codec.Decode(input);

  assert(out.GetLength() == 3);
  assert(out[0] == 'A');
  assert(out[1] == 'B');
  assert(out[2] == 'C');

  return 0;
}
