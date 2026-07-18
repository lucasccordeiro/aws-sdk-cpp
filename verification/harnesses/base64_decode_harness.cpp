/**
 * Memory-safety harness for Aws::Utils::Base64::Base64::Decode.
 *
 * Target (vendor/source/utils/base64/Base64.cpp:91-121), included verbatim:
 *
 *     ByteBuffer Decode(const Aws::String& str) const {
 *         size_t decodedLength = CalculateBase64DecodedLength(str);
 *         ByteBuffer buffer(decodedLength);
 *         size_t blockCount = str.length() / 4;
 *         for (i = 0; i < blockCount; ++i) { ... buffer[bufferIndex] = ...; }
 *     }
 *
 * The buffer is sized by CalculateBase64DecodedLength but written by a loop
 * driven by str.length()/4. Those are two independent computations over the
 * same input, so the property of interest is whether the writes can outrun the
 * allocation.
 *
 * INPUT MODEL
 * -----------
 * A symbolic Aws::String of unconstrained length in [0, MAXLEN]. Byte values
 * are controlled by the mode macro:
 *
 *   HARNESS_MODE_ANY_BYTE (default)
 *       Every byte fully unconstrained over the char range. This is the honest
 *       model of Decode's contract: it is a public method taking a String, with
 *       no documented precondition and no validation of its argument, reachable
 *       from HashingUtils::Base64Decode on attacker-supplied data.
 *
 *   HARNESS_MODE_ALPHABET
 *       Every byte constrained to the RFC 4648 base64 alphabet plus '='. This
 *       is the *strongest realistic precondition* a caller could satisfy. A
 *       violation that survives this mode cannot be dismissed as "you fed it
 *       garbage" -- the input is well-formed base64 characters throughout.
 *
 * Run both. If ANY_BYTE fails but ALPHABET passes, the defect is input
 * validation. If ALPHABET also fails, the defect is the length arithmetic
 * itself, which is the more serious claim.
 */

#include "esbmc_compat.h"

#include "source/utils/base64/Base64.cpp"

#ifndef MAXLEN
#define MAXLEN 6
#endif

extern "C" {
size_t nondet_size_t();
char nondet_char();
}

int main()
{
  /* Unconstrained length -- ESBMC explores every length in range, including
   * the non-multiples of 4 that the block loop truncates. */
  const size_t len = nondet_size_t();
  __ESBMC_assume(len <= (size_t)MAXLEN);

  char raw[MAXLEN + 1];
  for (size_t i = 0; i < (size_t)MAXLEN; ++i)
  {
    const char c = nondet_char();
#ifdef HARNESS_MODE_ALPHABET
    /* RFC 4648 base64 alphabet plus the pad character. Note this deliberately
     * still permits '=' at *any* position -- a caller cannot police interior
     * padding without reimplementing the parser, and Decode does not reject
     * it. */
    __ESBMC_assume(
      (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
      (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=');
#endif
    raw[i] = c;
  }
  raw[MAXLEN] = '\0';

  const Aws::String input(raw, len);
  const Aws::Utils::Base64::Base64 codec;

  /* The property is memory safety of the call itself: ESBMC's --bounds-check
   * and --pointer-check watch every buffer[...] store inside Decode, and
   * Array::GetItem's own assert(index < m_length) fires first when enabled.
   * No postcondition is asserted here on purpose -- a spurious functional
   * assertion would muddy a genuine memory-safety counterexample. */
  const Aws::Utils::ByteBuffer out = codec.Decode(input);

  /* Keep the result live so the call cannot be optimised away. */
  return out.GetLength() == 0 ? 0 : 1;
}
