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

/* Test-case generation and replay (see the `testgen` target in the Makefile).
 *
 * ESBMC's --generate-ctest-testcase emits concrete implementations named
 * __VERIFIER_nondet_<type> (src/goto-symex/ctest.cpp:376), so the harness must
 * call *those* names for the generated file to link against it. The collector
 * itself keys on the `nondet$` SSA symbol, not the callee name, so this rename
 * changes nothing about what ESBMC explores.
 *
 *   ESBMC_TESTGEN - compiled by ESBMC to produce test_case.cpp.
 *   ESBMC_REPLAY  - compiled by g++/ASan against that file. __ESBMC_assume
 *                   becomes a runtime assert, so replaying values that violate
 *                   the harness preconditions (the RFC 4648 alphabet, len
 *                   bound) aborts rather than silently testing something else.
 */
#if defined(ESBMC_TESTGEN) || defined(ESBMC_REPLAY)
#define nondet_size_t __VERIFIER_nondet_ulong
#define nondet_char __VERIFIER_nondet_char
#endif

#ifdef ESBMC_REPLAY
#include <cstdio>
#include <cstdlib>
/* Deliberately not assert(): the replay is built -DNDEBUG, to get the release
 * semantics under which the B-1 overflow is silent heap corruption rather than
 * a caught Array::GetItem assert. assert() would compile out with it, and the
 * check below is the one thing that distinguishes "the counterexample is a
 * real input" from "the counterexample violates the harness's own
 * preconditions and the crash proves nothing". */
#define __ESBMC_assume(cond)                                                   \
  do                                                                           \
  {                                                                            \
    if (!(cond))                                                               \
    {                                                                          \
      std::fprintf(stderr, "replay: assumption violated: %s\n", #cond);        \
      std::abort();                                                            \
    }                                                                          \
  } while (0)
#endif

extern "C" {
size_t nondet_size_t();
char nondet_char();
}

int main()
{
  /* Unconstrained length -- ESBMC explores every length in range, including
   * the non-multiples of 4 that the block loop truncates.
   *
   * Strictly less than MAXLEN, not <=, to dodge esbmc/esbmc#6199: the OM's
   * basic_string(const char*, size_t n) asserts n < strlen(s), so the
   * exact-length construction Aws::String(raw, MAXLEN) fails inside the ctor
   * before Decode is ever called. Keeping one spare byte in raw[] leaves
   * strlen(raw) > len for every len explored. Revert to <= once that is fixed. */
  const size_t len = nondet_size_t();
  __ESBMC_assume(len < (size_t)MAXLEN);

  char raw[MAXLEN + 1];
  for (size_t i = 0; i < (size_t)MAXLEN; ++i)
  {
    const char c = nondet_char();

    /* Second half of the esbmc/esbmc#6199 workaround. Keeping one spare byte in
     * raw[] only guarantees strlen(raw) > len while no interior byte is NUL; an
     * unconstrained NUL shortens strlen and trips the OM's bogus
     * n < strlen(s) precondition before Decode is reached. Excluding '\0' is
     * the narrowest constraint that keeps ANY_BYTE meaningful -- every other
     * byte value, high-bit ones included, is still explored, so this does not
     * weaken the B-2 result. Remove once #6199 lands. */
    __ESBMC_assume(c != '\0');

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

#ifdef ESBMC_REPLAY
  /* Report the input actually reconstructed from the generated test case, so a
   * replay cannot silently confirm a different input than the one the report
   * names. Hex because a counterexample may contain non-printable bytes -- B-2's
   * begins with 0x80. */
  std::fprintf(stderr, "replay: input=");
  for (size_t i = 0; i < len; ++i)
    std::fprintf(stderr, "%02x", (unsigned)(unsigned char)raw[i]);
  std::fprintf(stderr, " len=%zu\n", len);
#endif

  /* The property is memory safety of the call itself: ESBMC's array-bounds and
   * pointer checks (on by default; only --no-bounds-check / --no-pointer-check
   * exist) watch every buffer[...] store inside Decode, and Array::GetItem's
   * own assert(index < m_length) fires first when enabled.
   * No postcondition is asserted here on purpose -- a spurious functional
   * assertion would muddy a genuine memory-safety counterexample. */
  const Aws::Utils::ByteBuffer out = codec.Decode(input);

  /* Keep the result live so the call cannot be optimised away. */
  return out.GetLength() == 0 ? 0 : 1;
}
