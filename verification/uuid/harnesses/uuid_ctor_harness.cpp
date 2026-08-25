/**
 * Memory-safety harness for Aws::Utils::UUID::UUID(const Aws::String&).
 *
 * Target (vendor/source/utils/UUID.cpp:34-44), included verbatim:
 *
 *     UUID::UUID(const Aws::String& uuidToConvert) {
 *         assert(uuidToConvert.length() == UUID_STR_SIZE);      // 36
 *         memset(m_uuid, 0, sizeof(m_uuid));                    // m_uuid[16]
 *         Aws::String escapedHexStr(uuidToConvert);
 *         StringUtils::Replace(escapedHexStr, "-", "");
 *         assert(escapedHexStr.length() == UUID_BINARY_SIZE * 2);
 *         ByteBuffer&& rawUuid = HashingUtils::HexDecode(escapedHexStr);
 *         memcpy(m_uuid, rawUuid.GetUnderlyingData(), rawUuid.GetLength());
 *     }
 *
 * The destination is a fixed 16-byte member; the length is HexDecode's output
 * length, a function of the *input* length. The property is whether those two
 * can disagree, so the harness leaves the input length symbolic and lets
 * ESBMC's bounds check watch the copy.
 *
 * RELEASE SEMANTICS
 * -----------------
 * Both length constraints in the constructor are `assert`s, which vanish under
 * NDEBUG -- i.e. in any release build of the SDK, which is where the defect
 * bites. `make esbmc` therefore passes --no-assertions, ESBMC's equivalent:
 * user assertions ignored, built-in bounds and pointer checks still on. Without
 * it the run stops at the de-dashed-length assert and never reaches the memcpy,
 * which is the *debug* behaviour -- a different, already-known outcome that
 * `make esbmc-debug` keeps.
 *
 * INPUT MODEL
 * -----------
 *   HARNESS_MODE_ANY_LEN (default)
 *       Length unconstrained in [0, MAXLEN], every byte an ASCII hex digit.
 *       Hex digits rather than arbitrary bytes because HexDecode asserts on
 *       non-hex input and, under --no-assertions, a non-hex byte only changes
 *       the decoded *values*, never the decoded length -- so arbitrary bytes
 *       would widen the input space without touching the property. This models
 *       the constructor's actual (absent) precondition.
 *
 *   HARNESS_MODE_CONTRACT
 *       Length fixed at exactly UUID_STR_SIZE (36), the precondition the
 *       constructor itself documents and asserts, with every byte again a hex
 *       digit. This is the strongest precondition a caller could satisfy
 *       without reimplementing the parser: it is what the first assert demands.
 *       A violation in this mode is the stronger claim -- satisfying the
 *       documented contract does not make the copy safe, because the *second*
 *       assert (de-dashed length == 32) is the load-bearing one and it is
 *       equally absent in release.
 *
 * Neither mode emits '-', so StringUtils::Replace is a no-op over the input.
 * That is a restriction of the input space, not a weakening: dashes only
 * shorten the de-dashed body, and a shorter body decodes to fewer bytes. The
 * dash-free strings are exactly the worst case for the overflow.
 */

#include "../../stubs/esbmc_compat.h"

#include "source/utils/UUID.cpp"

/* HexDecode yields floor(len/2) bytes, so a violation needs len >= 34. Raising
 * MAXLEN only adds longer witnesses; lowering it to 33 is the safe side of the
 * boundary and is expected to verify. CONTRACT mode ignores MAXLEN entirely --
 * its length is fixed by the constructor's own precondition, so `make esbmc
 * MAXLEN=<n>` sweeps ANY_LEN without changing what CONTRACT means. */
#ifndef MAXLEN
#define MAXLEN 36
#endif

#ifdef HARNESS_MODE_CONTRACT
#define BUFLEN 36 /* UUID_STR_SIZE */
#else
#define BUFLEN MAXLEN
#endif

extern "C" {
size_t nondet_size_t();
char nondet_char();
}

int main()
{
  char raw[BUFLEN];
  for (size_t i = 0; i < (size_t)BUFLEN; ++i)
  {
    const char c = nondet_char();
    __ESBMC_assume(
      (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
    raw[i] = c;
  }

#ifdef HARNESS_MODE_CONTRACT
  const size_t len = BUFLEN; /* UUID_STR_SIZE: what the first assert demands */
#else
  const size_t len = nondet_size_t();
  __ESBMC_assume(len <= (size_t)MAXLEN);
#endif

  const Aws::String input(raw, len);

  /* The property is memory safety of the construction itself: ESBMC's bounds
   * and pointer checks (on by default) watch the memcpy into m_uuid[16]. No
   * postcondition is asserted -- a functional one would only muddy a genuine
   * memory-safety counterexample. */
  const Aws::Utils::UUID u(input);

  volatile const void *keep = &u; /* keep u live without the hexify round-trip */
  (void)keep;
  return 0;
}
