/**
 * ESBMC concrete confirmation of the UUID string-constructor overflow (U-1).
 *
 * Feeds one fixed input to Aws::Utils::UUID(const Aws::String&) and lets ESBMC
 * check the constructor's memcpy against the 16-byte m_uuid member. No
 * properties are asserted here; the property is ESBMC's built-in bounds check
 * on the memcpy at UUID.cpp:43.
 *
 *   default        -- 36 hex characters, no dashes (-> 18 bytes): expect
 *                     VERIFICATION FAILED (dest bounds violated).
 *   -D CASE_SAFE   -- a canonical 32-char hex body (-> 16 bytes): expect
 *                     VERIFICATION SUCCESSFUL, so the failing run is not vacuous.
 *
 * The default input is 36 characters DELIBERATELY: 36 is UUID_STR_SIZE, so the
 * input satisfies the constructor's first assert -- the only length constraint
 * the API documents -- and overflows regardless, because the check that matters
 * is the second assert on the de-dashed length. Under `make esbmc-debug`, with
 * asserts live, the violation reported is UUID.cpp:41 rather than :37; that is
 * the point of the choice, so do not "fix" this input to a longer one.
 *
 * Neither input carries a '-', so StringUtils::Replace performs no replacement
 * and the path under check is Aws::String -> HexDecode -> memcpy. Note this
 * makes Replace semantically a no-op but NOT a cheap one for symex -- see the
 * REPLACE_BOUND comment in the Makefile.
 */

#include "../../stubs/esbmc_compat.h"

#include "source/utils/UUID.cpp"

int main()
{
#ifdef CASE_SAFE
  const Aws::String input("12345678123412341234567890123456"); /* 32 hex -> 16 bytes */
#else
  const Aws::String input("123456781234123412345678901234561234"); /* 36 hex -> 18 bytes */
#endif

  const Aws::Utils::UUID u(input);
  volatile const void *keep = &u; /* keep u live without the hexify round-trip */
  (void)keep;
  return 0;
}
