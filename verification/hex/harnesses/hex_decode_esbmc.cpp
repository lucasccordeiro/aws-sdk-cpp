/**
 * Symbolic harness for H-1: what Aws::Utils::HashingUtils::HexDecode accepts.
 *
 * Target (vendor/source/utils/HashingUtils.cpp:174-230), analysed as the whole
 * pristine translation unit -- no extract, no paraphrase. The only guard on the
 * *characters* is
 *
 *     if(!StringUtils::IsAlnum(str[i]) || !StringUtils::IsAlnum(str[i + 1]))
 *         assert(0);                       // HashingUtils.cpp:199-203
 *
 * and IsAlnum (StringUtils.h:203) accepts every letter, not just 'a'-'f'. So
 * the guard passes for 'g'-'z' and 'G'-'Z' in *every* build, and for the rest
 * of the byte range the only thing standing in the way is an assert, which a
 * release build compiles out. Either way HexDecode returns a full-length
 * buffer, and the API has no other way to say "that was not hex".
 *
 * SEMANTICS
 * ---------
 * Release semantics is -D NDEBUG, the macro state of an actual release build,
 * rather than ESBMC's --no-assertions. The difference matters: --no-assertions
 * also drops __ESBMC_assert, so the harness could not state a property at all.
 * With -D NDEBUG the module's asserts vanish exactly as they do in the shipped
 * SDK while the properties below stay checked.
 *
 * MODES
 * -----
 *   HARNESS_MODE_VALIDATION (default)
 *       Every input byte assumed alnum, so the module's own assert is
 *       unreachable and the run says nothing about NDEBUG either way.
 *       Property: a non-empty result implies the input was hex.
 *
 *   HARNESS_MODE_ANY_BYTE
 *       Input bytes unconstrained. Release semantics only: with asserts live
 *       this mode stops at HashingUtils.cpp:202, which is the intended debug
 *       behaviour and a different claim.
 *
 *   HARNESS_MODE_HIGH_BIT
 *       Input bytes restricted to the high half of the range, i.e. negative as
 *       plain `char`. Release semantics only, same reason. A violation here
 *       says the accepted inputs include the ones that reach isalpha/toupper
 *       with an argument that is neither representable as unsigned char nor
 *       EOF -- undefined behaviour under C17 7.4p1, which no sanitizer and no
 *       ESBMC ctype model checks. stubs/ctype_precondition_guard.c watches
 *       that call directly; this mode says the class is not a corner case.
 *
 *   HARNESS_MODE_HEX_ONLY
 *       Every input byte assumed to be a hex digit -- the control. Expect
 *       SUCCESSFUL: the property is not trivially false, and a well-formed
 *       argument decodes to a full-length buffer with no complaint.
 *
 *   HARNESS_MODE_ALIAS
 *       Two inputs: `a` all hex digits, `b` alnum with at least one non-hex
 *       character. Property: they decode to different bytes. A violation is
 *       the security-relevant statement -- a string a caller would reject as
 *       malformed decodes to exactly the bytes of one it would accept.
 *
 * LEN is 2 by default: one decoded byte is enough for every property, and the
 * witness stays readable. Longer inputs only add copies of the same violation.
 */

#include "../../stubs/esbmc_compat.h"

#include <aws/core/utils/HashingUtils.h>

#ifndef LEN
#define LEN 2
#endif

extern "C" char nondet_char();

namespace
{
bool IsHexDigit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool IsAlnum(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}
} // namespace

int main()
{
    char raw[LEN];
    bool all_hex = true;

    for (size_t i = 0; i < (size_t)LEN; ++i)
    {
        const char c = nondet_char();
#if defined(HARNESS_MODE_HEX_ONLY)
        __ESBMC_assume(IsHexDigit(c));
#elif defined(HARNESS_MODE_HIGH_BIT)
        __ESBMC_assume(c < 0);
#elif !defined(HARNESS_MODE_ANY_BYTE)
        __ESBMC_assume(IsAlnum(c));
#endif
        raw[i] = c;
        all_hex = all_hex && IsHexDigit(c);
    }

    const Aws::String input(raw, LEN);
    const Aws::Utils::ByteBuffer out = Aws::Utils::HashingUtils::HexDecode(input);

#ifdef HARNESS_MODE_ALIAS
    char raw_hex[LEN];
    for (size_t i = 0; i < (size_t)LEN; ++i)
    {
        const char c = nondet_char();
        __ESBMC_assume(IsHexDigit(c));
        raw_hex[i] = c;
    }
    __ESBMC_assume(!all_hex); /* `input` is the malformed one */

    const Aws::String well_formed(raw_hex, LEN);
    const Aws::Utils::ByteBuffer expected = Aws::Utils::HashingUtils::HexDecode(well_formed);

    bool same = out.GetLength() == expected.GetLength();
    for (size_t i = 0; same && i < out.GetLength(); ++i)
        same = out[i] == expected[i];

    /* `input` is not hex and `well_formed` is, so `same` means the malformed
     * string produced the well-formed one's bytes. */
    __ESBMC_assert(!same, "a non-hex string decodes to the bytes of a hex string");
#else
    __ESBMC_assert(out.GetLength() == 0 || all_hex,
                   "HexDecode returned bytes for an input that was not hex");
#endif

    return 0;
}
