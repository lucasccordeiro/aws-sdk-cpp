/**
 * Executable contract cases for H-1 -- ordinary build, no sanitizer.
 *
 * Each row states what a hex decoder must do; the runner prints what the
 * pristine module actually does and exits non-zero on any mismatch. It fails
 * on unfixed sources and passes with fix/h1-reject-non-hex.patch applied, so it
 * doubles as the regression test for the fix.
 *
 * REJECT means "return an empty buffer", because that is the only way
 * HexDecode can report failure: it returns a ByteBuffer, and the odd-length
 * path (HashingUtils.cpp:180-183) already uses emptiness for exactly that.
 *
 * Built with -DNDEBUG, the macro state of a release build. Without it the two
 * non-alnum rows abort inside HexDecode at the assert(0) -- the intended debug
 * behaviour, which harnesses/hex_decode_witness.cpp exercises one input per
 * process.
 */

#include <aws/core/utils/HashingUtils.h>

#include <cstdio>

namespace
{
using Aws::Utils::ByteBuffer;
using Aws::Utils::HashingUtils;

enum Rule
{
    EXACT,    // must decode to these bytes
    REJECT,   // not hex: must come back empty
    NO_ALIAS  // must not decode to the same bytes as `other`
};

struct Case
{
    const char *input;
    Rule rule;
    const char *expected; // EXACT: hex of the expected bytes; NO_ALIAS: the other input
    const char *contract;
};

const Case CASES[] = {
    {"41", EXACT, "41", "canonical hex decodes to its byte"},
    {"aa", EXACT, "aa", "lower-case hex decodes"},
    {"AA", EXACT, "aa", "upper case decodes the same: hex is case-insensitive"},
    {"0x41", EXACT, "41", "the 0x prefix is stripped, as upstream intends"},
    {"4", REJECT, "", "odd length is not hex"},

    {"K1", REJECT, "", "'K' is not a hex digit"},
    {"zz", REJECT, "", "nor is 'z'"},
    {"EW", REJECT, "", "nor is 'W'"},
    {"v0", REJECT, "", "nor is 'v'"},
    {"\x80\x80", REJECT, "", "nor is a byte outside ASCII"},

    {"K1", NO_ALIAS, "41", "a rejected string must not decode to an accepted one's bytes"},
    {"EW", NO_ALIAS, "00", "0x00 is the value an attacker would most like to forge"},
    {"v0", NO_ALIAS, "f0", "the aliasing is systematic, not one unlucky pair"},
};

Aws::String ToHex(const ByteBuffer &b)
{
    Aws::String out;
    char byte[3];
    for (size_t i = 0; i < b.GetLength(); ++i)
    {
        snprintf(byte, sizeof(byte), "%02x", b[i]);
        out += byte;
    }
    return out;
}

bool Check(const Case &c)
{
    const ByteBuffer decoded = HashingUtils::HexDecode(c.input);
    const Aws::String got = ToHex(decoded);

    switch (c.rule)
    {
    case EXACT:
        return got == c.expected;
    case REJECT:
        return decoded.GetLength() == 0;
    case NO_ALIAS:
        return got != ToHex(HashingUtils::HexDecode(c.expected));
    }
    return false;
}
} // namespace

int main()
{
    int failed = 0;

    for (const Case &c : CASES)
    {
        const bool ok = Check(c);
        failed += ok ? 0 : 1;

        const ByteBuffer decoded = HashingUtils::HexDecode(c.input);
        printf("  %s  %-8s -> %-6s %s\n", ok ? "PASS" : "FAIL", c.input,
               decoded.GetLength() ? ToHex(decoded).c_str() : "(empty)", c.contract);
    }

    printf("  %d of %zu contract cases failed\n", failed, sizeof(CASES) / sizeof(CASES[0]));
    return failed == 0 ? 0 : 1;
}
