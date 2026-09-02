/* H-1 from an entry point.
 *
 * main() below calls one public SDK API -- Aws::Utils::UUID(const Aws::String&)
 * -- and never names HashingUtils::HexDecode. Every value it prints is what an
 * application parsing a UUID string out of a request, a config file or a
 * database column gets back today.
 *
 * Build: see reproduce.sh, leg "entrypoint". Release semantics (-DNDEBUG) is
 * the interesting one, but a debug build answers the same: UUID.cpp:37 and :41
 * assert on length, which a 36-character four-dash string satisfies whatever
 * its characters are, and HashingUtils.cpp:202 is unreached because IsAlnum
 * admits the letters. */

#include <aws/core/utils/UUID.h>

#include <cstdio>
#include <cstring>

using Aws::Utils::ByteBuffer;
using Aws::Utils::UUID;

static int failures = 0;
static int checks = 0;

static Aws::String Render(const char* uuidString)
{
    const Aws::String in(uuidString);
    const UUID parsed(in);
    return parsed.operator Aws::String();
}

static ByteBuffer Bytes(const char* uuidString)
{
    const Aws::String in(uuidString);
    const UUID parsed(in);
    return parsed.operator ByteBuffer();
}

static void Expect(bool ok, const char* what)
{
    printf("  %s  %s\n", ok ? "PASS" : "FAIL", what);
    checks++;
    if (!ok) failures++;
}

static void Show(const char* label, const char* in)
{
    printf("    %-12s %-38s -> %s\n", label, in, Render(in).c_str());
}

int main()
{
    /* RFC 9562's example UUID. */
    const char* valid = "550e8400-e29b-41d4-a716-446655440000";

    /* The same string with the pair "41" replaced by "K1". 'K' is not a hex
     * digit, and every UUID parser is required to reject it. */
    const char* withK = "550e8400-e29b-K1d4-a716-446655440000";

    /* Not one hex digit anywhere in either. */
    const char* allG  = "GGGGGGGG-GGGG-GGGG-GGGG-GGGGGGGGGGGG";
    const char* zeroG = "0G0G0G0G-0G0G-0G0G-0G0G-0G0G0G0G0G0G";

    printf("[what the parser returns]\n");
    Show("well-formed", valid);
    Show("one 'K'",     withK);
    Show("all 'G'",     allG);
    Show("'0G' pairs",  zeroG);

    printf("\n[what an application can observe]\n");
    Expect(Render(valid) == Aws::String("550E8400-E29B-41D4-A716-446655440000"),
           "the well-formed UUID round-trips");
    Expect(strcmp(withK, valid) != 0,
           "the 'K' string and the well-formed string are different inputs");
    Expect(Bytes(withK) == Bytes(valid),
           "yet the 'K' string parses to the well-formed UUID's 16 bytes");
    Expect(Render(withK) == Render(valid),
           "and renders as that UUID, so the 'K' is gone from the output");
    /* Array::operator== short-circuits to true when both capacities are 0, but
     * UUID::operator ByteBuffer() is always 16 bytes wide, so this comparison
     * always reaches the element loop and cannot pass vacuously. */
    Expect(Bytes(allG) == Bytes(zeroG),
           "two strings with no hex digit at all parse alike");
    Expect(Render(allG) == Aws::String("10101010-1010-1010-1010-101010101010"),
           "and to a well-formed-looking UUID");

    printf("\n%d of %d checks failed\n", failures, checks);
    return failures != 0;
}
