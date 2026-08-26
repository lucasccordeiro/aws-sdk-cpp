/**
 * Concrete, argv-driven witness for H-1 -- one input per process.
 *
 * Decodes each argument with the pristine HashingUtils::HexDecode and prints
 * what came back: how many bytes, their values, and whether the input was
 * actually hex. One input per process because a debug build aborts inside
 * HexDecode on a non-alnum byte (assert(0)), which would take a whole table
 * with it.
 *
 * Arguments are C strings, so a byte >= 0x80 is written \xNN and unescaped
 * here -- the shell cannot pass a NUL, and no case needs one.
 *
 * With no arguments it prints the census instead: every two-character string
 * the IsAlnum guard admits, decoded, counted. Requires a release build -- the
 * non-alnum half of the range is not enumerated for that reason.
 */

#include <aws/core/utils/HashingUtils.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>

namespace
{
bool IsHexDigit(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

Aws::String Unescape(const char *arg)
{
    Aws::String out;
    for (size_t i = 0; arg[i] != '\0'; ++i)
    {
        if (arg[i] == '\\' && arg[i + 1] == 'x' && isxdigit((unsigned char)arg[i + 2]) &&
            isxdigit((unsigned char)arg[i + 3]))
        {
            char hex[3] = {arg[i + 2], arg[i + 3], '\0'};
            out.push_back((char)strtol(hex, nullptr, 16));
            i += 3;
        }
        else
        {
            out.push_back(arg[i]);
        }
    }
    return out;
}
} // namespace

namespace
{
bool IsAlnum(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

void Census()
{
    size_t accepted = 0, not_hex = 0, largest_preimage = 0;
    size_t preimage[256] = {0};

    for (int a = 0; a < 256; ++a)
        for (int b = 0; b < 256; ++b)
        {
            char pair[2] = {(char)a, (char)b};
            if (!IsAlnum(pair[0]) || !IsAlnum(pair[1]))
                continue; // a debug build would abort here

            ++accepted;
            if (!IsHexDigit((unsigned char)pair[0]) || !IsHexDigit((unsigned char)pair[1]))
                ++not_hex;

            const Aws::Utils::ByteBuffer out =
                Aws::Utils::HashingUtils::HexDecode(Aws::String(pair, 2));
            if (out.GetLength() == 1) // "0x" and "0X" decode to nothing at all
                ++preimage[out[0]];
        }

    size_t produced = 0;
    for (size_t v = 0; v < 256; ++v)
    {
        produced += preimage[v] ? 1 : 0;
        if (preimage[v] > largest_preimage)
            largest_preimage = preimage[v];
    }

    printf("two-character strings the guard admits : %zu\n", accepted);
    printf("  of which not hex                     : %zu\n", not_hex);
    printf("byte values produced                   : %zu\n", produced);
    printf("largest preimage                       : %zu strings\n", largest_preimage);
}
} // namespace

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        Census();
        return 0;
    }

    for (int a = 1; a < argc; ++a)
    {
        const Aws::String input = Unescape(argv[a]);

        bool strict_hex = input.length() >= 2 && input.length() % 2 == 0;
        for (size_t i = 0; strict_hex && i < input.length(); ++i)
            strict_hex = IsHexDigit((unsigned char)input[i]);

        const Aws::Utils::ByteBuffer out = Aws::Utils::HashingUtils::HexDecode(input);

        printf("input=%-12s len=%2zu hex=%-3s decoded=%zu bytes:", argv[a], input.length(),
               strict_hex ? "yes" : "no", out.GetLength());
        for (size_t i = 0; i < out.GetLength(); ++i)
            printf(" %02X", out[i]);
        printf("\n");
    }
    return 0;
}
