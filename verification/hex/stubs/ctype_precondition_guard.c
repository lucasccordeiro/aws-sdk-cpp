/**
 * LD_PRELOAD guard for the <cctype> precondition, C17 7.4p1: the argument to
 * isalpha/toupper "shall be representable as an unsigned char or shall equal
 * the macro EOF", otherwise the behaviour is undefined.
 *
 * HexDecode passes a plain `char` (HashingUtils.cpp:208,210,219,221), which is
 * signed on every mainstream ABI, so any input byte >= 0x80 that gets past the
 * IsAlnum gate reaches these functions negative. Neither UBSan nor ESBMC's
 * ctype model checks that precondition -- glibc's table happens to be padded
 * for negative indices -- so this interposer makes the violation observable:
 * it reports the offending value and aborts, and is otherwise transparent.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#undef isalpha
#undef toupper

static void check(const char *fn, int c)
{
    if (c != EOF && (c < 0 || c > 255))
    {
        fprintf(stderr, "ctype precondition violated: %s(%d) -- not representable as unsigned char\n", fn, c);
        abort();
    }
}

int isalpha(int c)
{
    check("isalpha", c);
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

int toupper(int c)
{
    check("toupper", c);
    return (c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c;
}
