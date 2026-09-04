/**
 * J-3, as a property: does the accessor return the value the literal denotes?
 *
 *   cJSON.cpp:397-402         parse_number keeps the literal for any number with
 *                             no decimal point outside [INT_MIN, INT_MAX] --
 *                             which includes exponent forms, since 1.11.660
 *   StringUtils.cpp:337-349     ConvertToInt64(const char*) is std::atoll
 *   JsonSerializer.cpp:498,511  GetInt64 and AsInt64 return its answer unchanged
 *   Document.cpp:502,515        the same two accessors again
 *
 * Those four are the `if (valuestring)` arm. The `else` arm two lines below each
 * -- :502,515 and :506,519 -- is J-2's unguarded conversion, a different defect.
 *
 * The function under analysis is the one the SDK calls. std::atoll is not
 * transcribed here: ESBMC supplies it from its own C library model
 * (src/c2goto/library/stdlib.c, ATOI_DEF), which implements C11 7.22.1.2p2's
 * "equivalent to strtoll(nptr, NULL, 10)" -- leading space, optional sign, then
 * digits up to the first character that cannot continue the subject sequence
 * (7.22.1.4p4). That last clause is the defect: the character is the 'e'.
 *
 * Aws::Utils::StringUtils itself is not linked in. ESBMC 8.5.0's C++ frontend
 * rejects StringUtils.cpp -- its std::string operational model has no rbegin or
 * rend, and ::isspace is not in the global namespace -- so the one-line body is
 * quoted above and its callee analysed directly.
 *
 * The mantissa and the exponent are both symbolic. Nothing here says 5e9;
 * ESBMC is asked whether any literal the parser keeps can read back as something
 * other than the number it spells.
 */

#include <stdlib.h>

extern "C" int nondet_int(void);

#ifdef FIXED
/* fix/json-number-range-and-print.patch, transcribed: strtoll saturates an
 * out-of-range literal itself (C11 7.22.1.4p8), so its answer stands whenever it
 * consumed the whole literal; otherwise the double is used, saturating. */
static const double LLONG_MIN_AS_DOUBLE = -9223372036854775808.0;
static const double LLONG_MAX_PLUS_ONE = 9223372036854775808.0;

static long long ToInt64Saturating(double value)
{
    if (value != value)
    {
        return 0;
    }
    if (value >= LLONG_MAX_PLUS_ONE)
    {
        return 9223372036854775807LL;
    }
    if (value < LLONG_MIN_AS_DOUBLE)
    {
        return -9223372036854775807LL - 1;
    }
    return (long long)value;
}

static long long LiteralToInt64(const char *literal, double valuedouble)
{
    char *end = 0;
    const long long parsed = strtoll(literal, &end, 10);
    if (*end == '\0')
    {
        return parsed;
    }
    return ToInt64Saturating(valuedouble);
}
#endif

int main()
{
    const int m = nondet_int(); /* mantissa digit */
    const int k = nondet_int(); /* decimal exponent */
    __ESBMC_assume(m >= 1 && m <= 9);
    /* 10^18 * 9 still fits int64, and a single-digit mantissa times a power of
     * ten is exact in a double up to 10^22, so the value below is the number the
     * literal spells and not a rounding of it. */
    __ESBMC_assume(k >= 1 && k <= 18);

    /* A table rather than a loop: eighteen symbolic 64-bit multiplications put
     * Z3 past any time this suite should take. The table is not trusted -- the
     * assertion below makes ESBMC check the entry it selects against its
     * predecessor, so a typo fails the row instead of weakening it. */
    static const long long POW10[19] = {
        1LL, 10LL, 100LL, 1000LL, 10000LL, 100000LL, 1000000LL, 10000000LL,
        100000000LL, 1000000000LL, 10000000000LL, 100000000000LL,
        1000000000000LL, 10000000000000LL, 100000000000000LL,
        1000000000000000LL, 10000000000000000LL, 100000000000000000LL,
        1000000000000000000LL};
    __ESBMC_assert(POW10[k] == 10LL * POW10[k - 1], "the power of ten is the one it says");

    const long long denoted = (long long)m * POW10[k];

    /* cJSON.cpp:399 -- below this the parser keeps no literal and the accessor
     * takes the double branch, which answers correctly. */
    __ESBMC_assume(denoted > 2147483647LL);

    char literal[6];
    literal[0] = (char)('0' + m);
    literal[1] = 'e';
    if (k < 10)
    {
        literal[2] = (char)('0' + k);
        literal[3] = '\0';
    }
    else
    {
        literal[2] = (char)('0' + k / 10);
        literal[3] = (char)('0' + k % 10);
        literal[4] = '\0';
    }

#ifdef FIXED
    const long long read_back = LiteralToInt64(literal, (double)denoted);
#else
    const long long read_back = atoll(literal); /* StringUtils::ConvertToInt64 */
#endif

    __ESBMC_assert(read_back == denoted,
                   "the accessor returns the value the kept literal denotes");
    return 0;
}
