/**
 * The conversion JsonView performs on a wire-supplied number, with the double
 * left symbolic.
 *
 *   JsonSerializer.cpp:515  AsInt64             static_cast<int64_t>(valuedouble)
 *   JsonSerializer.cpp:641  IsIntegerType       static_cast<long long>(valuedouble)
 *   JsonSerializer.cpp:656  IsFloatingPointType static_cast<long long>(valuedouble)
 *   Document.cpp:492,549    the same two predicates
 *
 * ESBMC has no check of its own for an out-of-range floating-point to integer
 * conversion -- `--overflow-check --nan-check` reports SUCCESSFUL on a bare
 * `(long long)1e300` -- so the precondition [conv.fpint]/1 imposes is stated
 * here as the property, at the site, rather than left to the tool to infer.
 *
 * valuedouble is whatever strtod returned for the literal in the response
 * (cJSON.cpp:386), so the only values excluded below are the ones JSON's
 * grammar cannot spell: it has no NaN literal. Infinity it can spell, as an
 * exponent that overflows -- {"n":1.0e999}.
 */

extern "C" double nondet_double(void);

/* -2^63 and 2^63: both exactly representable, so the bound is exact rather than
 * a rounded approximation of LLONG_MIN / LLONG_MAX. */
static const double LLONG_MIN_AS_DOUBLE = -9223372036854775808.0;
static const double LLONG_MAX_PLUS_ONE = 9223372036854775808.0;

static long long convert(double valuedouble)
{
#ifdef FIXED
    if (!(valuedouble >= LLONG_MIN_AS_DOUBLE && valuedouble < LLONG_MAX_PLUS_ONE))
    {
        return valuedouble < 0 ? (-9223372036854775807LL - 1) : 9223372036854775807LL;
    }
#endif
    __ESBMC_assert(valuedouble >= LLONG_MIN_AS_DOUBLE && valuedouble < LLONG_MAX_PLUS_ONE,
                   "[conv.fpint] the double is representable as long long");
    return static_cast<long long>(valuedouble);
}

int main()
{
    double valuedouble = nondet_double();
    __ESBMC_assume(valuedouble == valuedouble); /* JSON cannot spell NaN */

    long long converted = convert(valuedouble);

#ifdef FIXED
    /* The fix saturates the way cJSON's own parse_number already does for
     * valueint ("use saturation in case of overflow", cJSON.cpp:401). */
    __ESBMC_assert(valuedouble >= LLONG_MIN_AS_DOUBLE || converted == (-9223372036854775807LL - 1),
                   "below the range, saturates low");
    __ESBMC_assert(valuedouble < LLONG_MAX_PLUS_ONE || converted == 9223372036854775807LL,
                   "above the range, saturates high");
#endif
    (void)converted;
    return 0;
}
