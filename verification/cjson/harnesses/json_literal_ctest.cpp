/**
 * Input for ESBMC's executable-test-case generation, J-3:
 *
 *   esbmc harnesses/json_literal_ctest.cpp --std c++11 --branch-coverage \
 *         --generate-ctest-testcase --ctest-output-dir results/esbmc-ctest-literal
 *
 * json_literal_esbmc.cpp asks whether a kept literal can read back as something
 * other than the number it spells. This file splits the same input into the
 * three regions the parser's own condition distinguishes, so covering every
 * branch makes the solver name a concrete mantissa and exponent in each.
 * json_literal_replay.cpp then builds {"n":<m>e<k>} and reads it back through
 * the real accessors.
 *
 * The two calls below fix the order the generated __VERIFIER_nondet_int() is
 * consumed in: mantissa first, exponent second. json_literal_replay.cpp calls it
 * in the same order.
 */

extern "C" int __VERIFIER_nondet_int(void);
extern "C" void __VERIFIER_assume(int);

static volatile int sink;

int main()
{
    const int m = __VERIFIER_nondet_int();
    const int k = __VERIFIER_nondet_int();
    __VERIFIER_assume(m >= 1 && m <= 9);
    __VERIFIER_assume(k >= 0 && k <= 18);

    if (k == 0)
    {
        sink = 0; /* plain digits: no exponent for atoll to stop at */
        return 0;
    }

    /* cJSON.cpp:399 keeps the literal only outside [INT_MIN, INT_MAX]. For a
     * single-digit mantissa that is exactly the condition below: 3e9 exceeds
     * INT_MAX and 2e9 does not, and every k of 10 or more does whatever m is.
     * Written this way rather than as m * 10^k so that the loop computing the
     * power does not become a branch of its own -- the generator would then emit
     * one test case per iteration count instead of one per region. */
    if (k >= 10 || (k == 9 && m >= 3))
    {
        sink = 1; /* J-3: the literal is kept and read with atoll */
        return 1;
    }
    sink = 2;     /* exponent form, but small enough that no literal is kept */
    return 2;
}
