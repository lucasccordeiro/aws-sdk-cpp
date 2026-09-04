/**
 * Input for ESBMC's executable-test-case generation:
 *
 *   esbmc harnesses/json_number_ctest.cpp --std c++11 --branch-coverage \
 *         --generate-ctest-testcase --ctest-output-dir results/esbmc-ctest
 *
 * json_number_esbmc.cpp states the conversion's precondition and asks whether it
 * can be violated; this file instead splits the conversion's input into the
 * three regions the precondition distinguishes, so that covering every branch
 * makes the solver produce one concrete double per region. Those doubles are the
 * counterexamples, emitted as compilable __VERIFIER_nondet_double() bodies.
 *
 * The generated CMakeLists.txt would rebuild *this* program with the concrete
 * values, which only re-runs the model. json_number_replay.cpp links the
 * generated value into the real accessors instead, which is the point: it turns
 * a counterexample into a response body the SDK actually mishandles.
 *
 * The names must be __VERIFIER_nondet_*: that is the interface the generator
 * emits implementations for.
 */

extern "C" double __VERIFIER_nondet_double(void);
extern "C" void __VERIFIER_assume(int);

/* -2^63 and 2^63, both exactly representable, so the bounds are exact rather
 * than a rounded approximation of LLONG_MIN / LLONG_MAX. */
static const double LLONG_MIN_AS_DOUBLE = -9223372036854775808.0;
static const double LLONG_MAX_PLUS_ONE = 9223372036854775808.0;

/* volatile so the conversion cannot be optimised away as dead. */
static volatile long long sink;

int main()
{
    double valuedouble = __VERIFIER_nondet_double();
    __VERIFIER_assume(valuedouble == valuedouble); /* JSON cannot spell NaN */

    if (valuedouble >= LLONG_MAX_PLUS_ONE)
    {
        sink = static_cast<long long>(valuedouble); /* J-2, above the range */
        return 1;
    }
    if (valuedouble < LLONG_MIN_AS_DOUBLE)
    {
        sink = static_cast<long long>(valuedouble); /* J-2, below the range */
        return 2;
    }
    sink = static_cast<long long>(valuedouble);     /* representable: defined */
    return 0;
}
