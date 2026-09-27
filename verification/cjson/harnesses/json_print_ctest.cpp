/**
 * Input for ESBMC's executable-test-case generation, J-1:
 *
 *   esbmc harnesses/json_print_ctest.cpp --std c++11 --branch-coverage \
 *         --generate-ctest-testcase --ctest-output-dir results/esbmc-ctest-print
 *
 * json_print_esbmc.cpp asks whether a literal length exists that makes the
 * printer return null. This file splits the length into the two regions the
 * printer's guard distinguishes, so covering every branch makes the solver name
 * a concrete length in each. json_print_replay.cpp then builds a response body
 * with that many digits and hands it to the real JsonValue.
 *
 * The names must be __VERIFIER_nondet_*: that is the interface the generator
 * emits implementations for.
 */

extern "C" int __VERIFIER_nondet_int(void);
extern "C" void __VERIFIER_assume(int);

/* volatile so neither branch can be optimised away as dead. */
static volatile int sink;

int main()
{
    const int n = __VERIFIER_nondet_int();
    __VERIFIER_assume(n >= 1 && n <= 40);

    /* cJSON.cpp:645-646 -- "snprintf failed or buffer overrun occurred", against
     * the 26-byte buffer declared at :613, so 25 characters is the most that can
     * be printed. */
    if (n > 25)
    {
        sink = 1; /* J-1: the document fails to print */
        return 1;
    }
    sink = 0;     /* it fits */
    return 0;
}
