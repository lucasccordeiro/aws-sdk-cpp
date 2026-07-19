/**
 * ESBMC reproducer: basic_string(const char*, size_t) rejects valid input.
 *
 * ESBMC's C++ operational model (src/cpp/library/string, in the two-argument
 * constructor) asserts:
 *
 *     __ESBMC_assert(n < strlen(s), "basic_string overflow");
 *
 * so the canonical construction below is reported as a violation:
 *
 *   $ esbmc --std c++11 esbmc_bug_repros/om_string_ptr_len_ctor.cpp
 *   Violated property:
 *     file <om>/string line 1132 function basic_string
 *     basic_string overflow
 *     n::1 < return_value$_strlen$1
 *   VERIFICATION FAILED
 *
 * That assert is wrong twice over. [string.cons] gives this constructor
 * exactly one precondition -- "[s, s + n) is a valid range" -- with effects
 * "constructs an object whose initial value is the range [s, s + n)":
 *
 *  1. THE OPERATOR IS WRONG. n == strlen(s) is the canonical case and the
 *     strict `<` rejects it. Only n > strlen(s) could over-read a
 *     null-terminated argument, so even a strlen-based approximation wants
 *     `n <= strlen(s)`.
 *
 *  2. THE PREMISE IS WRONG. `s` need not be null-terminated at all, so
 *     strlen(s) is not part of the precondition -- and calling strlen on a
 *     valid non-terminated argument is itself undefined. A faithful model
 *     cannot be phrased in terms of strlen.
 *
 * Minor, in the same function: the strlen(s) assert is evaluated BEFORE the
 * `s != NULL` assert that follows it, so a null argument is dereferenced
 * before it is checked. The two asserts want swapping regardless.
 *
 * This is a FALSE POSITIVE -- it does not threaten soundness -- but it blocks
 * verification of any code using this constructor. aws-sdk-cpp reaches it via
 * `Aws::String input(raw, len)` in harnesses/base64_decode_harness.cpp, which
 * is what stops the Base64::Decode proof today. See REPORT.md, "Blocked again,
 * one layer up".
 *
 * Found only after esbmc/esbmc#6183 and #6184 were fixed -- nothing could
 * reach this code before that.
 */
#include <string>
#include <cassert>

int main()
{
  /* [string.cons]: constructs from the first n characters at s.
   * n == strlen(s) == 3 is valid and is the common case. */
  std::string s("abc", 3);
  assert(s.size() == 3);

  /* n < strlen(s) -- the only shape the current assert accepts. */
  std::string shorter("abc", 2);
  assert(shorter.size() == 2);

  return 0;
}
