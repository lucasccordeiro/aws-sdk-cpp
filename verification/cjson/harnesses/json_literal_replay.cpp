/**
 * Replays one ESBMC-generated counterexample for J-3 against the real SDK.
 *
 * Link with a generated results/esbmc-ctest-literal/test_case_N.cpp, which
 * supplies __VERIFIER_nondet_int() -- the mantissa first, the exponent second,
 * the order json_literal_ctest.cpp consumes them in. This driver renders that
 * pair as a response body and reads it back exactly as a generated deserializer
 * does, so the counterexample is executed against JsonView and DocumentView.
 *
 * The expected value is recomputed here by repeated multiplication rather than
 * taken from the harness, so the two arrive at it independently.
 *
 * Exit status: 0 the accessors returned the value the literal denotes, 3 the
 * pair is outside the range the harness constrained, 4 the body did not parse,
 * 5 the value read back is wrong -- which is the finding.
 */
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/core/utils/Document.h>

#include <cinttypes>
#include <cstdio>
#include <cstdlib>

extern "C" int __VERIFIER_nondet_int(void);

using Aws::Utils::Json::JsonValue;
using Aws::Utils::Document;

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    const int m = __VERIFIER_nondet_int();
    const int k = __VERIFIER_nondet_int();
    if (m < 1 || m > 9 || k < 0 || k > 18)
    {
        std::printf("INFIDELITY: mantissa %d exponent %d is outside the harness's range\n", m, k);
        return 3;
    }

    int64_t denoted = m;
    for (int i = 0; i < k; i++)
    {
        denoted *= 10;
    }

    char body[64];
    if (k == 0)
    {
        std::snprintf(body, sizeof(body), "{\"n\":%d}", m);
    }
    else
    {
        std::snprintf(body, sizeof(body), "{\"n\":%de%d}", m, k);
    }

    JsonValue doc{Aws::String{body}};
    if (!doc.WasParseSuccessful())
    {
        std::printf("PARSE FAILED %s\n", body);
        return 4;
    }

    const auto view = doc.View();
    const int64_t as_int64 = view.GetObject("n").AsInt64();
    const int64_t get_int64 = view.GetInt64("n");
    Document ddoc{Aws::String{body}};
    const int64_t document_int64 = ddoc.View().GetObject("n").AsInt64();

    const bool exact = as_int64 == denoted && get_int64 == denoted && document_int64 == denoted;
    std::printf("body=%s denoted=%" PRId64 " AsInt64=%" PRId64 " GetInt64=%" PRId64
                " document=%" PRId64 " %s\n",
                body, denoted, as_int64, get_int64, document_int64,
                exact ? "exact" : "WRONG");
    return exact ? 0 : 5;
}
