/**
 * Replays one ESBMC-generated counterexample for J-1 against the real SDK.
 *
 * Link with a generated results/esbmc-ctest-print/test_case_N.cpp, which supplies
 * __VERIFIER_nondet_int() -- the literal length the solver chose. This driver
 * builds a response body carrying a number of that many digits and prints the
 * document the way JsonErrorMarshaller::Marshall does, so the counterexample is
 * executed against JsonView and DocumentView rather than against the model.
 *
 * Exit status: 0 the document printed, 3 the length is outside the range the
 * harness constrained, 4 the body did not parse, 134 the process aborted inside
 * WriteCompact -- which is the finding.
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
    const int n = __VERIFIER_nondet_int();
    if (n < 1 || n > 40)
    {
        std::printf("INFIDELITY: length %d is outside the harness's range\n", n);
        return 3;
    }

    char body[64];
    int at = std::snprintf(body, sizeof(body), "{\"n\":");
    for (int i = 0; i < n; i++)
    {
        body[at++] = '9';
    }
    body[at++] = '}';
    body[at] = '\0';

    JsonValue doc{Aws::String{body}};
    if (!doc.WasParseSuccessful())
    {
        std::printf("PARSE FAILED %s\n", body);
        return 4;
    }

    const auto view = doc.View();
    std::printf("digits=%d AsInt64=%" PRId64 " isInteger=%d\n",
                n,
                static_cast<int64_t>(view.GetObject("n").AsInt64()),
                static_cast<int>(view.GetObject("n").IsIntegerType()));

    /* JsonSerializer.cpp:680-681 -- the two lines the property was about. */
    std::printf("round-trip: %s\n", view.WriteCompact().c_str());

    Document ddoc{Aws::String{body}};
    std::printf("document round-trip: %s\n", ddoc.View().WriteCompact().c_str());
    return 0;
}
