/**
 * Replays one ESBMC-generated counterexample against the real SDK modules.
 *
 * Link with a generated results/esbmc-ctest/test_case_N.cpp, which supplies
 * __VERIFIER_nondet_double(). This driver renders that concrete double as a
 * JSON response body and reads it back exactly as a generated deserializer
 * does, so the counterexample is executed against JsonView and DocumentView
 * rather than against the model ESBMC analysed.
 *
 * Exit status: 0 replayed, 3 the value did not survive rendering, 4 the body
 * did not parse. A sanitizer diagnostic, if the value is out of range, arrives
 * on stderr from the accessors themselves.
 */
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/core/utils/Document.h>

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" double __VERIFIER_nondet_double(void);

using Aws::Utils::Json::JsonValue;
using Aws::Utils::Document;

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    const double d = __VERIFIER_nondet_double();

    char body[512];
    std::snprintf(body, sizeof(body), "{\"n\":%.17g}", d);

    /* The replay is only faithful if the text parses back to the very double
     * the solver chose; %.17g round-trips an IEEE double, and this checks it
     * rather than trusting it. */
    const double reparsed = std::strtod(std::strchr(body, ':') + 1, nullptr);
    if (std::memcmp(&d, &reparsed, sizeof d) != 0)
    {
        std::printf("INFIDELITY: %.17g does not survive rendering\n", d);
        return 3;
    }

    JsonValue doc{Aws::String{body}};
    if (!doc.WasParseSuccessful())
    {
        std::printf("PARSE FAILED %s\n", body);
        return 4;
    }

    const auto view = doc.View();
    std::printf("body=%s AsInt64=%" PRId64 " GetInt64=%" PRId64 " isInteger=%d isFloat=%d\n",
                body,
                static_cast<int64_t>(view.GetObject("n").AsInt64()),
                static_cast<int64_t>(view.GetInt64("n")),
                static_cast<int>(view.GetObject("n").IsIntegerType()),
                static_cast<int>(view.GetObject("n").IsFloatingPointType()));

    Document ddoc{Aws::String{body}};
    std::printf("document AsInt64=%" PRId64 "\n",
                static_cast<int64_t>(ddoc.View().GetObject("n").AsInt64()));
    return 0;
}
