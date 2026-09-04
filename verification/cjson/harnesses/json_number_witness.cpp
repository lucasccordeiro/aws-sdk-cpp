/**
 * Drives Aws::Utils::Json::JsonValue exactly as a generated deserializer does:
 * construct from a response body, then read a numeric field.
 *
 *   JsonValue(const Aws::String&)          JsonSerializer.cpp:44
 *   JsonView::GetInt64 -> AsInt64          JsonSerializer.cpp:506
 *   JsonView::IsIntegerType                JsonSerializer.cpp:629
 *
 * Every input below is a well-formed JSON document that a service could return.
 */
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/core/utils/Document.h>

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <cstdlib>

using Aws::Utils::Json::JsonValue;
using Aws::Utils::Document;

static void probe(const char* label, const char* body)
{
    JsonValue doc(Aws::String{body});
    if (!doc.WasParseSuccessful())
    {
        std::printf("%-14s %-34s PARSE FAILED\n", label, body);
        return;
    }

    const auto view = doc.View();
    const auto n = view.GetObject("n");

    std::printf("%-14s %-34s isInteger=%d isFloat=%d AsInt64=%" PRId64 " AsDouble=%g\n",
                label, body,
                static_cast<int>(n.IsIntegerType()),
                static_cast<int>(n.IsFloatingPointType()),
                static_cast<int64_t>(n.AsInt64()),
                n.AsDouble());

    const Aws::String printed = doc.View().WriteCompact();
    std::printf("%-14s round-trip: %s\n", label, printed.empty() ? "<EMPTY>" : printed.c_str());
}

static const struct { const char* label; const char* body; } CASES[] = {
    {"control",    "{\"n\":42}"},
    {"int64-max",  "{\"n\":9223372036854775807}"},
    {"exp-no-dot", "{\"n\":1e300}"},
    {"exp-dot",    "{\"n\":1.5e300}"},
    {"inf-dot",    "{\"n\":1.0e999}"},
    {"26-digits",  "{\"n\":99999999999999999999999999}"},
};

/* Document carries the same four accessors and the same two writers
 * (Document.cpp:492, :502, :515, :549, :655, :668), so the evidence has to
 * cover it too rather than argue from the fact that the code is identical. */
static void probe_document(const char* label, const char* body)
{
    Document doc(Aws::String{body});
    if (!doc.WasParseSuccessful())
    {
        std::printf("%-14s %-34s PARSE FAILED\n", label, body);
        return;
    }

    const auto n = doc.View().GetObject("n");
    std::printf("%-14s %-34s isInteger=%d AsInt64=%" PRId64 "\n",
                label, body, static_cast<int>(n.IsIntegerType()), static_cast<int64_t>(n.AsInt64()));
    const Aws::String printed = doc.View().WriteCompact();
    std::printf("%-14s round-trip: %s\n", label, printed.empty() ? "<EMPTY>" : printed.c_str());
}

int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    const size_t count = sizeof(CASES) / sizeof(CASES[0]);
    if (argc > 2 && std::strcmp(argv[1], "document") == 0)
    {
        const size_t i = static_cast<size_t>(atoi(argv[2]));
        if (i >= count) { return 2; }
        probe_document(CASES[i].label, CASES[i].body);
        return 0;
    }
    if (argc > 1)
    {
        const size_t i = static_cast<size_t>(atoi(argv[1]));
        if (i >= count) { return 2; }
        probe(CASES[i].label, CASES[i].body);
        return 0;
    }
    for (size_t i = 0; i < count; ++i) { probe(CASES[i].label, CASES[i].body); }
    return 0;
}
