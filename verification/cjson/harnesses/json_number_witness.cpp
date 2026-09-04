/**
 * Drives Aws::Utils::Json::JsonValue exactly as a generated deserializer does:
 * construct from a response body, then read a numeric field.
 *
 *   JsonValue(const Aws::String&)          JsonSerializer.cpp:28
 *   JsonView::GetInt64                     JsonSerializer.cpp:491
 *   JsonView::WriteCompact / WriteReadable JsonSerializer.cpp:669, :686
 *   JsonView::IsIntegerType                JsonSerializer.cpp:629
 *
 * Every input below is a well-formed JSON document that a service could return.
 * Cases 0-6 are the ones REPORT.md and README.md quote by index; 7-14 pin the
 * two boundaries (J-1's 26th character, J-2's 2^63) from both sides.
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

    std::printf("%-14s %-34s isInteger=%d isFloat=%d AsInt64=%" PRId64 " GetInt64=%" PRId64 " AsDouble=%g\n",
                label, body,
                static_cast<int>(n.IsIntegerType()),
                static_cast<int>(n.IsFloatingPointType()),
                static_cast<int64_t>(n.AsInt64()),
                static_cast<int64_t>(view.GetInt64("n")),
                n.AsDouble());

    const Aws::String compact = doc.View().WriteCompact();
    std::printf("%-14s round-trip: %s\n", label, compact.empty() ? "<EMPTY>" : compact.c_str());
    const Aws::String readable = doc.View().WriteReadable();
    std::printf("%-14s readable: %s\n", label, readable.empty() ? "<EMPTY>" : "printed");
}

static const struct { const char* label; const char* body; } CASES[] = {
    {"control",    "{\"n\":42}"},
    {"int64-max",  "{\"n\":9223372036854775807}"},
    {"exp-no-dot", "{\"n\":1e300}"},
    {"exp-dot",    "{\"n\":1.5e300}"},
    {"inf-dot",    "{\"n\":1.0e999}"},
    {"26-digits",  "{\"n\":99999999999999999999999999}"},
    /* Appended rather than grouped with the other exponent form: the indices
     * are quoted in REPORT.md and README.md. 5e9 is in range for int64 and
     * still kept as a literal, which is what makes J-3 a corruption of a value
     * the SDK could have represented exactly. */
    {"exp-in-range", "{\"n\":5e9}"},
    /* Everything below is likewise appended to keep 0-6 stable.
     *
     * The passing side of J-1's boundary: one character shorter than case 5,
     * so print_number's `length > 25` guard admits it. */
    {"25-digits",  "{\"n\":9999999999999999999999999}"},
    /* J-2's boundary, and the reason the fix's guard is half-open. 2^63 is the
     * smallest double outside int64's range, and (double)INT64_MAX rounds up to
     * it -- so a guard written `d <= (double)INT64_MAX` would admit exactly this
     * value and stay undefined. Its negative counterpart is representable,
     * because the range is asymmetric, and must NOT saturate. */
    {"two-63",     "{\"n\":9223372036854775808.0}"},
    {"int64-min",  "{\"n\":-9223372036854775808.0}"},
    {"below-min",  "{\"n\":-9223372036854777856.0}"},
    {"neg-inf",    "{\"n\":-1.0e999}"},
    {"neg-zero",   "{\"n\":-0.0}"},
    /* The literal path at both ends: in range exactly, and one past it. */
    {"min-lit",    "{\"n\":-9223372036854775808}"},
    {"max-lit-p1", "{\"n\":9223372036854775808}"},
};

/* Document carries the same four accessors and the same two writers
 * (Document.cpp:492, :506, :519, :549, :655, :668), so the evidence has to
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
    std::printf("%-14s %-34s isInteger=%d isFloat=%d AsInt64=%" PRId64 " GetInt64=%" PRId64 "\n",
                label, body,
                static_cast<int>(n.IsIntegerType()),
                static_cast<int>(n.IsFloatingPointType()),
                static_cast<int64_t>(n.AsInt64()),
                static_cast<int64_t>(doc.View().GetInt64("n")));
    const Aws::String compact = doc.View().WriteCompact();
    std::printf("%-14s round-trip: %s\n", label, compact.empty() ? "<EMPTY>" : compact.c_str());
    const Aws::String readable = doc.View().WriteReadable();
    std::printf("%-14s readable: %s\n", label, readable.empty() ? "<EMPTY>" : "printed");
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
