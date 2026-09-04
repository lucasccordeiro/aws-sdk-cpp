/**
 * Executable contract cases for T-2 and T-3 -- ordinary build, no sanitizer.
 *
 * Every row is a sequence an application performs through std::iostream, and
 * every row is run three times: once against std::stringbuf, which SimpleStreamBuf
 * is documented as replacing (SimpleStreamBuf.h:21), and once against each of the
 * two AWS buffers. The std::stringbuf column is the control -- it passes every
 * row, so a row that fails below is a disagreement with the standard rather than
 * an expectation invented here.
 *
 * The payload is "0123456789", so the byte an application reads back names the
 * position it was left at and a wrong seek is visible as a wrong digit.
 *
 * Built with -DNDEBUG, the macro state of a release build. Without it row
 * "seekg(-3,end)" aborts inside seekpos at the assert -- see
 * harnesses/streambuf_witness.cpp, which takes one behaviour per process.
 */

#include <aws/core/utils/stream/PreallocatedStreamBuf.h>
#include <aws/core/utils/stream/SimpleStreamBuf.h>

#include <cstdio>
#include <cstring>
#include <istream>
#include <sstream>
#include <string>

namespace
{
using Aws::Utils::Stream::PreallocatedStreamBuf;
using Aws::Utils::Stream::SimpleStreamBuf;

const char PAYLOAD[] = "0123456789";
const size_t PAYLOAD_LENGTH = sizeof(PAYLOAD) - 1;

/* What the caller can see: the digit at the position the buffer was left at,
 * "FAIL" if the seek reported failure, or "EOF" if there is nothing there. */
std::string Observe(std::iostream &stream)
{
    if (stream.fail())
    {
        return "FAIL";
    }

    char c = 0;
    if (!stream.get(c))
    {
        return "EOF";
    }
    return std::string(1, c);
}

std::string SeekBeg(std::iostream &stream, std::streambuf &, std::streamoff off)
{
    stream.seekg(off, std::ios_base::beg);
    return Observe(stream);
}

std::string SeekEnd(std::iostream &stream, std::streambuf &, std::streamoff off)
{
    stream.seekg(off, std::ios_base::end);
    return Observe(stream);
}

/* pubseekpos and pubseekoff default to in|out. [stringbuf.virtuals] table 144:
 * with both bits set and way == beg, both sequences are positioned. */
std::string SeekPosBoth(std::iostream &stream, std::streambuf &buf, std::streamoff off)
{
    if (buf.pubseekpos(off) == std::streampos(std::streamoff(-1)))
    {
        return "FAIL";
    }
    return Observe(stream);
}

std::string SeekOffBoth(std::iostream &stream, std::streambuf &buf, std::streamoff off)
{
    if (buf.pubseekoff(off, std::ios_base::beg) == std::streampos(std::streamoff(-1)))
    {
        return "FAIL";
    }
    return Observe(stream);
}

struct Case
{
    std::string (*probe)(std::iostream &, std::streambuf &, std::streamoff);
    std::streamoff off;
    const char *expected;
    const char *contract;
};

const Case CASES[] = {
    {SeekBeg, 0, "0", "seekg(0,beg) lands on the first byte"},
    {SeekBeg, 5, "5", "seekg(5,beg) lands on the sixth"},
    {SeekEnd, 0, "EOF", "seekg(0,end) lands one past the last byte"},

    {SeekEnd, -3, "7", "seekg(-3,end) lands three before the end: [stringbuf.virtuals] t.145"},
    {SeekEnd, 3, "FAIL", "seekg(+3,end) is past the end and must fail"},

    {SeekPosBoth, 2, "2", "pubseekpos(2) positions the input sequence too: t.144"},
    {SeekOffBoth, 4, "4", "pubseekoff(4,beg) likewise"},
};

const size_t CASE_COUNT = sizeof(CASES) / sizeof(CASES[0]);

int RunOne(const char *label, std::streambuf &buf, const Case &c)
{
    std::iostream stream(&buf);
    const std::string got = c.probe(stream, buf, c.off);
    const bool ok = got == c.expected;

    printf("  %s  %-10s %-14s got %-6s %s\n", ok ? "PASS" : "FAIL", label, c.expected, got.c_str(), c.contract);
    return ok ? 0 : 1;
}

enum Kind
{
    REFERENCE,
    SIMPLE,
    PREALLOCATED
};

int RunAll(const char *label, Kind kind)
{
    int failures = 0;
    for (size_t i = 0; i < CASE_COUNT; ++i)
    {
        /* A fresh buffer per row: a row must not inherit the position, or the
         * failure, of the row above it. */
        if (kind == REFERENCE)
        {
            std::stringbuf buf(std::string(PAYLOAD), std::ios_base::in | std::ios_base::out);
            failures += RunOne(label, buf, CASES[i]);
        }
        else if (kind == SIMPLE)
        {
            SimpleStreamBuf buf{Aws::String(PAYLOAD)};
            failures += RunOne(label, buf, CASES[i]);
        }
        else
        {
            unsigned char storage[PAYLOAD_LENGTH];
            memcpy(storage, PAYLOAD, sizeof(storage));
            PreallocatedStreamBuf buf(storage, sizeof(storage));
            failures += RunOne(label, buf, CASES[i]);
        }
    }
    return failures;
}
} // namespace

int main()
{
    printf("[std::stringbuf -- the control, and the documented reference]\n");
    const int reference = RunAll("stringbuf", REFERENCE);

    printf("\n[SimpleStreamBuf]\n");
    const int simple = RunAll("simple", SIMPLE);

    printf("\n[PreallocatedStreamBuf]\n");
    const int preallocated = RunAll("prealloc", PREALLOCATED);

    printf("\n%d of %zu reference cases failed\n", reference, CASE_COUNT);
    printf("%d of %zu SimpleStreamBuf cases failed\n", simple, CASE_COUNT);
    printf("%d of %zu PreallocatedStreamBuf cases failed\n", preallocated, CASE_COUNT);

    return (reference + simple + preallocated) != 0;
}
