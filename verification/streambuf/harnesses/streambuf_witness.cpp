/**
 * T-1 witnesses -- one behaviour per process, because the third one aborts.
 *
 *   ./witness invariant   what setg is handed after an ordinary read/seek mix
 *   ./witness stale       what a read past the written data returns
 *   ./witness crash       what the same read does when it spans more than a byte
 *   ./witness write       the same defect through xsputn rather than underflow
 *
 * The first three share one sequence: write, seekg forward, seekp back, read.
 * `write` differs only in ending with a write, which reaches the second of the
 * two places this class hands setg an unchecked pptr() (SimpleStreamBuf.cpp:197,
 * beside :221). Nothing here is out of contract for std::iostream -- an
 * application that rewinds the put position of a stream it is also reading does
 * exactly this -- and the runs against std::stringbuf are the control that says
 * so.
 *
 * Observer exposes the get-area pointers, which std::streambuf makes protected;
 * it adds no state and overrides nothing, so the code under test is unchanged.
 */

#include <aws/core/utils/stream/SimpleStreamBuf.h>

#include <cstdio>
#include <cstring>
#include <istream>
#include <sstream>
#include <string>

namespace
{
const size_t WRITTEN = 50;   /* bytes the application writes */
const size_t READ_TO = 40;   /* where it leaves the get pointer */
const size_t PUT_BACK_TO = 10; /* where it rewinds the put pointer */

class Observer : public Aws::Utils::Stream::SimpleStreamBuf
{
public:
    std::ptrdiff_t GetOffset() const { return gptr() - eback(); }
    std::ptrdiff_t GetAreaEnd() const { return egptr() - eback(); }
    std::ptrdiff_t PutOffset() const { return pptr() - eback(); }
};

/* write, seekg forward, seekp back -- then let the caller do the read. */
void Interleave(std::iostream &stream)
{
    const std::string payload(WRITTEN, 'A');
    stream.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    stream.seekg(static_cast<std::streamoff>(READ_TO));
    stream.seekp(static_cast<std::streamoff>(PUT_BACK_TO));
}

int Invariant()
{
    Observer buf;
    std::iostream stream(&buf);
    Interleave(stream);

    /* Drain the get area, which is what drives underflow(). */
    char sink[WRITTEN];
    stream.read(sink, static_cast<std::streamsize>(WRITTEN - READ_TO));
    char one = 0;
    stream.get(one);

    printf("after underflow: gptr=%td egptr=%td pptr=%td\n", buf.GetOffset(), buf.GetAreaEnd(), buf.PutOffset());
    printf("get area well-formed, gptr <= egptr: %s\n", buf.GetOffset() <= buf.GetAreaEnd() ? "yes" : "no");
    return 0;
}

int Stale()
{
    Observer buf;
    std::iostream stream(&buf);
    Interleave(stream);

    char sink[WRITTEN];
    stream.read(sink, static_cast<std::streamsize>(WRITTEN - READ_TO));

    char one = 0;
    const bool got = static_cast<bool>(stream.get(one));
    printf("read past the written data: %s", got ? "returned a byte" : "reported EOF");
    if (got)
    {
        /* The payload is WRITTEN copies of 'A', so any other byte is one the
         * application never wrote -- checked, not asserted in the message. */
        printf(" 0x%02x, which the application %s", static_cast<unsigned char>(one),
               one == 'A' ? "did write" : "never wrote");
    }
    printf("\n");
    return 0;
}

int Crash()
{
    Observer buf;
    std::iostream stream(&buf);
    Interleave(stream);

    char sink[WRITTEN];
    printf("reading %zu bytes across the exhausted get area\n", WRITTEN);
    fflush(stdout);
    stream.read(sink, static_cast<std::streamsize>(WRITTEN));
    printf("read returned, gcount=%ld\n", static_cast<long>(stream.gcount()));
    return 0;
}

/* Drain the get area, rewind the put pointer, then *write*. The write lands in
 * xsputn, which re-points the end of the get area at the put pointer exactly as
 * underflow does -- so the same inversion arrives without underflow running. */
void InterleaveWithWrite(std::iostream &stream)
{
    const std::string payload(WRITTEN, 'A');
    stream.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    stream.seekg(static_cast<std::streamoff>(READ_TO));

    char sink[WRITTEN - READ_TO];
    stream.read(sink, static_cast<std::streamsize>(sizeof(sink)));

    stream.seekp(static_cast<std::streamoff>(PUT_BACK_TO));
    stream.write("BBBBB", 5);
}

int Write()
{
    Observer buf;
    std::iostream stream(&buf);
    InterleaveWithWrite(stream);

    printf("after the write: gptr=%td egptr=%td pptr=%td\n", buf.GetOffset(), buf.GetAreaEnd(), buf.PutOffset());
    printf("get area well-formed, gptr <= egptr: %s\n", buf.GetOffset() <= buf.GetAreaEnd() ? "yes" : "no");

    char out[WRITTEN];
    stream.clear();
    printf("reading %zu bytes after it\n", WRITTEN);
    fflush(stdout);
    stream.read(out, static_cast<std::streamsize>(WRITTEN));
    printf("read returned, gcount=%ld\n", static_cast<long>(stream.gcount()));
    return 0;
}

/* The same two sequences on the buffer SimpleStreamBuf replaces. */
int Reference()
{
    std::stringbuf buf(std::ios_base::in | std::ios_base::out);
    std::iostream stream(&buf);
    Interleave(stream);

    char sink[WRITTEN];
    stream.read(sink, static_cast<std::streamsize>(WRITTEN));
    printf("std::stringbuf on the same sequence: gcount=%ld\n", static_cast<long>(stream.gcount()));

    std::stringbuf wbuf(std::ios_base::in | std::ios_base::out);
    std::iostream wstream(&wbuf);
    InterleaveWithWrite(wstream);
    char out[WRITTEN];
    wstream.clear();
    wstream.read(out, static_cast<std::streamsize>(WRITTEN));
    printf("std::stringbuf ending in a write: gcount=%ld\n", static_cast<long>(wstream.gcount()));
    return 0;
}
} // namespace

int main(int argc, char **argv)
{
    const char *what = argc > 1 ? argv[1] : "invariant";

    if (strcmp(what, "invariant") == 0) return Invariant();
    if (strcmp(what, "stale") == 0) return Stale();
    if (strcmp(what, "crash") == 0) return Crash();
    if (strcmp(what, "write") == 0) return Write();
    if (strcmp(what, "reference") == 0) return Reference();

    fprintf(stderr, "usage: %s invariant|stale|crash|write|reference\n", argv[0]);
    return 2;
}
