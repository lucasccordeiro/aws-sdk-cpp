/**
 * Symbolic harness for T-1, T-2 and T-3: what the SDK's two hand-written stream
 * buffers do with a seek, over every offset rather than the handful the native
 * legs try.
 *
 * Targets, sliced verbatim out of the pristine sources by reproduce.sh:
 *   vendor/source/utils/stream/SimpleStreamBuf.cpp:67-112 (seekoff, seekpos)
 *   vendor/source/utils/stream/SimpleStreamBuf.cpp:217-232 (underflow)
 *   vendor/source/utils/stream/PreallocatedStreamBuf.cpp:16-72 (ctor, seekoff, seekpos)
 *
 * WHAT THE STANDARD SAYS
 * ----------------------
 * SimpleStreamBuf is documented as a replacement for std::stringbuf
 * (SimpleStreamBuf.h:21), so [stringbuf.virtuals] is the contract both buffers
 * are read against here:
 *
 *   table 145 + p11  way == end gives newoff = high_mark - xbeg, and the new
 *                    position is xbeg + newoff + off. The offset is *added*;
 *                    seeking to the last three bytes is off == -3.
 *   table 144        with in|out set and way == beg or end, *both* sequences
 *                    are positioned. Not one of them, and not neither.
 *   [streambuf.get.area]/5  setg requires [gbeg, gnext), [gbeg, gend) and
 *                    [gnext, gend) to be valid ranges, so gnext <= gend.
 *
 * SEMANTICS
 * ---------
 * Release semantics is -D NDEBUG, the macro state of a shipped build, not
 * ESBMC's --no-assertions -- which would also drop __ESBMC_assert and leave the
 * harness unable to state anything. Run without it, SEEK_END stops at the
 * module's own assert (SimpleStreamBuf.cpp:95) instead of at the property: a
 * debug build turns T-2 from a wrong answer into an abort, which is the same
 * defect and a different observable.
 *
 * MODES
 * -----
 *   HARNESS_MODE_SEEK_END (default)
 *       SimpleStreamBuf::seekoff(off, end, in) against table 145.
 *
 *   HARNESS_MODE_SEEK_ZERO
 *       The same property with off == 0 -- the control. Expect SUCCESSFUL:
 *       zero is its own negation, so the one end-relative seek the SDK's own
 *       callers perform is also the one the sign error cannot reach, and the
 *       property is not false for every input.
 *
 *   HARNESS_MODE_SEEK_BACK
 *       The same property over -length <= off <= -1 -- every seek that asks for
 *       a position inside the sequence, and none that asks for one outside it.
 *       Run with the module's asserts live it stops at SimpleStreamBuf.cpp:95:
 *       a debug build does not merely answer wrongly here, it aborts. Keeping
 *       the offsets inside is what makes that row mean something, since the
 *       same assert also fires for a seek that really is out of range.
 *
 *   HARNESS_MODE_SEEK_BOTH
 *       SimpleStreamBuf::seekpos(pos, in|out) against table 144: a call that
 *       reports success must have moved both pointers to pos.
 *
 *   HARNESS_MODE_GET_AREA
 *       underflow() from a well-formed get area. Property: setg's precondition
 *       still holds afterwards. The entry state is constrained to gptr <= egptr
 *       -- what the class has when its own operations built it -- so a
 *       violation is the module turning a good state into a bad one, not the
 *       harness handing it a bad one.
 *
 *   HARNESS_MODE_PREALLOC_END / HARNESS_MODE_PREALLOC_BOTH
 *       The same two properties against PreallocatedStreamBuf, the buffer the
 *       transfer manager puts on every multipart upload part.
 */

#include "streambuf_scaffold.h"

#ifndef SIZE
#define SIZE 8
#endif

extern "C" long nondet_long();

using Aws::Utils::Stream::PreallocatedStreamBuf;
using Aws::Utils::Stream::SimpleStreamBuf;

namespace
{
const std::streampos SEEK_FAILED = std::streampos(std::streamoff(-1));

long SymbolicOffsetWithin(long lo, long hi)
{
    const long v = nondet_long();
    __ESBMC_assume(v >= lo && v <= hi);
    return v;
}
} // namespace

int main()
{
    /* How much of the buffer holds data. Every property below is stated over
     * all of them, not one chosen length. */
    const long length = SymbolicOffsetWithin(1, SIZE);

#if defined(HARNESS_MODE_PREALLOC_END) || defined(HARNESS_MODE_PREALLOC_BOTH)
    unsigned char bytes[SIZE];
    PreallocatedStreamBuf buf(bytes, (uint64_t)length);
#else
    char buffer[SIZE];
    SimpleStreamBuf buf(buffer, SIZE, length);
#endif

#if defined(HARNESS_MODE_GET_AREA)
    const long getPos = SymbolicOffsetWithin(0, SIZE - 1);
    const long getEnd = SymbolicOffsetWithin(0, SIZE - 1);
    const long putPos = SymbolicOffsetWithin(0, SIZE);
    __ESBMC_assume(getPos <= getEnd); /* [streambuf.get.area]/5 held on entry */

    buf.InstallAreas(getPos, getEnd, putPos);
    buf.underflow();

    __ESBMC_assert(
        buf.gptr() <= buf.egptr(),
        "underflow left the get area with gptr past egptr, which setg forbids");

#elif defined(HARNESS_MODE_SEEK_BOTH) || defined(HARNESS_MODE_PREALLOC_BOTH)
    const long pos = SymbolicOffsetWithin(0, length);

    const std::streampos got = buf.seekpos(pos, std::ios_base::in | std::ios_base::out);

    __ESBMC_assert(
        got == SEEK_FAILED ||
            (buf.gptr() == buf.eback() + pos && buf.pptr() == buf.eback() + pos),
        "a seek that reported success positioned neither sequence");

#else
    /* One past each end of the buffer, so the property covers the offsets that
     * must fail as well as the ones that must land somewhere. */
#if defined(HARNESS_MODE_SEEK_ZERO)
    const long off = 0;
#elif defined(HARNESS_MODE_SEEK_BACK)
    /* Bounded by the data, so every offset here names a position that exists:
     * whatever the run reports, it cannot be a caller asking for one that
     * does not. */
    const long off = SymbolicOffsetWithin(-length, -1);
#else
    const long off = SymbolicOffsetWithin(-SIZE - 1, SIZE + 1);
#endif

    const std::streampos got = buf.seekoff(off, std::ios_base::end, std::ios_base::in);
    const long want = length + off; /* [stringbuf.virtuals] table 145, p11 */

    if (want >= 0 && want <= length)
    {
        __ESBMC_assert(
            got == std::streampos(want) && buf.gptr() == buf.eback() + want,
            "an end-relative seek inside the sequence did not land at length + off");
    }
    else
    {
        __ESBMC_assert(
            got == SEEK_FAILED,
            "an end-relative seek outside the sequence reported success");
    }
#endif

    return 0;
}
