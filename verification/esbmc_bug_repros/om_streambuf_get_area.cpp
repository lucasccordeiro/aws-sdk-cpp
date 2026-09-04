/**
 * ESBMC reproducer: std::basic_streambuf's get and put areas do nothing.
 *
 * src/cpp/library/streambuf:83-96 declares eback, gptr, egptr, gbump, setg,
 * pbase, pptr, epptr, pbump and setp, and defines none of them. So setg writes
 * nowhere and the accessors return unconstrained values: both assertions below
 * fail, although [streambuf.get.area]/6 states them as setg's postconditions.
 *
 * The consequence is that no user-derived stream buffer can be verified as
 * written -- its arithmetic lives in these calls. aws-sdk-cpp has eight classes
 * deriving from std::basic_streambuf, which is what this reproducer came out of;
 * see ../streambuf/REPORT.md "Fidelity of the model".
 *
 *   $ esbmc --std c++11 --multi-property esbmc_bug_repros/om_streambuf_get_area.cpp
 *   FAILED  [main.assertion.1]  setg postcondition: gptr() == the gnext it was given
 *   FAILED  [main.assertion.2]  setg postcondition: gptr() <= egptr()
 *   VERIFICATION FAILED
 *
 * Expected: VERIFICATION SUCCESSFUL.
 * Observed on ESBMC 8.4.0 and 8.5.0.
 */

#include <streambuf>

class Buf : public std::streambuf
{
public:
    Buf(char *begin, char *end) { setg(begin, begin, end); }
    bool AtBegin() const { return gptr() == eback(); }
    bool Ordered() const { return gptr() <= egptr(); }
};

int main()
{
    char storage[4];
    Buf buf(storage, storage + 4);

    __ESBMC_assert(buf.AtBegin(), "setg postcondition: gptr() == the gnext it was given");
    __ESBMC_assert(buf.Ordered(), "setg postcondition: gptr() <= egptr()");
    return 0;
}
