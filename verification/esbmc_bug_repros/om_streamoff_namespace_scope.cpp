/**
 * ESBMC reproducer: std::streamoff and std::streampos are not namespace-scope
 * types.
 *
 * src/cpp/library/ios:162-163 declares them inside class ios, so a program that
 * names them at namespace scope, as the standard declares them, does not parse. ESBMC's own diagnostic
 * points at the member typedefs:
 *
 *   $ esbmc --std c++11 esbmc_bug_repros/om_streamoff_namespace_scope.cpp
 *   error: no type named 'streamoff' in namespace 'std'; did you mean 'std::ios::streamoff'?
 *   error: no type named 'streampos' in namespace 'std'; did you mean 'std::ios::streampos'?
 *   ERROR: PARSING ERROR
 *
 * Every seekoff/seekpos override spells its signature with these types, so this
 * blocks the same code as ../esbmc_bug_repros/om_streambuf_get_area.cpp does.
 * Both are typedef'd to int in the model. [stream.types] requires streamoff to
 * be "one of the signed basic integral types of sufficient size to represent
 * the maximum possible file size for the operating system", which int is not on
 * any mainstream target; [iosfwd.syn] declares streampos as
 * fpos<char_traits<char>::state_type>, not an integer at all.
 *
 * Expected: VERIFICATION SUCCESSFUL.
 * Observed on ESBMC 8.4.0 and 8.5.0.
 */

#include <ios>

std::streamoff offset = 0;
std::streampos position = 0;

int main()
{
    __ESBMC_assert(offset == 0 && position == 0, "namespace-scope stream types are usable");
    return 0;
}
