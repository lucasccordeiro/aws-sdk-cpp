/**
 * Verification stub for aws/core/utils/StringUtils.h.
 *
 * UUID.cpp uses exactly two members of StringUtils -- Replace and IsAlnum (the
 * latter via HexDecode). The upstream header drags in the whole string-utility
 * surface; this stub declares only what the target translation unit names.
 * IsAlnum is reproduced verbatim from the 1.11.869 header; Replace is defined
 * out-of-line in stubs/aws_str_hash_extract.cpp, also verbatim.
 */
#pragma once

#include <aws/core/utils/memory/stl/AWSString.h>

namespace Aws
{
namespace Utils
{
class StringUtils
{
public:
    static void Replace(Aws::String& s, const char* search, const char* replace);

    static bool IsAlnum(char c)
    {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    }
};
} // namespace Utils
} // namespace Aws
