/**
 * Verification-only stub for <aws/crt/StringUtils.h>.
 *
 * AWSString.h:118 uses Aws::Crt::HashString for std::hash<Aws::String>.
 * Nothing in the hex harnesses hashes a string.
 */
#pragma once

#include <cstddef>

namespace Aws
{
    namespace Crt
    {
        inline std::size_t HashString(const char *) { return 0; }
    }
}
