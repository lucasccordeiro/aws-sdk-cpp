/**
 * Verification-only stub for <aws/crt/Types.h>, standing in for the
 * aws-crt-cpp submodule. Nothing under analysis here reaches what follows; the
 * names exist so the translation unit compiles and links. Array.h (vendored) is
 * the only header in this tree that includes it.
 *
 * Layout mirrors aws-c-common's `struct aws_byte_buf`. StringUtils.h:232 names
 * `aws_byte_cursor` directly, from <aws/common/byte_buf.h>, so no alias for it
 * is needed here.
 */

#pragma once

#include <aws/common/byte_buf.h>

#include <cstddef>

struct aws_allocator;

namespace Aws
{
    namespace Crt
    {
        /* Array.h includes this header for ByteBuf, used only by CryptoBuffer's
         * CRT move-interop ctor and assignment (Array.h:266-291). Nothing on the
         * JSON number path constructs a CryptoBuffer, so the layout only has to
         * satisfy the compiler. */
        struct ByteBuf
        {
            struct aws_allocator *allocator;
            unsigned char *buffer;
            std::size_t len;
            std::size_t capacity;
        };
    }
}

/* aws-c-common's default allocator accessor, referenced by CryptoBuffer's
 * `assert(get_aws_allocator() == other.allocator)`. Never called from any
 * harness; returning nullptr keeps it a pure declaration-satisfier. */
inline struct aws_allocator *get_aws_allocator() { return nullptr; }
