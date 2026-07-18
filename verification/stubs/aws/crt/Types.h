/**
 * Verification-only stub for <aws/crt/Types.h>.
 *
 * Array.h includes this for Aws::Crt::ByteBuf, which is used *only* by
 * CryptoBuffer's CRT move-interop ctor/assignment (Array.h:266-291). Base64
 * and the hex codec touch ByteBuffer, never CryptoBuffer, so this type never
 * appears in any harness's reachable call graph -- it just has to exist and
 * expose the four members those two functions name.
 *
 * Layout mirrors aws-c-common's `struct aws_byte_buf`.
 */

#pragma once

#include <cstddef>

struct aws_allocator;

namespace Aws
{
    namespace Crt
    {
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
