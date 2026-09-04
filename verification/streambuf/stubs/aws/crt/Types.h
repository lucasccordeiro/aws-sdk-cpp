/**
 * Verification-only stub for <aws/crt/Types.h>, standing in for the
 * aws-crt-cpp submodule. Nothing under analysis here reaches any of what
 * follows; the names exist so the translation unit compiles and links.
 * Array.h (vendored) is the only header in this tree that includes it.
 *
 * Layouts mirror aws-c-common's `struct aws_byte_buf` / `aws_byte_cursor`.
 */

#pragma once

#include <aws/common/byte_buf.h>

#include <cstddef>
#include <string>
#include <vector>

struct aws_allocator;

namespace Aws
{
    namespace Crt
    {
        /* Array.h includes this header for ByteBuf, used only by CryptoBuffer's
         * CRT move-interop ctor and assignment (Array.h:266-291). The stream
         * buffers touch neither; PreallocatedStreamBuf takes a raw uint8_t*. */
        struct ByteBuf
        {
            struct aws_allocator *allocator;
            unsigned char *buffer;
            std::size_t len;
            std::size_t capacity;
        };

        /* HashingUtils.cpp reaches the CRT again through the CRC and XXHash
         * checksum classes, which name these two. */
        using ByteCursor = aws_byte_cursor;

        inline ByteCursor ByteCursorFromArray(const unsigned char *ptr, std::size_t len)
        {
            ByteCursor cursor;
            cursor.len = len;
            cursor.ptr = const_cast<unsigned char *>(ptr);
            return cursor;
        }

        /* Declared only because Array.h's include of this header expects the
         * namespace to exist. No source in this tree calls them. */
        inline std::string Base64Encode(ByteCursor) { return std::string(); }
        inline std::vector<unsigned char> Base64Decode(ByteCursor) { return std::vector<unsigned char>(); }
        inline std::size_t Base64EncodedLength(ByteCursor) { return 0; }
        inline std::size_t Base64DecodedLength(ByteCursor) { return 0; }
    }
}

/* aws-c-common's default allocator accessor, referenced by CryptoBuffer's
 * `assert(get_aws_allocator() == other.allocator)`. Never called from any
 * harness; returning nullptr keeps it a pure declaration-satisfier. */
inline struct aws_allocator *get_aws_allocator() { return nullptr; }
