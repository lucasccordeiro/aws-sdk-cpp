/**
 * Verification-only substitute for aws-c-common's aws/common/byte_buf.h.
 *
 * Included only by the aws/crt/Types.h stub beside it, which Array.h pulls in
 * for ByteBuf. The layout below is the upstream one; nothing here is executed.
 */
#pragma once

#include <cstddef>
#include <cstdint>

struct aws_byte_cursor
{
    size_t len;
    uint8_t *ptr;
};
