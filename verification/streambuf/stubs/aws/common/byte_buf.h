/**
 * Verification-only substitute for aws-c-common's aws/common/byte_buf.h.
 *
 * StringUtils.h names exactly one type from the CRT -- aws_byte_cursor, in the
 * inline FromByteCursor helper (StringUtils.h:232), which HexDecode does not
 * call. The layout below is the upstream one; nothing here is executed.
 */
#pragma once

#include <cstddef>
#include <cstdint>

struct aws_byte_cursor
{
    size_t len;
    uint8_t *ptr;
};
