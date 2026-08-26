/**
 * Verification-only stub for <aws/crt/checksum/CRC.h>.
 *
 * CRC32.h and CRC64.h instantiate CRCChecksum with these three function
 * pointers (CRC32.h:109,113; CRC64.h:31), so the names must exist and have the
 * upstream signatures. HexDecode reaches none of them.
 */
#pragma once

#include <aws/crt/Types.h>

#include <cstdint>

namespace Aws
{
    namespace Crt
    {
        namespace Checksum
        {
            inline uint32_t ComputeCRC32(ByteCursor, uint32_t previous = 0) { return previous; }
            inline uint32_t ComputeCRC32C(ByteCursor, uint32_t previous = 0) { return previous; }
            inline uint64_t ComputeCRC64NVME(ByteCursor, uint64_t previous = 0) { return previous; }
        }
    }
}
