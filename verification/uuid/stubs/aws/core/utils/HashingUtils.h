/**
 * Verification stub for aws/core/utils/HashingUtils.h.
 *
 * The UUID string constructor calls exactly one HashingUtils member --
 * HexDecode. The upstream header pulls in every hash and checksum backend
 * (CRC32/64, MD5, SHA*, XXHash) which the target does not touch. This stub
 * declares only HexDecode; its body is reproduced verbatim from the 1.11.869
 * HashingUtils.cpp in stubs/aws_str_hash_extract.cpp.
 */
#pragma once

#include <aws/core/utils/Array.h>
#include <aws/core/utils/memory/stl/AWSString.h>

namespace Aws
{
namespace Utils
{
class HashingUtils
{
public:
    static ByteBuffer HexDecode(const Aws::String& str);
};
} // namespace Utils
} // namespace Aws
