/**
 * Verification stub for aws/core/utils/crypto/SecureRandom.h.
 *
 * Only the SecureRandomBytes interface is needed so that UUID.cpp's RandomUUID
 * compiles. The string constructor under test never instantiates it; a link
 * stub for the factory lives in stubs/aws_str_hash_extract.cpp.
 */
#pragma once

#include <cstddef>

namespace Aws
{
namespace Utils
{
namespace Crypto
{
class SecureRandomBytes
{
public:
    virtual ~SecureRandomBytes() = default;
    virtual void GetBytes(unsigned char* buffer, size_t bufferSize) = 0;
};
} // namespace Crypto
} // namespace Utils
} // namespace Aws
