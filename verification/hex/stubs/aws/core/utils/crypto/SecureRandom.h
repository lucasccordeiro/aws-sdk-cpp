/**
 * Verification stub for aws/core/utils/crypto/SecureRandom.h.
 *
 * Only the SecureRandomBytes interface is needed so that UUID.cpp's RandomUUID
 * compiles. The string constructor under test never instantiates it; a link
 * stub for the factory lives in stubs/aws_random_link_stub.cpp.
 *
 * Upstream also carries operator bool() over an m_failure flag. Omitting it is
 * safe only because UUID.cpp:75 asserts on the shared_ptr rather than the
 * pointee -- assert(*secureRandom) would have bound to that operator, and this
 * stub would then be changing what a vendored line means.
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
