/**
 * Verification stub for aws/core/utils/crypto/Factories.h.
 *
 * Declares only CreateSecureRandomBytesImplementation, which UUID::RandomUUID
 * names. The definition is a link stub in stubs/aws_random_link_stub.cpp; the
 * string constructor under test never reaches it.
 */
#pragma once

#include <aws/core/utils/crypto/SecureRandom.h>

#include <memory>

namespace Aws
{
namespace Utils
{
namespace Crypto
{
std::shared_ptr<SecureRandomBytes> CreateSecureRandomBytesImplementation();
} // namespace Crypto
} // namespace Utils
} // namespace Aws
