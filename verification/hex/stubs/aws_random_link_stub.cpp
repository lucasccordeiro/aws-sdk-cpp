/**
 * Link stubs for the two random sources UUID.cpp's generating constructors
 * reach. The entry-point harness parses UUID strings and never generates one,
 * so neither body can run; they exist so UUID.cpp links pristine rather than
 * being edited or partially compiled.
 */

#include <aws/core/utils/crypto/Factories.h>
#include <aws/core/utils/local/Random.h>

namespace Aws
{
namespace Utils
{
namespace Crypto
{
std::shared_ptr<SecureRandomBytes> CreateSecureRandomBytesImplementation()
{
    return nullptr;
}
} // namespace Crypto

std::mt19937::result_type GetRandomValue()
{
    return 0;
}
} // namespace Utils
} // namespace Aws
