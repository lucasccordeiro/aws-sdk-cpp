/**
 * Link stubs for the hash and checksum classes HashingUtils.cpp instantiates.
 *
 * The target is HexDecode, which calls none of them; the other functions in
 * the same translation unit do, so their out-of-line members have to resolve.
 * Every body here is empty on purpose -- reaching one would mean the harness
 * left HexDecode, which no harness does.
 *
 * Aws::Utils::Base64 is not stubbed here: Base64.cpp is vendored pristine, and
 * since 1.11.862 it is a pass-through to aws-crt-cpp, stubbed one level down in
 * stubs/aws/crt/Types.h.
 */

#include <aws/core/utils/checksum/XXHash.h>
#include <aws/core/utils/crypto/CRC32.h>
#include <aws/core/utils/crypto/CRC64.h>
#include <aws/core/utils/crypto/MD5.h>
#include <aws/core/utils/crypto/Sha1.h>
#include <aws/core/utils/crypto/Sha256.h>
#include <aws/core/utils/crypto/Sha256HMAC.h>
#include <aws/core/utils/crypto/Sha512.h>
#include <aws/core/utils/logging/AWSLogging.h>

using Aws::Utils::Crypto::HashResult;

#define AWS_HASH_LINK_STUB(NS, CLASS)                                          \
    NS::CLASS::CLASS() {}                                                      \
    HashResult NS::CLASS::Calculate(const Aws::String &) { return HashResult(); } \
    HashResult NS::CLASS::Calculate(Aws::IStream &) { return HashResult(); }   \
    void NS::CLASS::Update(unsigned char *, size_t) {}                         \
    HashResult NS::CLASS::GetHash() { return HashResult(); }

#define AWS_HASH_LINK_STUB_DTOR(NS, CLASS)                                     \
    AWS_HASH_LINK_STUB(NS, CLASS)                                              \
    NS::CLASS::~CLASS() {}

namespace Crypto = Aws::Utils::Crypto;
namespace Checksum = Aws::Utils::Checksum;

AWS_HASH_LINK_STUB_DTOR(Crypto, MD5)
AWS_HASH_LINK_STUB_DTOR(Crypto, Sha1)
AWS_HASH_LINK_STUB_DTOR(Crypto, Sha256)
AWS_HASH_LINK_STUB_DTOR(Crypto, Sha512)
AWS_HASH_LINK_STUB_DTOR(Crypto, CRC32)
AWS_HASH_LINK_STUB_DTOR(Crypto, CRC32C)
AWS_HASH_LINK_STUB(Crypto, CRC64)
AWS_HASH_LINK_STUB_DTOR(Checksum, XXHash64)
AWS_HASH_LINK_STUB_DTOR(Checksum, XXHash3)
AWS_HASH_LINK_STUB_DTOR(Checksum, XXHash128)

Crypto::Sha256HMAC::Sha256HMAC() {}
Crypto::Sha256HMAC::~Sha256HMAC() {}
HashResult Crypto::Sha256HMAC::Calculate(const Aws::Utils::ByteBuffer &,
                                         const Aws::Utils::ByteBuffer &)
{
    return HashResult();
}

namespace Aws
{
namespace Utils
{
namespace Logging
{
LogSystemInterface *GetLogSystem() { return nullptr; }
} // namespace Logging
} // namespace Utils
} // namespace Aws
