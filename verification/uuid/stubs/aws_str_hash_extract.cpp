/**
 * Verbatim extracts of the two helper functions the UUID string constructor
 * depends on, lifted from aws-sdk-cpp 1.11.869 so the constructor can be
 * exercised without vendoring the entire hashing/crypto subsystem.
 *
 *   HashingUtils::HexDecode  -- src/aws-cpp-sdk-core/source/utils/HashingUtils.cpp:174-230
 *   StringUtils::Replace     -- src/aws-cpp-sdk-core/source/utils/StringUtils.cpp:23-42
 *
 * Both bodies are byte-for-byte upstream. IsAlnum is reproduced (also verbatim)
 * inline in the StringUtils.h stub. Nothing here is under test -- the target is
 * UUID.cpp -- but HexDecode's output *length* is what drives the constructor's
 * overflowing memcpy, so it must be the real function, not a paraphrase.
 *
 * The two factory definitions at the bottom are pure link stubs: RandomUUID and
 * PseudoRandomUUID are compiled from the real UUID.cpp but never called by the
 * harness, so their externs only need to resolve, not behave.
 */

#include <aws/core/utils/HashingUtils.h>
#include <aws/core/utils/StringUtils.h>
#include <aws/core/utils/crypto/Factories.h>
#include <aws/core/utils/local/Random.h>

#include <cassert>
#include <cctype>
#include <cstring>

namespace Aws
{
namespace Utils
{

ByteBuffer HashingUtils::HexDecode(const Aws::String& str)
{
    //number of characters should be even
    assert(str.length() % 2 == 0);
    assert(str.length() >= 2);

    if(str.length() < 2 || str.length() % 2 != 0)
    {
        return ByteBuffer();
    }

    size_t strLength = str.length();
    size_t readIndex = 0;

    if(str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
    {
        strLength -= 2;
        readIndex = 2;
    }

    ByteBuffer hexBuffer(strLength / 2);
    size_t bufferIndex = 0;

    for (size_t i = readIndex; i < str.length(); i += 2)
    {
        if(!StringUtils::IsAlnum(str[i]) || !StringUtils::IsAlnum(str[i + 1]))
        {
            //contains non-hex characters
            assert(0);
        }

        char firstChar = str[i];
        uint8_t distance = firstChar - '0';

        if(isalpha(firstChar))
        {
            firstChar = static_cast<char>(toupper(firstChar));
            distance = firstChar - 'A' + 10;
        }

        unsigned char val = distance * 16;

        char secondChar = str[i + 1];
        distance = secondChar - '0';

        if(isalpha(secondChar))
        {
            secondChar = static_cast<char>(toupper(secondChar));
            distance = secondChar - 'A' + 10;
        }

        val += distance;
        hexBuffer[bufferIndex++] = val;
    }

    return hexBuffer;
}

void StringUtils::Replace(Aws::String& s, const char* search, const char* replace)
{
    if(!search || !replace)
    {
        return;
    }

    size_t replaceLength = strlen(replace);
    size_t searchLength = strlen(search);

    for (std::size_t pos = 0;; pos += replaceLength)
    {
        pos = s.find(search, pos);
        if (pos == Aws::String::npos)
            break;

        s.erase(pos, searchLength);
        s.insert(pos, replace);
    }
}

namespace Crypto
{
std::shared_ptr<SecureRandomBytes> CreateSecureRandomBytesImplementation()
{
    return nullptr; // link stub: RandomUUID is never called by the harness
}
} // namespace Crypto

std::mt19937::result_type GetRandomValue()
{
    return 0; // link stub: PseudoRandomUUID is never called by the harness
}

} // namespace Utils
} // namespace Aws
