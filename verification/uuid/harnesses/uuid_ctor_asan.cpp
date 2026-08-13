/**
 * Concrete reproducer for the UUID string-constructor buffer overflow, under
 * AddressSanitizer.
 *
 * THE DEFECT (vendor/source/utils/UUID.cpp:34-44)
 * -----------------------------------------------
 *     UUID::UUID(const Aws::String& uuidToConvert)
 *     {
 *         assert(uuidToConvert.length() == UUID_STR_SIZE);        // 36
 *         memset(m_uuid, 0, sizeof(m_uuid));                      // m_uuid[16]
 *         Aws::String escapedHexStr(uuidToConvert);
 *         StringUtils::Replace(escapedHexStr, "-", "");
 *         assert(escapedHexStr.length() == UUID_BINARY_SIZE * 2); // 32
 *         ByteBuffer&& rawUuid = HashingUtils::HexDecode(escapedHexStr);
 *         memcpy(m_uuid, rawUuid.GetUnderlyingData(), rawUuid.GetLength());
 *     }
 *
 * m_uuid is a fixed 16-byte member (UUID.h:54). HexDecode returns a buffer of
 * length floor(hexChars/2), where hexChars is the input length after '-'
 * removal (and an optional "0x" prefix). Both length checks are plain asserts:
 * under NDEBUG -- i.e. any release build of the SDK -- they are compiled out,
 * and nothing else bounds the copy. So an input whose de-dashed hex body
 * exceeds 32 characters decodes to more than 16 bytes, and the memcpy writes
 * past m_uuid: an out-of-bounds WRITE of attacker-influenced data.
 *
 * Example: a 40-hex-character string (no dashes) -> HexDecode returns 20 bytes
 * -> memcpy(m_uuid, ..., 20) writes 4 bytes past the 16-byte object.
 *
 * The UUID object is heap-allocated here so the overflow lands in a real
 * allocation with ASan redzones; the same write off a stack-resident UUID is
 * equally out of bounds.
 *
 * BUILD/RUN: see the `asan` target in the Makefile. Built with -DNDEBUG
 * (release semantics, asserts gone) the overflow is reported by ASan; built
 * without, the length assert fires first -- both are exercised.
 */

#include <aws/core/utils/UUID.h>

#include <cstdio>

int main(int argc, char **argv)
{
  const char *arg = NULL;
  if (argc == 2)
  {
    arg = argv[1];
  }
  else
  {
    fprintf(stderr, "usage: %s <uuid-string>\n", argv[0]);
    return 2;
  }

  Aws::String input(arg);

  size_t hexChars = 0;
  for (size_t i = 0; i < input.length(); ++i)
    if (input[i] != '-')
      ++hexChars;
  if (hexChars >= 2 && (input[0] == '0') && (input[1] == 'x' || input[1] == 'X'))
    hexChars -= 2;

  const size_t decoded = hexChars / 2;
  printf("input_len=%zu hex_chars=%zu decoded_bytes=%zu m_uuid=16%s\n",
         input.length(), hexChars, decoded,
         decoded > 16 ? "  <-- PREDICTED OVERFLOW" : "");
  fflush(stdout);

  Aws::Utils::UUID *u = Aws::New<Aws::Utils::UUID>("uuid-harness", input);

  const Aws::String round = (Aws::String)(*u);
  printf("  constructed, round-trip len=%zu -- no sanitizer diagnostic\n",
         round.length());
  Aws::Delete(u);
  return 0;
}
