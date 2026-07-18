/**
 * Concrete reproducer for the Base64::Decode heap overflow, under sanitizers.
 *
 * This is the fallback oracle for the ESBMC crash documented in
 * esbmc_bug_repros/: the property we wanted a symbolic proof of is instead
 * demonstrated concretely, with ASan as the detector.
 *
 * THE DEFECT (vendor/source/utils/base64/Base64.cpp)
 * --------------------------------------------------
 * Decode sizes its output buffer with CalculateBase64DecodedLength:
 *
 *     len = b64input.length();
 *     if (len < 2) return 0;
 *     padding = (last two chars are '=') ? 2 : (last char is '=') ? 1 : 0;
 *     return len * 3 / 4 - padding;                      // line 138
 *
 * but fills it with a loop bounded by str.length() / 4:
 *
 *     blockCount = str.length() / 4;                     // line 98
 *     for (i = 0; i < blockCount; ++i) {
 *         bufferIndex = i * 3;
 *         buffer[bufferIndex] = ...;                     // line 109
 *         if (value3 != SENTINEL) { buffer[++bufferIndex] = ...;   // 112
 *             if (value4 != SENTINEL) buffer[++bufferIndex] = ...; // 115
 *     } }
 *
 * The two disagree when the input length is NOT a multiple of 4 and the input
 * ends in '='. Take "AAAA=" (length 5):
 *
 *   sizing:  len=5, last char '=' and second-to-last 'A' -> padding = 1
 *            decodedLength = 5*3/4 - 1 = 3 - 1 = 2       -> buffer of 2 bytes
 *   filling: blockCount = 5/4 = 1, so one block is decoded: "AAAA"
 *            'A' maps to 0, and SENTINEL (255) is only ever the value of '=',
 *            so neither value3 nor value4 is SENTINEL and all three stores run
 *            -> writes buffer[0], buffer[1], buffer[2]
 *
 * buffer[2] is one past the end of a 2-byte heap allocation: an out-of-bounds
 * WRITE of attacker-influenced data. The trailing '=' is counted as padding by
 * the sizing pass but is never seen by the filling pass, because the block
 * loop truncates it away.
 *
 * REACHABILITY: Decode is public, is reached from
 * HashingUtils::Base64Decode, and performs no validation of its argument --
 * not length%4, not alphabet membership, not padding position.
 *
 * BUILD/RUN: see the `asan` target in the Makefile. Under a build with
 * NDEBUG set (i.e. any release build of the SDK) the Array::GetItem
 * assert(index < m_length) is compiled out and this is a silent heap
 * corruption; without NDEBUG the assert fires first. Both are checked.
 */

#include "source/utils/base64/Base64.cpp"

#include <cstdio>
#include <cstring>

/* One input per process, so a sanitizer abort on one case cannot hide the
 * verdict on the others. The Makefile's `asan` target drives the table. */
static int hexval(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

int main(int argc, char **argv)
{
  /* -x takes the input as hex so non-printable and high-bit bytes survive the
   * shell intact -- passing a raw 0xFF through command substitution does not
   * work, and silently degrades the test into a no-op. */
  bool as_hex = false;
  const char *arg = NULL;

  if (argc == 2)
  {
    arg = argv[1];
  }
  else if (argc == 3 && strcmp(argv[1], "-x") == 0)
  {
    as_hex = true;
    arg = argv[2];
  }
  else
  {
    fprintf(stderr, "usage: %s <base64-string> | -x <hex-bytes>\n", argv[0]);
    return 2;
  }

  Aws::String decoded_arg;
  if (as_hex)
  {
    const size_t n = strlen(arg);
    if (n % 2 != 0)
    {
      fprintf(stderr, "hex input must have an even number of digits\n");
      return 2;
    }
    for (size_t i = 0; i < n; i += 2)
    {
      const int hi = hexval(arg[i]), lo = hexval(arg[i + 1]);
      if (hi < 0 || lo < 0)
      {
        fprintf(stderr, "bad hex digit\n");
        return 2;
      }
      decoded_arg.push_back((char)((hi << 4) | lo));
    }
  }
  else
  {
    decoded_arg = arg;
  }

  const Aws::Utils::Base64::Base64 codec;
  const Aws::String input(decoded_arg);

  const size_t sized =
    Aws::Utils::Base64::Base64::CalculateBase64DecodedLength(input);
  const size_t blocks = input.length() / 4;

  /* Highest index the fill loop can reach is blocks*3 - 1, since each block
   * performs up to three stores at i*3, i*3+1, i*3+2. The later two are
   * skipped only when that block literally contains '=' in its 3rd/4th
   * position -- which a trailing '=' outside the last full block does not. */
  printf(
    "input=%-12s len=%zu sized=%zu blocks=%zu max_write_index=%zu%s\n",
    as_hex ? arg : decoded_arg.c_str(),
    input.length(),
    sized,
    blocks,
    blocks ? blocks * 3 - 1 : 0,
    (blocks && blocks * 3 > sized) ? "  <-- PREDICTED OVERFLOW" : "");
  fflush(stdout);

  /* The call itself. Under ASan a genuine overflow aborts here. */
  const Aws::Utils::ByteBuffer out = codec.Decode(input);

  printf("  decoded, GetLength()=%zu -- no sanitizer diagnostic\n",
         out.GetLength());
  return 0;
}
