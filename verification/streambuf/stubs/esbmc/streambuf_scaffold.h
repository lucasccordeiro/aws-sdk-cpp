/**
 * Verification-only scaffolding for the ESBMC leg: the two classes' declarations
 * and the state setup the harness needs, with nothing in the bodies of the five
 * functions under test -- reproduce.sh cuts those out of the pristine sources at
 * run time and appends them to this header's includer.
 *
 * Three things differ from the SDK headers, all of them here rather than in the
 * sliced bytes:
 *
 *  1. The base class is verification::StreamBufBase, because ESBMC's
 *     std::basic_streambuf has no get or put area -- see streambuf_model.h.
 *  2. The five functions are public. The native legs reach them the way an
 *     application does, through std::iostream; the ESBMC leg states properties
 *     about them directly, and protected access would only add a subclass
 *     between the property and the code it is about.
 *  3. The constructors take the buffer and the pointer offsets, rather than
 *     allocating and filling one. What they install is the state the pristine
 *     constructors leave behind -- SimpleStreamBuf.cpp:38-53 for the string
 *     constructor, and PreallocatedStreamBuf's own, sliced -- so the arithmetic
 *     under test starts from the same place it does in a real process.
 */

#ifndef VERIFICATION_STREAMBUF_SCAFFOLD_H
#define VERIFICATION_STREAMBUF_SCAFFOLD_H

#include "streambuf_model.h"

#include <cstddef>
#include <cstdint>

namespace Aws
{
namespace Utils
{
namespace Stream
{
class SimpleStreamBuf : public verification::StreamBufBase
{
public:
  /* The state SimpleStreamBuf(const Aws::String&) leaves behind for a payload of
   * `dataLength` bytes in a buffer of `bufferSize`: the put pointer at the end of
   * the payload, the get area still empty (SimpleStreamBuf.cpp:52-53). */
  SimpleStreamBuf(char *buffer, size_t bufferSize, long dataLength)
    : m_buffer(buffer), m_bufferSize(bufferSize)
  {
    setp(buffer + dataLength, buffer + bufferSize);
    setg(buffer, buffer, buffer);
  }

  /* An arbitrary but well-formed get and put area, for properties about what
   * underflow() does to one it is handed. */
  void InstallAreas(long getPos, long getEnd, long putPos)
  {
    setg(m_buffer, m_buffer + getPos, m_buffer + getEnd);
    setp(m_buffer + putPos, m_buffer + m_bufferSize);
  }

  std::streampos seekoff(
    std::streamoff off,
    std::ios_base::seekdir dir,
    std::ios_base::openmode which = std::ios_base::in | std::ios_base::out);
  std::streampos
  seekpos(std::streampos pos, std::ios_base::openmode which = std::ios_base::in | std::ios_base::out);
  int underflow();

private:
  char *m_buffer;
  size_t m_bufferSize;
};

class PreallocatedStreamBuf : public verification::StreamBufBase
{
public:
  PreallocatedStreamBuf(unsigned char *buffer, uint64_t lengthToRead);

  pos_type seekoff(
    off_type off,
    std::ios_base::seekdir dir,
    std::ios_base::openmode which = std::ios_base::in | std::ios_base::out);
  pos_type
  seekpos(pos_type pos, std::ios_base::openmode which = std::ios_base::in | std::ios_base::out);

private:
  unsigned char *m_underlyingBuffer;
  const uint64_t m_lengthToRead;
};
} // namespace Stream
} // namespace Utils
} // namespace Aws

#endif
