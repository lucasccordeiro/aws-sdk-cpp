/**
 * Verification-only stand-in for the part of std::basic_streambuf the code under
 * test actually uses: the get and put areas. Reached only by the ESBMC leg --
 * the native legs derive from the real <streambuf> and never see this file.
 *
 * Why it exists. ESBMC's operational model declares the ten area members
 * without defining any of them (src/cpp/library/streambuf:83-96), so a derived
 * buffer's setg/setp calls have nothing to write to and gptr()/egptr() come back
 * unconstrained: `gptr() <= egptr()` is already violable on a freshly
 * constructed buffer, and every property below would hold or fail for reasons
 * that have nothing to do with the SDK. The model also declares streampos and
 * streamoff only as members of class ios (src/cpp/library/ios:162-163), and as
 * int rather than the 64-bit type the SDK's signatures are written against.
 *
 * What it promises. The bodies below are the postconditions the standard states
 * for these members -- [streambuf.get.area]/5-6 for setg, [streambuf.put.area]/3
 * for setp -- and nothing else. They deliberately do not enforce setg's
 * precondition: whether the SDK's code can break it is the question the
 * GET_AREA mode asks, and a stand-in that asserted it would answer that question
 * by construction instead of measuring it.
 */

#ifndef VERIFICATION_STREAMBUF_MODEL_H
#define VERIFICATION_STREAMBUF_MODEL_H

#include <ios>
#include <streambuf>

#ifdef ESBMC_OM_MISSING_STREAMPOS
namespace std
{
typedef long long streamoff;
typedef long long streampos;
} // namespace std
#endif

namespace verification
{
class StreamBufBase
{
public:
  typedef char char_type;
  typedef int int_type;
  typedef long long off_type;
  typedef long long pos_type;

  StreamBufBase() : m_eback(0), m_gptr(0), m_egptr(0), m_pbase(0), m_pptr(0), m_epptr(0) {}
  virtual ~StreamBufBase() {}

  char *eback() const { return m_eback; }
  char *gptr() const { return m_gptr; }
  char *egptr() const { return m_egptr; }
  char *pbase() const { return m_pbase; }
  char *pptr() const { return m_pptr; }
  char *epptr() const { return m_epptr; }

  void setg(char *gbeg, char *gnext, char *gend)
  {
    m_eback = gbeg;
    m_gptr = gnext;
    m_egptr = gend;
  }

  void setp(char *pbeg, char *pend)
  {
    m_pbase = pbeg;
    m_pptr = pbeg;
    m_epptr = pend;
  }

  void gbump(int n) { m_gptr += n; }
  void pbump(int n) { m_pptr += n; }

private:
  char *m_eback;
  char *m_gptr;
  char *m_egptr;
  char *m_pbase;
  char *m_pptr;
  char *m_epptr;
};
} // namespace verification

#endif
