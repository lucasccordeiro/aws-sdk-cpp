/**
 * ESBMC-only shim for aws/core/utils/memory/stl/AWSStreamFwd.h.
 *
 * The upstream header spells its six stream typedefs as basic_* templates
 * (AWSStreamFwd.h:17-22). ESBMC 8.4.0's C++ operational model defines the
 * template aliases std::basic_istream and std::basic_ostream -- added for
 * esbmc/esbmc#6063 -- but not basic_ifstream, basic_ofstream, basic_fstream or
 * basic_iostream, although it does define the ifstream/ofstream/fstream/
 * iostream classes those aliases would name (src/cpp/library/fstream:60,93,124;
 * iostream:12). The four missing aliases are a parse error, so HashingUtils.h
 * cannot be read at all without this file.
 *
 * The typedefs below therefore name the OM's classes directly. Nothing in the
 * hex harnesses touches a stream: HexDecode takes an Aws::String. This is on
 * the ESBMC include path only (-Istubs/esbmc), so the native builds still
 * compile the pristine header.
 */
#pragma once

#include <aws/core/Core_EXPORTS.h>

#include <functional>
#include <fstream>
#include <iostream>

namespace Aws
{

typedef std::ifstream IFStream;
typedef std::ofstream OFStream;
typedef std::fstream FStream;
typedef std::istream IStream;
typedef std::ostream OStream;
typedef std::iostream IOStream;
typedef std::istreambuf_iterator<char, std::char_traits<char> > IStreamBufIterator;

using IOStreamFactory = std::function<Aws::IOStream *(void)>;

} // namespace Aws
