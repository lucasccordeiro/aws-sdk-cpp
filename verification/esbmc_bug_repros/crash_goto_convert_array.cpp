/**
 * ESBMC reproducer: SIGABRT during GOTO conversion.
 *
 * Constructing a single Aws::Utils::Array<unsigned char> (aws-sdk-cpp's
 * ByteBuffer) aborts ESBMC while it prints "Converting". The abort message
 * varies run to run over this same deterministic, single-threaded input:
 *
 *   Fatal glibc error: pthread_mutex_lock.c:450 ... assertion failed: e != ESRCH || !robust
 *   The futex facility returned an unexpected error code.
 *   terminate called after throwing an instance of 'std::system_error'  what(): Invalid argument
 *   Fatal glibc error: tpp.c:83 (__pthread_tpp_change_priority): assertion failed: ...
 *
 * Run from the verification/ directory of
 * https://github.com/lucasccordeiro/aws-sdk-cpp :
 *
 *   $ ./scripts/make_model_headers.sh
 *   $ esbmc --std c++11 -D ESBMC_OM_MISSING_TRAITS -Istubs -Imodel/include \
 *       esbmc_bug_repros/crash_goto_convert_array.cpp \
 *       --unwind 4 --no-unwinding-assertions
 *   ... Converting
 *   <one of the aborts above>, exit 134
 *
 * Requires the local OM patches for unique_ptr(nullptr_t) and
 * basic_string::{operator[] const, push_back, reserve}; without them this stops
 * at a parse error before reaching the crash.
 *
 * Raising the stack (ulimit -s unlimited) turns the abort into a hang with zero
 * CPU time rather than fixing it. Not resource exhaustion: 177 GB free, 797 of
 * 1.49M threads used, peak RSS ~100 MB, no --memlimit/--enable-keep-alive.
 *
 * ESBMC version 8.4.0 64-bit x86_64 linux
 */
#include "esbmc_compat.h"
#include <aws/core/utils/Array.h>
namespace Aws {
void* Malloc(const char*, size_t n) { return malloc(n); }
void Free(void* p) { free(p); }
}
int main(){ Aws::Utils::ByteBuffer b(3); b[0]=1; return b[0]; }
