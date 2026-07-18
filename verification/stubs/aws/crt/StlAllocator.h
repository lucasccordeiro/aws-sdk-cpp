/**
 * Verification-only stub for <aws/crt/StlAllocator.h>.
 *
 * The real header lives in the aws-crt-cpp submodule (crt/aws-crt-cpp), which
 * we deliberately do not check out: it drags in the whole C99 CRT stack and is
 * irrelevant to the codec logic under analysis.
 *
 * AWSAllocator.h includes this header unconditionally, but only *references*
 * Aws::Crt::StlAllocator inside `#ifdef USE_AWS_MEMORY_MANAGEMENT`. We build
 * with that macro undefined (see stubs/aws/core/SDKConfig.h), so an empty
 * declaration is enough to satisfy the include and nothing more.
 */

#pragma once

#include <memory>

namespace Aws
{
    namespace Crt
    {
        template <typename T> using StlAllocator = std::allocator<T>;
    }
}
