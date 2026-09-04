/**
 * Verification-only substitute for the CMake-generated aws/core/SDKConfig.h.
 *
 * Upstream generates this from SDKConfig.h.in via `#cmakedefine
 * USE_AWS_MEMORY_MANAGEMENT`. We leave the macro undefined, which selects the
 * plain-std::allocator code path in AWSAllocator.h. That keeps Aws::String a
 * std::basic_string with the default allocator and avoids pulling the SDK
 * custom memory system (and the CRT) into the model.
 */

#pragma once

/* #undef USE_AWS_MEMORY_MANAGEMENT */
