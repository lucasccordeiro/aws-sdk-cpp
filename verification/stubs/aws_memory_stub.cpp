/**
 * Verification-only substitute for the allocator plumbing in
 * source/utils/memory/AWSMemory.cpp.
 *
 * Why not vendor the real TU: AWSMemory.cpp lines 176-206 define CRT hooks
 * (MemAcquire/MemRelease over aws_allocator) that pull in the aws-crt-cpp
 * submodule we deliberately excluded. Those hooks are unreachable from the
 * codecs.
 *
 * Fidelity: upstream Malloc/Free (AWSMemory.cpp:130-174) consult
 * GetMemorySystem() and fall through to plain malloc/free when no custom
 * memory system is installed. No memory system is installed unless the client
 * calls Aws::InitAPI with a MemoryManagementOptions override, so the
 * malloc/free path below IS the default-configuration behaviour -- this is the
 * branch a stock SDK build takes.
 *
 * Using raw malloc/free is also what makes the ASan cross-check meaningful:
 * ByteBuffer's backing store gets real allocator redzones, so an out-of-bounds
 * write past it is detectable at runtime rather than landing inside a
 * pool-allocated slab.
 */

#include "esbmc_compat.h"

#include <cstdlib>

#include <aws/core/utils/memory/MemorySystemInterface.h>

namespace Aws
{
namespace Utils
{
namespace Memory
{
/* Upstream keeps this in a file-scope pointer set by InitializeAWSMemorySystem.
 * We model the uninitialised (default) state: no custom memory system. */
MemorySystemInterface *GetMemorySystem()
{
  return nullptr;
}
} // namespace Memory
} // namespace Utils

void *Malloc(const char * /*allocationTag*/, size_t allocationSize)
{
  return malloc(allocationSize);
}

void Free(void *memoryPtr)
{
  if (memoryPtr == nullptr)
  {
    return;
  }
  free(memoryPtr);
}
} // namespace Aws
