/**
 * Verification-only substitute for the allocator plumbing in
 * source/utils/memory/AWSMemory.cpp, modelling the default (no custom memory
 * system) configuration a stock SDK build runs with -- Malloc/Free fall through
 * to plain malloc/free (AWSMemory.cpp:130-174 when GetMemorySystem() is null).
 *
 * Raw malloc/free is also what makes the ASan cross-check meaningful: any
 * heap-allocated UUID object gets real allocator redzones, so the constructor's
 * overflowing memcpy past m_uuid[16] is caught at runtime.
 */

#include "../../stubs/esbmc_compat.h"

#include <cstdlib>

#include <aws/core/utils/memory/MemorySystemInterface.h>

namespace Aws
{
namespace Utils
{
namespace Memory
{
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
