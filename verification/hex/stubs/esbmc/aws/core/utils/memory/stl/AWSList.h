/**
 * ESBMC-only shim for aws/core/utils/memory/stl/AWSList.h.
 *
 * Upstream spells the alias std::list<T, Aws::Allocator<T>> (AWSList.h:17).
 * ESBMC 8.4.0's operational model declares list with a single template
 * parameter and no allocator (src/cpp/library/list:53), so the upstream
 * spelling is "too many template arguments for class template 'list'" and
 * HashingUtils.cpp will not parse.
 *
 * HexDecode does not use a list; Aws::List appears only in the SHA-256 tree
 * hash (HashingUtils.cpp:80,116,130), which no harness calls. Dropping the
 * allocator argument keeps that code parseable without changing anything the
 * harnesses reach. ESBMC include path only (-Istubs/esbmc).
 */
#pragma once

#include <aws/core/utils/memory/stl/AWSAllocator.h>

#include <list>

namespace Aws
{

template <typename T> using List = std::list<T>;

} // namespace Aws
