/**
 * ESBMC reproducer: std::allocate_shared is absent from the C++ operational
 * model, and its absence is a PARSE error rather than a link error.
 *
 * esbmc/esbmc#6403 ("[om] Model shared_ptr, weak_ptr and make_shared") added a
 * real reference-counted shared_ptr to src/cpp/library/memory, closing the
 * larger half of the gap this repo hit as esbmc/esbmc#6183. It did not add
 * allocate_shared:
 *
 *   $ esbmc --std c++11 esbmc_bug_repros/om_allocate_shared.cpp
 *   error: no member named 'allocate_shared' in namespace 'std'
 *   error: 'T' does not refer to a value
 *   ERROR: PARSING ERROR
 *
 * The second diagnostic is the important one. With no declaration in scope the
 * name is not a template, so clang parses the `<` as less-than and the
 * template argument T as a value. That happens during PARSING of the template
 * definition -- before any instantiation -- so naming allocate_shared in an
 * UNINSTANTIATED function template is enough to fail the whole translation
 * unit. A declaration alone fixes it; no semantics are required to unblock
 * code that never calls it.
 *
 * That is exactly how aws-cpp-sdk-core is blocked. Aws::MakeShared
 * (include/aws/core/utils/memory/stl/AWSAllocator.h:105-118) is a function
 * template no Base64 harness ever instantiates, whose body reads:
 *
 *     return std::allocate_shared<T, Aws::Allocator<T>>(
 *              Aws::Allocator<T>(), std::forward<ArgTypes>(args)...);
 *
 * Merely including the header therefore stops the run. This repo works around
 * it with a declaration-only shim (stubs/esbmc_compat.h, behind
 * -D ESBMC_OM_MISSING_ALLOCATE_SHARED) -- deliberately with NO definition, so
 * that code which genuinely reaches allocate_shared fails at link time instead
 * of verifying against an allocator-blind substitute.
 *
 * g++ -std=c++11 -fsyntax-only accepts this file.
 *
 * Suggested fix, in rough order of cost:
 *   1. Declare allocate_shared in src/cpp/library/memory. Unblocks every
 *      translation unit that merely mentions it, which is the common case.
 *   2. Define it in terms of the existing make_shared, accepting that the
 *      allocator argument is ignored. Sound only if the OM's shared_ptr is the
 *      one doing the releasing; worth a comment saying the allocator is not
 *      modelled.
 *   3. Model allocator-aware allocation properly, so that a custom Allocator's
 *      allocate/deallocate are actually called. Needed before anyone can verify
 *      a claim ABOUT the allocator, as opposed to code that merely uses one.
 */
#include <memory>

/* Never instantiated -- naming allocate_shared is enough to fail parsing.
 * This is the shape of Aws::MakeShared. */
template <typename T>
std::shared_ptr<T> MakeShared(const std::allocator<T> &alloc)
{
  return std::allocate_shared<T, std::allocator<T>>(alloc);
}

int main()
{
  return 0;
}
