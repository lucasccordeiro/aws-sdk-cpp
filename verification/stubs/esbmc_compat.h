/**
 * ESBMC C++ operational-model compatibility shim.
 *
 * Force-included (-include esbmc_compat.h) ahead of all AWS SDK sources so the
 * SDK itself stays byte-for-byte verbatim -- no #ifdefs, no edited headers, no
 * stubbed-out Array.h. Everything the harnesses verify is real upstream code.
 *
 * Two independent gaps in ESBMC 8.4.0's C++ OM block aws-cpp-sdk-core:
 *
 *  (1) src/cpp/library/type_traits lacks std::is_class, std::is_polymorphic and
 *      std::is_trivially_default_constructible. AWSMemory.h dispatches on all
 *      three (lines 100, 112, 132, 307, 315). ESBMC's clang frontend *does*
 *      accept the corresponding __is_class / __is_polymorphic /
 *      __is_trivially_constructible builtins, so the traits are recoverable
 *      here and the upstream fix is a handful of lines in that OM header.
 *
 *  (2) MemorySystemInterface.h says `std::size_t` while including only
 *      <cstdlib>. libstdc++ leaks std::size_t through <cstdlib>; ESBMC's OM
 *      <cstdlib> does not. Pulling <cstddef> first (which ESBMC's OM *does*
 *      define std::size_t in) closes it.
 *
 * Reported upstream: see verification/esbmc_bug_repros/.
 */

#pragma once

/* Gap (2): make std::size_t visible before any AWS header is parsed. */
#include <cstddef>

/* Gap (1): supply the three missing traits on top of the clang builtins that
 * ESBMC's frontend already understands.
 *
 * ESBMC 8.4.0 predefines no identifying macro (neither __ESBMC__ nor __ESBMC),
 * so the Makefile passes -D ESBMC_OM_MISSING_TRAITS on the ESBMC command line
 * only. Under g++/libstdc++ -- used for the ASan cross-check and by clangd --
 * these traits already exist and redefining them is an error, so the block
 * below must stay dark there. Drop the -D once ESBMC's OM grows the traits;
 * nothing else in the tree changes. */
#ifdef ESBMC_OM_MISSING_TRAITS

#include <type_traits>

namespace std
{
template <typename T>
struct is_class : public integral_constant<bool, __is_class(T)>
{
};

template <typename T>
struct is_polymorphic : public integral_constant<bool, __is_polymorphic(T)>
{
};

template <typename T>
struct is_trivially_default_constructible
  : public integral_constant<bool, __is_trivially_constructible(T)>
{
};

template <typename T>
struct is_trivially_destructible
  : public integral_constant<bool, __is_trivially_destructible(T)>
{
};
} // namespace std

/* Gap (3): ESBMC 8.4.0's C++ OM has no std::shared_ptr at all (grep the whole
 * of src/cpp/library -- the only hit is a boost config header). AWSAllocator.h
 * names std::shared_ptr<T> as the return type of the Aws::MakeShared function
 * template and calls std::allocate_shared in its body.
 *
 * SCOPE OF THIS MODEL -- read before reusing:
 * MakeShared is a *function template* that no codec harness ever instantiates,
 * but the non-dependent name `std::shared_ptr` must still resolve when the
 * template is parsed. So the names have to exist; the semantics do not.
 *
 * allocate_shared is therefore left as a pure declaration with NO definition.
 * That is deliberate: if a future harness ever does reach shared_ptr, it fails
 * loudly at link time instead of silently verifying against a fake ownership
 * model with no reference counting. Do not "helpfully" give it a body -- write
 * a real model in ESBMC's OM instead.
 */
namespace std
{
template <typename T>
class shared_ptr
{
  T *ptr;

public:
  shared_ptr() : ptr(nullptr)
  {
  }
  explicit shared_ptr(T *p) : ptr(p)
  {
  }
  T *get() const
  {
    return ptr;
  }
  T &operator*() const
  {
    return *ptr;
  }
  T *operator->() const
  {
    return ptr;
  }
  explicit operator bool() const
  {
    return ptr != nullptr;
  }
};

template <typename T, typename Alloc, typename... Args>
shared_ptr<T> allocate_shared(const Alloc &, Args &&...); /* no definition */
} // namespace std

#endif // ESBMC_OM_MISSING_TRAITS
