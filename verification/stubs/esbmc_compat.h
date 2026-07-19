/**
 * ESBMC C++ operational-model compatibility shim.
 *
 * Force-included (-include esbmc_compat.h) ahead of all AWS SDK sources so the
 * SDK itself stays byte-for-byte verbatim -- no #ifdefs, no edited headers, no
 * stubbed-out Array.h. Everything the harnesses verify is real upstream code.
 *
 * Gaps in ESBMC's C++ OM that block aws-cpp-sdk-core:
 *
 *  (1) std::is_class / std::is_polymorphic / std::is_trivially_* were missing
 *      from src/cpp/library/type_traits. AWSMemory.h dispatches on all three
 *      (lines 100, 112, 132, 307, 315).
 *      FIXED UPSTREAM by esbmc/esbmc#6190, which closed esbmc/esbmc#6183. The
 *      shim below now *conflicts* with the OM (redefinition errors), so
 *      -D ESBMC_OM_MISSING_TRAITS must NOT be passed to a current ESBMC. It is
 *      kept only for reproducing against 8.4.0-era builds.
 *
 *  (2) MemorySystemInterface.h says `std::size_t` while including only
 *      <cstdlib>. libstdc++ leaks std::size_t through <cstdlib>; ESBMC's OM
 *      <cstdlib> does not. Pulling <cstddef> first (which ESBMC's OM *does*
 *      define std::size_t in) closes it.
 *
 *  (3) std::shared_ptr / std::allocate_shared are still absent from the OM.
 *      STILL OPEN -- this is the one part of the shim that remains load-bearing,
 *      which is why it sits outside the guard for (1).
 *
 * Reported upstream: see verification/esbmc_bug_repros/.
 */

#pragma once

/* Gap (2): make std::size_t visible before any AWS header is parsed. */
#include <cstddef>

/* Gap (1): supply the three missing traits on top of the clang builtins that
 * ESBMC's frontend already understands.
 *
 * Obsolete against ESBMC >= #6190, which added these to the OM: enabling this
 * block now produces "redefinition of 'is_class'" and friends. The Makefile no
 * longer passes -D ESBMC_OM_MISSING_TRAITS; it is retained only so the tree can
 * still be pointed at an 8.4.0-era build. Under g++/libstdc++ -- used for the
 * ASan cross-check and by clangd -- it must likewise stay dark. */
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

#endif // ESBMC_OM_MISSING_TRAITS

/* Gap (3): ESBMC's C++ OM has no std::shared_ptr at all (grep the whole
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
