/**
 * ESBMC C++ operational-model compatibility shim.
 *
 * Force-included (-include esbmc_compat.h) ahead of all AWS SDK sources so the
 * SDK itself stays byte-for-byte verbatim -- no #ifdefs, no edited headers, no
 * stubbed-out Array.h. Everything the harnesses verify is real upstream code.
 *
 * ONE gap in ESBMC's C++ OM still blocks aws-cpp-sdk-core: std::shared_ptr.
 *
 * The traits (std::is_class, std::is_polymorphic,
 * std::is_trivially_default_constructible, std::is_trivially_destructible) and
 * std::size_t-via-<cstdlib> were fixed upstream by esbmc/esbmc#6190, which
 * closed esbmc/esbmc#6183. Shimming them here is now a *redefinition error*
 * against the OM, so those blocks are gone rather than merely disabled.
 *
 * Reported upstream: see verification/esbmc_bug_repros/.
 */

#pragma once

/* ESBMC 8.4.0 predefines no identifying macro (neither __ESBMC__ nor __ESBMC),
 * so the Makefile passes -D ESBMC_OM_MISSING_SHARED_PTR on the ESBMC command
 * line only. Under g++/libstdc++ -- used for the ASan cross-check and by
 * clangd -- std::shared_ptr already exists and redefining it is an error, so
 * the block below must stay dark there. Drop the -D once ESBMC's OM grows a
 * real shared_ptr; nothing else in the tree changes. */
#ifdef ESBMC_OM_MISSING_SHARED_PTR

/* ESBMC's OM has no std::shared_ptr at all (grep the whole of src/cpp/library
 * -- the only hit is a boost config header). AWSAllocator.h names
 * std::shared_ptr<T> as the return type of the Aws::MakeShared function
 * template and calls std::allocate_shared in its body.
 *
 * esbmc/esbmc#6190 left this out deliberately: reference counting, aliasing
 * constructors, weak_ptr and enable_shared_from_this need a real model, not a
 * header addition.
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

#endif // ESBMC_OM_MISSING_SHARED_PTR
