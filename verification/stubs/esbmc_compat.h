/**
 * ESBMC C++ operational-model compatibility shim.
 *
 * Force-included (-include esbmc_compat.h) ahead of all AWS SDK sources so the
 * SDK itself stays byte-for-byte verbatim -- no #ifdefs, no edited headers, no
 * stubbed-out Array.h. Everything the harnesses verify is real upstream code.
 *
 * ONE gap in ESBMC's C++ OM still blocks aws-cpp-sdk-core: std::allocate_shared.
 *
 * Everything else this file used to carry has been fixed upstream and removed
 * rather than merely disabled, because shimming a member the OM now defines is
 * a *redefinition error*:
 *
 *   - the traits (std::is_class, std::is_polymorphic,
 *     std::is_trivially_default_constructible, std::is_trivially_destructible)
 *     and std::size_t-via-<cstdlib>, by esbmc/esbmc#6190 (closed #6183);
 *   - std::shared_ptr itself, by esbmc/esbmc#6403 ("[om] Model shared_ptr,
 *     weak_ptr and make_shared"). The OM's shared_ptr is a real model with
 *     reference counting, so the hand-written one that used to live here is
 *     both unnecessary and now a hard error.
 *
 * Reported upstream: see verification/esbmc_bug_repros/.
 */

#pragma once

/* ESBMC 8.4.0 predefines no identifying macro (neither __ESBMC__ nor __ESBMC),
 * so the Makefile passes -D ESBMC_OM_MISSING_ALLOCATE_SHARED on the ESBMC
 * command line only. Under g++/libstdc++ -- used for the ASan cross-check and
 * by clangd -- std::allocate_shared already exists and redeclaring it this way
 * is an error, so the block below must stay dark there. Drop the -D once
 * ESBMC's OM grows allocate_shared; nothing else in the tree changes. */
#ifdef ESBMC_OM_MISSING_ALLOCATE_SHARED

/* The declaration below names std::shared_ptr as its return type, and this
 * header is force-included ahead of everything, so pull in the OM's <memory>
 * first rather than relying on the SDK to have done it already. */
#  include <memory>

/* esbmc/esbmc#6403 modelled shared_ptr, weak_ptr and make_shared, but not
 * allocate_shared -- and allocate_shared is the one AWSAllocator.h:117 calls:
 *
 *     return std::allocate_shared<T, Aws::Allocator<T>>(
 *              Aws::Allocator<T>(), std::forward<ArgTypes>(args)...);
 *
 * Without a declaration the name is not a template, so clang reads the `<` as
 * less-than and reports "'T' does not refer to a value" -- a parse error, not a
 * link error, which is why an uninstantiated function template is enough to
 * block the whole translation unit.
 *
 * SCOPE OF THIS MODEL -- read before reusing:
 * MakeShared is a *function template* that no codec harness ever instantiates,
 * but the non-dependent name std::allocate_shared must still resolve when the
 * template is parsed. So the name has to exist; the semantics do not.
 *
 * It is therefore left as a pure declaration with NO definition. That is
 * deliberate: if a future harness ever does reach allocate_shared, it fails
 * loudly at link time instead of silently verifying against an allocator-blind
 * substitute. Do not "helpfully" give it a body -- forwarding to the OM's
 * make_shared would drop the allocator argument, which is precisely the part
 * this repo would be claiming to have verified. Add it to ESBMC's OM instead.
 */
namespace std
{
template <typename T, typename Alloc, typename... Args>
shared_ptr<T> allocate_shared(const Alloc &, Args &&...); /* no definition */
} // namespace std

#endif // ESBMC_OM_MISSING_ALLOCATE_SHARED
