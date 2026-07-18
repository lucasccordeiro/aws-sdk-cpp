# Plan: fixing esbmc/esbmc#6183 and #6184

Two issues were filed against ESBMC while trying to verify `Base64::Decode`
(see [REPORT.md](REPORT.md)). This is the plan to close them.

They are **not** equally understood. #6183 is a known-scope, mechanical fix
that is already half-written. #6184 is a memory-corruption bug in ESBMC's core
data structure whose *symptom* is now diagnosed but whose *cause* is not yet
located. Plan accordingly: #6183 can be finished and merged; #6184 needs an
investigation phase before anyone can estimate the fix.

Sequencing matters: **#6183 must land first.** Without its patches ESBMC stops
at a parse error before reaching #6184's crash, so #6184 is not even
reproducible on a stock build.

---

## Issue #6183 — C++ operational-model gaps

**Status:** diagnosed, patch written for the hard half.

Eight gaps, in three tiers by difficulty.

### Tier 1 — already patched (branch `fix/cpp-om-unique-ptr-nullptr-assign`)

`src/cpp/library/{memory,string}`, +75 lines, no deletions:

| Addition | Standard reference |
|---|---|
| `unique_ptr::operator=(nullptr_t)` (both primary and `T[]` specialisation) | [unique.ptr.single.asgn] p5 |
| `unique_ptr(nullptr_t)` — non-explicit (both specialisations) | [unique.ptr.single.ctor] p1 |
| `basic_string::operator[](size_t) const` | [string.access] p1 |
| `basic_string::push_back` | [string.modifiers] |
| `basic_string::reserve` | [string.capacity] |

These cannot be shimmed externally — they are members of operational-model
types — which is why they were done first.

**Remaining work:** open as a PR, add regression tests under
`regression/esbmc-cpp/`, one per added member (a handful of lines each,
asserting the standard-mandated behaviour rather than merely compiling).

### Tier 2 — trivial, not yet written

Add to `src/cpp/library/type_traits`, each a one-liner over a clang builtin
that ESBMC's frontend **already accepts** (verified):

```cpp
template <typename T> struct is_class
  : public integral_constant<bool, __is_class(T)> {};
template <typename T> struct is_polymorphic
  : public integral_constant<bool, __is_polymorphic(T)> {};
template <typename T> struct is_trivially_default_constructible
  : public integral_constant<bool, __is_trivially_constructible(T)> {};
template <typename T> struct is_trivially_destructible
  : public integral_constant<bool, __is_trivially_destructible(T)> {};
```

Plus: make `<cstdlib>` pull in `std::size_t` (it is already defined in the OM's
`<cstddef>`; only the transitive include is missing).

Once Tier 2 lands, `stubs/esbmc_compat.h` in this repo shrinks to almost
nothing — a good end-to-end check that the fix is real.

### Tier 3 — `std::shared_ptr`, absent entirely

Genuinely larger, and **should be its own issue and its own PR**. A correct
model needs reference counting, aliasing constructors, `weak_ptr` and
`enable_shared_from_this`. Deliberately out of scope here.

Interim mitigation worth doing regardless: naming `std::shared_ptr` in an
*uninstantiated* function template is enough to fail parsing, so even a
declaration-only `shared_ptr` in the OM would unblock a large class of real
code. Propose that as the first step, clearly marked as parse-support only.

### Also worth fixing while in there

Found during this work, not blocking, no reproducer attached:

- `basic_string::size()` returns `int`, not `size_type`. Wrong for any string
  longer than `INT_MAX` and wrong in template deduction.
- **OM `unique_ptr`'s destructor is `#if 0`-ed out** with
  `// TODO: fix remove goto sideeffect`, so the model never releases. This
  silently invalidates `--memory-leak-check` on any C++ target using
  `unique_ptr` — a clean leak verdict currently means nothing there. Until it
  is fixed, ESBMC should **warn** when `--memory-leak-check` is combined with
  C++ input, rather than reporting a misleading pass.
- `basic_string::operator[]` asserts `pos < _size`, but `s[s.size()]` is
  well-defined since C++11 and returns the null character. Fixing this changes
  behaviour under existing tests, so it needs its own check.

---

## Issue #6184 — SIGABRT during GOTO conversion

**Status:** symptom diagnosed precisely; root cause NOT yet located.

### What is now known

Under gdb the abort resolves to a single point:

```
#9  irept::detatch (this=0xa2fc828) at src/util/irep.cpp:48
48    old_data->dt_mutex.lock();
```

reached from `clang_c_adjust::adjust_comma` → `adjust_operands`
(`clang_c_adjust_expr.cpp:1589`).

Inspecting the object being locked:

```
(gdb) p *data
$2 = {ref_count = 0,
      dt_mutex = {... __lock = -2147483487, __owner = 157060624,
                  __kind = 170985904 ...},
      named_sub = {... _M_color = (unknown: 0xa302e70) ...},
      sub = {... _M_start = 0x0, _M_finish = 0xa0, _M_end_of_storage = 0x40}}
```

This is **freed memory that has been recycled**: `ref_count` is already 0,
`__kind` is not a valid mutex kind, and an `_M_color` enum holds a pointer.
`detatch()` is locking a mutex inside a destroyed `dt`.

Two hypotheses are now **ruled out**:

- **Not a data race.** `info threads` shows exactly one thread at the abort.
  The varying glibc messages come from garbage in the mutex — the bogus
  `__kind` sends glibc down the priority-inheritance path
  (`__futex_lock_pi64`), which is why the symptom shifts between
  `pthread_mutex_lock` assertions, futex errors and `std::system_error`.
- **Not stack exhaustion.** The full backtrace is 44 frames. The earlier
  observation that `ulimit -s unlimited` changed the symptom was a red herring
  — it perturbs allocation layout, so the freed block gets recycled
  differently; it does not fix anything.

So: **use-after-free of `irept::dt` under `SHARING`.** `SHARING` is
unconditionally enabled at `irep.h:11` with no build toggle.

### What is not known

Where the reference count is unbalanced. `detatch()` found a `dt` with
`ref_count == 0` still reachable from a live `irept`, so some path either
dropped a reference it did not own or failed to take one it did.

### Phase 1 — locate the free site (blocking; do this first)

Nothing can be designed until we know who freed the block.

1. Build ESBMC with ASan and frame pointers:
   `-DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer"`.
2. Run the reproducer
   (`verification/esbmc_bug_repros/crash_goto_convert_array.cpp`). ASan's
   heap-use-after-free report gives both the **free site** and the
   **allocation site** — which is exactly the missing information.
3. If ASan's quarantine masks it, cross-check with valgrind (not installed on
   the current box; `apt install valgrind`).

Expected output of this phase: the specific `remove_ref` / destructor call that
drops the last reference while an `irept` still points at the block.

### Phase 2 — reduce

With the free site known, retry the reduction that failed before. Earlier
hand-written approximations (custom-deleter `unique_ptr`, `cond ? mk() :
nullptr`, virtual dtor, derived non-template class) all verified fine, so the
trigger is more specific than any of those. Knowing which irep the corrupted
`dt` belongs to should make a targeted reduction tractable, and a
`creduce`-based reduction becomes viable once the interestingness test can key
on the ASan report rather than on a flaky abort message.

Deliverable: a self-contained `.cpp` with no AWS headers, for the ESBMC
regression suite.

### Phase 3 — fix

Cannot be specified until Phase 1 lands. Two candidate shapes, to be confirmed
or discarded by evidence, **not** to be implemented speculatively:

- **A missing reference acquisition** on some `irept` copy/move path, or a
  double `remove_ref` on an error path in `clang_c_adjust`. If so the fix is
  local and small.
- **A structural problem with the sharing scheme itself.** Note two latent
  defects visible by inspection today, independent of this crash:
  - `remove_ref` (`irep.cpp:82-95`) releases `old_data->dt_mutex` and *then*
    `delete old_data` — destroying the very mutex it just unlocked. Safe only
    while single-threaded.
  - `ref_count` is a plain `unsigned` guarded by a per-object mutex, and
    `detatch()` unlocks before calling `remove_ref`, which re-locks. The
    check-then-act across that gap is not atomic.

  Both are real bugs waiting for the day ESBMC parallelises this code, and are
  worth fixing on their own merits — but neither explains a single-threaded
  use-after-free, so fixing them **must not** be mistaken for fixing #6184.

### Phase 4 — verify

- The Phase 2 reduction goes into `regression/esbmc-cpp/` as a durable test.
- Re-run the harnesses in this repo (`make smoke`, then `make esbmc`) against
  the fixed build. `make smoke` going green is the real acceptance criterion:
  it means ESBMC can convert and symex `Aws::Utils::Array<unsigned char>`.
- Drop `scripts/make_model_headers.sh`'s `CryptoBuffer` transformation and
  confirm the unmodified upstream `Array.h` converts. That removes the last
  deviation between `vendor/` and `model/`.
- Run the full ESBMC regression suite; `irept` is core, so the blast radius of
  any change there is the whole tool.

---

## Order of work

1. **#6183 Tier 1** — open the PR, add regression tests. Unblocks everything.
2. **#6183 Tier 2** — the four traits plus `std::size_t`. Small, independent.
3. **#6184 Phase 1** — ASan build. This is the long pole; start it early since
   it is a full rebuild and is independent of the #6183 work.
4. **#6184 Phases 2-4** — scope only after Phase 1 reports.
5. **#6183 Tier 3** (`shared_ptr`) — separate issue, separate PR, no dependency
   on the above.

## Honest assessment

Items 1, 2 and 5 are ordinary library work with predictable effort. Item 3-4 is
a memory-corruption bug in the data structure the entire tool is built on; the
diagnosis above narrows it a great deal, but anyone estimating the fix before
the ASan run has the free site is guessing. The gate is deliberate: no patch to
`irept` should be written against a hypothesis.
