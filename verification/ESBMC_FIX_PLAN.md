# Plan: fixing esbmc/esbmc#6183 and #6184

Two issues were filed against ESBMC while trying to verify `Base64::Decode`
(see [REPORT.md](REPORT.md)). This is the plan to close them.

**Status as of 2026-07-19:**

| Issue | State | What is left |
|---|---|---|
| [#6183](https://github.com/esbmc/esbmc/issues/6183) | **CLOSED** by [PR #6190](https://github.com/esbmc/esbmc/pull/6190), merged | `shared_ptr` only, deliberately deferred — needs its own issue |
| [#6184](https://github.com/esbmc/esbmc/issues/6184) | **CLOSED** by [PR #6195](https://github.com/esbmc/esbmc/pull/6195), merged | — |
| [#6199](https://github.com/esbmc/esbmc/issues/6199) | **OPEN** — filed 2026-07-19 | Land it, then revert the harness workarounds |

Two framings in earlier revisions of this document are **superseded**:

- "#6184's cause is not located, gate all work behind an ASan run." The cause
  is known and is not what the gdb session suggested. See "Correction" below.
- "`make smoke` going green is the real acceptance criterion." It went green,
  and it was necessary but not sufficient — the harnesses then hit a *third*
  OM defect one layer up.

**Where this actually stands:** the crash is fixed, `make smoke` is green,
`make esbmc` runs the symbolic harnesses end-to-end for the first time, and a
single wrong comparison in the OM's `basic_string` constructor is all that
stands between here and a symbolic proof of B-1/B-2.

---

## Issue #6183 — C++ operational-model gaps — CLOSED

Merged as [#6190](https://github.com/esbmc/esbmc/pull/6190), "[om] Add missing
type_traits, unique_ptr and basic_string members" (commit `ba1ac4cb7f`).

### What landed

| Addition | Standard reference |
|---|---|
| `is_class`, `is_polymorphic`, `is_trivially_default_constructible`, `is_trivially_destructible` (+ `_v` variants) | over the clang builtins the frontend already accepted |
| `unique_ptr(nullptr_t)` — `constexpr`, non-explicit, both specialisations | [unique.ptr.single.ctor] p1 |
| `unique_ptr::operator=(nullptr_t)` — delegates to `reset()`, both specialisations | [unique.ptr.single.asgn] p5 |
| `basic_string::operator[](size_t) const` | [string.access] p1 |
| `basic_string::push_back`, `basic_string::reserve` | [string.modifiers], [string.capacity] |
| `<cstdlib>`: `using ::size_t;` | matches libstdc++ |

Two fixes fell out of reviewing the above:

- `capacity()` returned `size()`, contradicting [string.capacity]'s
  `capacity() >= res_arg` guarantee once `reserve()` exists. It now returns the
  fixed buffer size.
- `operator+=(char)` wrote `_size + 2` bytes into a 128-byte buffer with no
  guard. The guard went there rather than in `push_back`, which closes the
  overflow for both entry points.

Validated with five regression tests under `regression/esbmc-cpp/cpp/github_6183*`,
confirmed failing on a rebuilt unpatched baseline, mutation-tested so nothing
passes vacuously, both new capacity guards shown reachable, and 1,931 existing
C++ regression tests passing.

### End-to-end confirmation in this repo

The plan predicted that once these landed, `stubs/esbmc_compat.h` would "shrink
to almost nothing — a good end-to-end check that the fix is real." It did, and
the check passed. With the shim **entirely disabled**, the only parse errors
remaining are:

```
no member named 'allocate_shared' in namespace 'std'
no template named 'shared_ptr' in namespace 'std'
```

Nothing about traits, nothing about `size_t`. Those gaps are genuinely closed
upstream.

Consequently the shim is now down to `shared_ptr` alone, and the Makefile's
gate was renamed `ESBMC_OM_MISSING_TRAITS` → `ESBMC_OM_MISSING_SHARED_PTR`.
This was **forced, not cosmetic**: with #6190 in the build, shimming the traits
is a *redefinition error* against the OM, so `make smoke` fails until the shim
shrinks.

### Still open, deliberately

**`std::shared_ptr` (was Tier 3).** #6190 left it out on purpose: reference
counting, aliasing constructors, `weak_ptr` and `enable_shared_from_this` need
a real model, not a header addition. **Should be its own issue and its own PR.**

Interim mitigation still worth doing: naming `std::shared_ptr` in an
*uninstantiated* function template is enough to fail parsing — which is exactly
how `Aws::MakeShared` blocks this repo — so even a declaration-only `shared_ptr`
in the OM would unblock a large class of real code. Propose that as the first
step, clearly marked parse-support only. `stubs/esbmc_compat.h` contains a
working example of that shape, including why `allocate_shared` is left
undefined on purpose.

### Known OM defects still unfixed

Verified still present on `main` at `05c7409289`:

- **`basic_string::size()` returns `int`, not `size_type`** (`src/cpp/library/string:644`).
  Wrong for any string longer than `INT_MAX` and wrong in template deduction.
- **OM `unique_ptr`'s destructor is `#if 0`-ed out** (`src/cpp/library/memory:290`)
  with `// TODO: fix remove goto sideeffect`, so the model never releases. This
  silently invalidates `--memory-leak-check` on any C++ target using
  `unique_ptr` — a clean leak verdict currently means nothing there. Until it is
  fixed, ESBMC should **warn** when `--memory-leak-check` is combined with C++
  input rather than reporting a misleading pass.
- **`operator[]` keeps the strict `pos < _size` bound**, even though
  [string.access] p1 makes `s[s.size()]` well-defined. #6190 kept it
  deliberately and recorded why in a source comment: `basic_string(int)` sets
  `_size` without initialising `str[]`, so `str[_size]` is not reliably `'\0'`,
  and returning it would hand the solver an unconstrained byte. A spurious
  failure beats a silent wrong value in a verifier. The sound fix (return a
  static `'\0'` for `pos == _size`) is noted there too. **Do not "fix" this into
  the unsound form.**

---

## Issue #6184 — SIGABRT during GOTO conversion — root cause located

**Status:** cause found, minimal reproducer in hand, fix not yet applied.

### Correction: it is not a use-after-free

The previous revision of this document concluded "use-after-free of `irept::dt`
under `SHARING`" and gated all further work behind an ASan build to find the
free site. **That diagnosis was wrong, and the ASan phase is unnecessary.**

The real cause is an **out-of-bounds read**, not a use-after-free:

`Aws::NewArray` (`AWSMemory.h:185`) constructs elements with

```cpp
new (pointerToT + i) T;      // placement new, NO initializer
```

For a non-class `T`, `new (p) T;` default-initializes, which performs *no*
initialization at all ([dcl.init.general]). Clang therefore attaches **no
initializer child** to the `CXXNewExpr`, and ESBMC ends up building a `comma`
expression with a single operand. Then
`clang_c_adjust::adjust_comma` (`src/clang-c-frontend/clang_c_adjust_expr.cpp:1589`)
does:

```cpp
expr.type() = expr.op1().type();   // unguarded op1() on a 1-operand expr
```

`op1()` on a one-element operand vector reads one past the end. The garbage
`irept` that comes back is what the gdb session mistook for recycled memory:
`ref_count == 0`, a mutex with an invalid `__kind`, and an `_M_color` enum
holding a pointer are all simply **out-of-bounds bytes**. Assigning from that
garbage reference drives `detatch()` on a junk `dt` pointer, which is why the
backtrace ended in `irept::detatch` locking `old_data->dt_mutex`.

This also explains every loose end the UAF theory had to hand-wave:

- **Single thread** — an OOB read needs no race. Consistent with `info threads`.
- **Only 44 frames** — no stack exhaustion, as observed.
- **Varying glibc abort messages** — the bogus `__kind` sends glibc down the
  priority-inheritance path (`__futex_lock_pi64`), and *which* garbage lands
  there depends on heap layout. `ulimit -s unlimited` changing the symptom was,
  as suspected, a layout perturbation and not a fix.

The evidence recorded under gdb was accurate; the *interpretation* was wrong.
Worth noting for next time: `ref_count == 0` on a live-looking `irept` reads as
"freed" but is equally consistent with "never was an `irept`."

### Reproducer (Phase 2 deliverable — done)

`esbmc_bug_repros/placement_new_no_init.cpp` — self-contained, **no AWS
headers, no shim, no `-I` flags**. This is what the earlier reduction attempt
was looking for and failed to find.

```
$ esbmc --std c++11 esbmc_bug_repros/placement_new_no_init.cpp
Converting
Generating GOTO Program
ERROR:
migrate expr failed
<core dumped>
```

The differential is clean and one character wide:

| Expression | Result |
|---|---|
| `new (p) int;` | crash |
| `new (p) int();` | `VERIFICATION SUCCESSFUL` |

The `()` gives clang an initializer child, so the comma gets its second operand
and `op1()` is in bounds.

Note the crash *signature* on a current build is `migrate expr failed` plus a
core dump, rather than the glibc pthread assertions in the original issue text.
Same mechanism, different downstream victim of the same garbage expression —
the garbage now reaches migration before it reaches a mutex.

### Phase 3 — fix (done; [PR #6195](https://github.com/esbmc/esbmc/pull/6195), open)

The fix has two halves, and the split is the point: **fix the producer, assert
at the consumer.**

1. **Producer** (`src/clang-cpp-frontend/clang_cpp_convert.cpp`). Don't build
   the malformed expression in the first place. When the `CXXNewExpr` has no
   initializer, the value of `new (p) T;` is just the placement address, so the
   conversion emits the typecast directly and returns:

   ```cpp
   if (!ne.hasInitializer())
   {
     new_expr = tp;
     break;
   }
   ```

   There is nothing to sequence, so there is no reason to build a `comma` at
   all. This also lets the initializer path below drop a level of nesting,
   since `getInitializer()` is now known non-null.

2. **Consumer** (`src/clang-c-frontend/clang_c_adjust_expr.cpp`). Make the
   latent invariant explicit rather than silently reading out of bounds:

   ```cpp
   assert(expr.operands().size() == 2);
   expr.type() = expr.op1().type();
   ```

This is better than the consumer-side workaround of taking the type from the
last operand regardless of count. That would have papered over malformed IR and
left a one-operand `comma` circulating through the rest of the tool; the assert
instead catches *any* other producer of one, loudly and at the source line that
built it.

Because this adds branches, CLAUDE.md's Mode C **C-Live** obligation applies —
each must be shown reachable. `placement_new_no_init.cpp` discharges that for
the producer branch concretely.

Shipped with two regression tests,
`regression/esbmc-cpp/cpp/placement_new_no_init{,_fail}/`.

### Phase 4 — verify (partly discharged)

Against a build carrying both #6190 and #6195:

- ✅ `placement_new_no_init.cpp` → `VERIFICATION SUCCESSFUL`.
- ✅ **`make smoke` green** — `Aws::Utils::Array<unsigned char>` converts and
  symexes. This was the stated acceptance criterion for the crash, and it is
  met.
- ✅ `make esbmc` reaches the solver on both harness modes, where it previously
  aborted during conversion.
- ❌ Both modes end `VERIFICATION FAILED` on a **spurious** `basic_string
  overflow` inside the OM, not on B-1. See the next section.
- ⬜ Drop `scripts/make_model_headers.sh`'s `CryptoBuffer` transformation and
  confirm the unmodified upstream `Array.h` converts, removing the last
  deviation between `vendor/` and `model/`. Not attempted yet — it is only
  worth testing once the run can get past the string constructor.
- ⬜ Full ESBMC regression suite. `adjust_comma` is on the path of every C and
  C++ program, so the blast radius is the whole tool. Owned by #6195's CI.

Also fixed here while re-running: the Makefile passed `--bounds-check` and
`--pointer-check`, which current ESBMC has **removed** — both checks are now on
by default and only `--no-` opt-outs exist, so the old spellings are hard
errors. `--memory-leak-check` was dropped too, since the OM's `#if 0`-ed
`unique_ptr` destructor makes any leak verdict meaningless.

---

## New: `basic_string(const char*, size_t)` rejects valid input

**Status:** found by running the harnesses post-#6195; filed as
[esbmc/esbmc#6199](https://github.com/esbmc/esbmc/issues/6199), still open.
Worked around in the harnesses (see REPORT.md), so it no longer blocks the
proof. The filed issue adds two defects beyond the wrong comparison: the copy
loop truncates at embedded nulls while `_size` is already `n`, and `strlen` is
evaluated before the `s != NULL` check.

`src/cpp/library/string:1132` asserts:

```cpp
__ESBMC_assert(n < strlen(s), "basic_string overflow");
```

[string.cons] gives this constructor exactly one precondition — "`[s, s + n)`
is a valid range" — and effects "constructs an object whose initial value is
the range `[s, s + n)`". The assert is wrong twice over:

1. **The operator.** `n == strlen(s)` is the canonical case; strict `<` rejects
   it. `std::string("abc", 3)` is reported as `basic_string overflow`. Even a
   deliberately conservative strlen-based approximation wants `n <= strlen(s)`.
2. **The premise.** `s` need not be null-terminated, so `strlen(s)` is not part
   of the precondition — and calling `strlen` on a valid non-terminated
   argument is itself UB. A faithful model cannot be phrased via `strlen` at
   all.

Minor, same function: the `strlen(s)` assert is evaluated *before* the
`s != NULL` assert that follows it, so a null argument is dereferenced before
it is checked. Swap them regardless of the above.

This is a **false positive**, so soundness is not at risk — but it blocks
verification of any code using the constructor, including
`Aws::String input(raw, len)` in the Base64 harness.

Reproducer: `esbmc_bug_repros/om_string_ptr_len_ctor.cpp` (no AWS headers).

Suggested fix: drop the `strlen` assert entirely, or reduce it to
`n <= strlen(s)` if a defensive check is wanted for the null-terminated case,
and order it after the null check. Needs a regression test for
`n == strlen(s)`, which is the case that currently fails.

### Not #6184's cause, but still real

Two latent defects in the sharing scheme, visible by inspection and unchanged
by any of the above:

- `remove_ref` (`irep.cpp:82-95`) releases `old_data->dt_mutex` and *then*
  `delete old_data` — destroying the mutex it just unlocked. Safe only while
  single-threaded.
- `ref_count` is a plain `unsigned` guarded by a per-object mutex, and
  `detatch()` unlocks before calling `remove_ref`, which re-locks. The
  check-then-act across that gap is not atomic.

Both are bugs waiting for the day ESBMC parallelises this code, and are worth
fixing on their own merits. Now that #6184 is explained by an out-of-bounds
read, it is even clearer that fixing these **would not have fixed #6184** —
they were never the cause.

---

## Order of work

1. **File and fix `basic_string(const char*, size_t)`.** One comparison, plus a
   regression test for `n == strlen(s)`. This is the only thing between here
   and a symbolic proof of B-1/B-2, which is the entire point of the exercise.
2. **Merge [#6195](https://github.com/esbmc/esbmc/pull/6195).** Already
   verified green here; awaiting review.
3. **Finish Phase 4** — re-run `make esbmc` for the real verdict, then drop the
   `CryptoBuffer` surgery from `make_model_headers.sh` and confirm pristine
   `Array.h` converts.
4. **`shared_ptr`** — separate issue, separate PR, no dependency on the above.
   Declaration-only support first.
5. **OM cleanups** — `size()` returning `int`, and the `#if 0`-ed `unique_ptr`
   destructor that quietly voids `--memory-leak-check`. Independent; the second
   is the more serious because it makes a verifier report a pass it has not
   earned.

## Honest assessment

The remaining work is ordinary, and the trend is good: each blocker has been
shallower than the last. #6183 was eight missing members; #6184 was one
unguarded `op1()`; this one is a single `<` that should be `<=` — or, done
properly, an assert that should not exist.

Worth keeping in view: **none of these three were findable in advance.** Each
surfaced only once its predecessor was cleared, and the current one could not
exist as a symptom until code actually reached the string constructor. Any
estimate of "how far from a proof" made before the next blocker is uncovered is
a guess, and this document has now been wrong about that twice — once by
diagnosing a use-after-free that was an out-of-bounds read, and once by calling
`make smoke` the acceptance criterion when it was merely the next gate.

The one gate that did hold up was the original refusal to patch `irept` against
a hypothesis. That suspect was entirely innocent.
