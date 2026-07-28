# Plan: fixing esbmc/esbmc#6183 and #6184 — DISCHARGED

Two issues were filed against ESBMC while trying to verify `Base64::Decode`
(see [REPORT.md](REPORT.md)); three more followed. This was the plan to close
them. **All five are now closed**, so this document is kept as the record of the
diagnostic path rather than as work outstanding.

**Status as of 2026-07-28:**

| Issue | State |
|---|---|
| [#6183](https://github.com/esbmc/esbmc/issues/6183) | **CLOSED** by [PR #6190](https://github.com/esbmc/esbmc/pull/6190), merged |
| [#6184](https://github.com/esbmc/esbmc/issues/6184) | **CLOSED** by [PR #6195](https://github.com/esbmc/esbmc/pull/6195), merged |
| [#6199](https://github.com/esbmc/esbmc/issues/6199) | **CLOSED** by [PR #6225](https://github.com/esbmc/esbmc/pull/6225), merged 2026-07-22 |
| [#6207](https://github.com/esbmc/esbmc/issues/6207) | **CLOSED** by [PR #6209](https://github.com/esbmc/esbmc/pull/6209), merged |
| [#6208](https://github.com/esbmc/esbmc/issues/6208) | **CLOSED** by [PR #6210](https://github.com/esbmc/esbmc/pull/6210), merged |

Three framings in earlier revisions of this document are **superseded**:

- "#6184's cause is not located, gate all work behind an ASan run." The cause
  is known and is not what the gdb session suggested. See "Correction" below.
- "`make smoke` going green is the real acceptance criterion." It went green,
  and it was necessary but not sufficient — the harnesses then hit a *third*
  OM defect one layer up.
- "A single wrong comparison in the OM's `basic_string` constructor is all that
  stands between here and a symbolic proof." That comparison was fixed by
  #6225, and nothing appeared behind it. The proof is obtained.

**Where this actually stands:** every blocker is fixed upstream, every harness
workaround has been reverted, and the generated `model/` tree is gone — ESBMC
now analyses pristine `vendor/` sources and confirms both defects. The single
remaining OM gap is `std::allocate_shared` (see below), which costs one shim
line and blocks nothing.

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

### `shared_ptr` — landed separately; `allocate_shared` did not

**`std::shared_ptr` (was Tier 3).** #6190 left it out on purpose: reference
counting, aliasing constructors, `weak_ptr` and `enable_shared_from_this` need
a real model, not a header addition. It was subsequently modelled for real by
[PR #6403](https://github.com/esbmc/esbmc/pull/6403), "[om] Model shared_ptr,
weak_ptr and make_shared" — reference-counted, not the declaration-only
placeholder this document proposed as an interim step. The hand-written
`shared_ptr` that used to live in `stubs/esbmc_compat.h` was deleted rather than
disabled, because shimming it against the OM is now a redefinition error.

**What #6403 did not add is `std::allocate_shared`** — and that is the name
`AWSAllocator.h:117` actually calls:

```cpp
return std::allocate_shared<T, Aws::Allocator<T>>(
         Aws::Allocator<T>(), std::forward<ArgTypes>(args)...);
```

Without a declaration the name is not a template, so clang reads the `<` as
less-than and reports `'T' does not refer to a value`. That is a *parse* error,
not a link error, which is why naming it in an *uninstantiated* function
template still blocks the whole translation unit — the same shape that made the
original `shared_ptr` gap so expensive. The shim is correspondingly down to one
declaration, and the Makefile gate was renamed `ESBMC_OM_MISSING_SHARED_PTR` →
`ESBMC_OM_MISSING_ALLOCATE_SHARED`. **Worth its own issue and PR:** the OM now
has a real `shared_ptr` and a `make_shared` to build on, so adding
`allocate_shared` is a much smaller job than it was when #6190 deferred it.

### Known OM defects still unfixed

Re-verified on 2026-07-28 against `8d3cee251a`:

- **`basic_string::size()` returns `int`, not `size_type`**
  (`src/cpp/library/string:1753`). Wrong for any string longer than `INT_MAX`
  and wrong in template deduction. **Still present.**
- **`operator[]` keeps the strict `pos < _size` bound**, even though
  [string.access] p1 makes `s[s.size()]` well-defined. #6190 kept it
  deliberately and recorded why in a source comment: `basic_string(int)` sets
  `_size` without initialising `str[]`, so `str[_size]` is not reliably `'\0'`,
  and returning it would hand the solver an unconstrained byte. A spurious
  failure beats a silent wrong value in a verifier. The sound fix (return a
  static `'\0'` for `pos == _size`) is noted there too. **Do not "fix" this into
  the unsound form.**

**Now fixed, and worth recording because this document leaned on it:** OM
`unique_ptr`'s destructor was `#if 0`-ed out with a
`// TODO: fix remove goto sideeffect`, so the model never released and
`--memory-leak-check` was meaningless against any C++ target using it — a clean
leak verdict meant nothing. Both specialisations now call `deleter(ptr)`. The
check was mutation-tested here in both directions: a raw `new` with no `delete`
reports `dereference failure: forgotten memory`, and the same allocation held in
a `unique_ptr` reports `VERIFICATION SUCCESSFUL`. So the warning this repo used
to carry against `--memory-leak-check` is retired.

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

### Phase 4 — verify (discharged 2026-07-28)

Against a build carrying #6190, #6195, #6209, #6210 and #6225:

- ✅ `placement_new_no_init.cpp` → `VERIFICATION SUCCESSFUL`.
- ✅ **`make smoke` green** — `Aws::Utils::Array<unsigned char>` converts and
  symexes. This was the stated acceptance criterion for the crash, and it is
  met.
- ✅ `make esbmc` reaches the solver on both harness modes, where it previously
  aborted during conversion.
- ✅ Both modes now end `VERIFICATION FAILED` **on the defects themselves** —
  `Array.h:208 assertion index < m_length` in ALPHABET mode, `Base64.cpp:104`
  out-of-bounds read in ANY_BYTE mode — not on the spurious `basic_string
  overflow` that #6225 has since removed.
- ✅ The `CryptoBuffer` transformation is gone, and with it the whole generated
  `model/` tree and `scripts/make_model_headers.sh`. Pristine upstream
  `Array.h` converts and reports B-1 at
  `vendor/include/aws/core/utils/Array.h:208`. There is no longer any deviation
  between what upstream ships and what ESBMC analyses.
- ⬜ Full ESBMC regression suite. `adjust_comma` is on the path of every C and
  C++ program, so the blast radius is the whole tool. Owned by #6195's CI, which
  merged.

Also fixed here while re-running: the Makefile passed `--bounds-check` and
`--pointer-check`, which current ESBMC has **removed** — both checks are now on
by default and only `--no-` opt-outs exist, so the old spellings are hard
errors. `--memory-leak-check` was dropped at the same time because the OM's
`#if 0`-ed `unique_ptr` destructor made any leak verdict meaningless; that
destructor has since been restored (see above), so the flag would work now,
but it stays off — these harnesses assert memory safety, not ownership.

---

## `basic_string(const char*, size_t)` rejects valid input — CLOSED

**Status:** found by running the harnesses post-#6195; filed as
[esbmc/esbmc#6199](https://github.com/esbmc/esbmc/issues/6199) and **closed by
[PR #6225](https://github.com/esbmc/esbmc/pull/6225)**, merged 2026-07-22. The
filed issue added two defects beyond the wrong comparison: the copy loop
truncated at embedded nulls while `_size` was already `n`, and `strlen` was
evaluated before the `s != NULL` check. The constructor now reads:

```cpp
// [string.cons]: constructs from the range [s, s + n); n is unrelated to
// strlen(s) and the range may contain embedded null characters. Check for
// null before any dereference, then copy exactly n characters.
__ESBMC_assert(s != NULL, "invalid basic_string");
__ESBMC_assert(n < STRING_CAPACITY, "String capacity exceeded");

_size = n;
for (size_t i = 0; i < n; i++)
  str[i] = s[i];
str[n] = '\0';
```

All three defects are addressed: no `strlen`, exactly `n` characters copied so
embedded nulls survive, and the null check first. **Both harness workarounds
have been reverted** — the symbolic harness is back to `len <= MAXLEN` with no
spare byte and no `c != '\0'` constraint, and the concrete harness's string
literals no longer carry filler bytes.

The original defect, for the record — `src/cpp/library/string:1132` asserted:

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

This was a **false positive**, so soundness was never at risk — but it blocked
verification of any code using the constructor, including
`Aws::String input(raw, len)` in the Base64 harness.

Reproducer: `esbmc_bug_repros/om_string_ptr_len_ctor.cpp` (no AWS headers). It
now reports `VERIFICATION SUCCESSFUL`, and `make repros` expects that — there is
no longer an expected-failing case in that target.

The fix taken was the first of the two suggested here: drop the `strlen` assert
entirely rather than weaken it to `n <= strlen(s)`, which is the right call,
since the premise was unsound independently of the operator.

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

## Order of work — what is left

Items 1-3 of the original list are done: #6199 was filed and fixed by #6225,
#6195 merged, and Phase 4 is discharged including the `CryptoBuffer` surgery,
which is now deleted along with the tree it generated. What remains:

1. **`std::allocate_shared`** — the last OM gap, and the last shim line in this
   repo. Separate issue, separate PR. Smaller than it was when #6190 deferred
   the whole of `shared_ptr`, because #6403 has since supplied a real
   reference-counted `shared_ptr` and a `make_shared` to build on.
2. **OM cleanup** — `basic_string::size()` still returns `int` rather than
   `size_type`. Independent of everything above. The other item that used to sit
   here, the `#if 0`-ed `unique_ptr` destructor, has been fixed.
3. **Report B-1 and B-2 to `aws/aws-sdk-cpp`.** Nothing in this repo has been
   sent upstream to the SDK. The defects, the reproducers and a suggested fix
   for each are in [REPORT.md](REPORT.md); B-1 is a heap overflow reachable from
   a public API on untrusted input, so this is the item with a clock on it.

## Honest assessment

The trend held all the way down: each blocker was shallower than the last.
#6183 was eight missing members; #6184 was one unguarded `op1()`; #6199 was a
single `<` that should not have existed at all. And behind #6199 there was
nothing — the proof came out.

Worth keeping in view: **none of these were findable in advance.** Each surfaced
only once its predecessor was cleared, and #6199 could not exist as a symptom
until code actually reached the string constructor. Any estimate of "how far
from a proof" made before the next blocker is uncovered is a guess, and this
document was wrong about that twice — once by diagnosing a use-after-free that
was an out-of-bounds read, and once by calling `make smoke` the acceptance
criterion when it was merely the next gate. It was then wrong a third time in
the optimistic direction, by calling #6199 "the only thing between here and a
symbolic proof" — which happened to be true, but was not knowable when written.

The one gate that did hold up was the original refusal to patch `irept` against
a hypothesis. That suspect was entirely innocent.
