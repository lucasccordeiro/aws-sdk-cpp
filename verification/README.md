# verification/

Bounded-model-checking and sanitizer harnesses for the hand-written codecs in
`aws-cpp-sdk-core/source/utils/`.

**Findings live in [REPORT.md](REPORT.md).** Two memory-safety defects were
confirmed in `Base64::Decode`: a heap buffer overflow (write) and an
out-of-bounds read.

## Layout

```
harnesses/      one harness per target
  smoke_harness.cpp          concrete input, no properties -- proves the
                             toolchain works before trusting any verdict
  base64_decode_harness.cpp  symbolic input for ESBMC (ANY_BYTE / ALPHABET modes)
  base64_decode_asan.cpp     concrete reproducer, argv-driven, for ASan/UBSan

stubs/          verification-only substitutes, each documenting what it replaces
  esbmc_compat.h             shims for gaps in ESBMC's C++ operational model
  aws_memory_stub.cpp        Aws::Malloc/Free (default no-memory-system path)
  aws/core/SDKConfig.h       stands in for the CMake-generated header
  aws/crt/{StlAllocator,Types}.h   stands in for the aws-crt-cpp submodule

vendor/         PRISTINE upstream sources. Never edited by hand.
                UPSTREAM_COMMIT / UPSTREAM_VERSION pin the provenance.

model/          GENERATED from vendor/ by scripts/make_model_headers.sh.
                Exists only to work around an ESBMC crash; the delta is one
                reviewable `diff -u` against vendor/.

esbmc_bug_repros/   reproducers for the ESBMC issues hit along the way
results/            build outputs and logs (regenerated; safe to delete)
scripts/            make_model_headers.sh
```

The separation of `vendor/` from `model/` is the point: everything ESBMC or
ASan actually analyses is upstream code, and any deviation is a mechanical,
scripted transformation you can diff rather than a hand-maintained fork.

## Running

```bash
make confirm  # ESBMC on the two named defect inputs (B-1, B-2)
make esbmc    # symbolic memory-safety harnesses
make smoke    # ESBMC frontend smoke test
make repros   # the ESBMC bug reproducers
make asan     # independent ASan cross-check; needs only GCC
make model    # regenerate model/ from vendor/
```

Against a build carrying esbmc/esbmc#6190 and #6195, **ESBMC confirms both
findings**: `make confirm` reports `VERIFICATION FAILED` on `"AAAA="` (B-1,
`assertion GetItem`) and on `\xFF\xFF\xFF\xFF` (B-2, out-of-bounds read), and
`make esbmc` fails the same way symbolically with input bytes constrained to the
RFC 4648 alphabet. `FAILED` is the desired result — it is the confirmation.
`make asan` is the independent cross-check.

Two things to know before changing anything:

* **Do not lower `UNWIND`.** The Base64 constructor fills a 256-entry decoding
  table in a loop; truncating it makes every byte decode to the sentinel, skips
  the overflowing writes, and yields `VERIFICATION SUCCESSFUL` on a program that
  overflows. The old value of 8 did exactly that.
* The harnesses work around esbmc/esbmc#6199 (the OM's `basic_string(const
  char*, n)` asserts `n < strlen(s)`) by keeping a spare byte in the backing
  array. Reproducer: `esbmc_bug_repros/om_string_ptr_len_ctor.cpp`. See
  REPORT.md and ESBMC_FIX_PLAN.md.

## Toolchain notes

* ESBMC 8.4.0 uses `--std c++11` and `--goto-functions-only`. The older
  `--cppstd` / `--parse-only` spellings do not exist.
* The ESBMC targets require [PR #6190](https://github.com/esbmc/esbmc/pull/6190)
  (merged 2026-07-19, closing issue #6183), which added the missing
  `unique_ptr`/`basic_string`/`type_traits` members to `src/cpp/library/`.
  Against an older build the run stops at a parse error instead.
* The one remaining OM gap is `std::shared_ptr`, still shimmed in
  `stubs/esbmc_compat.h` behind `-D ESBMC_OM_MISSING_SHARED_PTR`. Note this
  define is **required** against a #6190 build and **must not** be paired with
  the pre-#6190 traits shim, which would now be a redefinition error.
* `--memory-leak-check` is not meaningful against this operational model:
  ESBMC's OM `unique_ptr` has its destructor `#if 0`-ed out, so nothing is ever
  released.

## Adding a target

1. Vendor the pristine source and its transitive SDK headers under `vendor/`
   (`g++ -MM` gives the exact set).
2. Write a smoke harness with concrete input first. Get it green before writing
   a symbolic one — otherwise a modelling failure reads as a finding.
3. Then write the symbolic harness, and give it both an unconstrained mode and
   a realistic-precondition mode. A violation that survives the constrained
   mode is the one worth reporting.
