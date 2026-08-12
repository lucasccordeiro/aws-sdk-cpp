# verification/

Bounded-model-checking and sanitizer harnesses for the hand-written codecs in
`aws-cpp-sdk-core/source/utils/`.

**Findings live in [REPORT.md](REPORT.md).** Two memory-safety defects were
confirmed in `Base64::Decode`: a heap buffer overflow (write) and an
out-of-bounds read.

Both were reported to AWS Security on 2026-07-29 and are now published as
[CVE-2026-19642](https://github.com/aws/aws-sdk-cpp/security/advisories/GHSA-wxx3-prfc-69xx)
(B-1, write) and
[CVE-2026-19643](https://github.com/aws/aws-sdk-cpp/security/advisories/GHSA-mxm9-xpf9-x66x)
(B-2, read), affecting `<= 1.11.861` and fixed in
**[1.11.862](https://github.com/aws/aws-sdk-cpp/releases/tag/1.11.862)**, which
delegates the codec to `aws-crt-cpp`. AWS also issued
[Security Bulletin 2026-080-AWS](https://aws.amazon.com/security/security-bulletins/2026-080-aws/).

## Layout

```
harnesses/      one harness per target
  smoke_harness.cpp          concrete input, no properties -- proves the
                             toolchain works before trusting any verdict
  base64_decode_harness.cpp  symbolic input for ESBMC (ANY_BYTE / ALPHABET modes)
  base64_decode_asan.cpp     concrete reproducer, argv-driven, for ASan/UBSan

stubs/          verification-only substitutes, each documenting what it replaces
  esbmc_compat.h             shim for the one remaining gap in ESBMC's C++
                             operational model (std::allocate_shared)
  aws_memory_stub.cpp        Aws::Malloc/Free (default no-memory-system path)
  aws/core/SDKConfig.h       stands in for the CMake-generated header
  aws/crt/{StlAllocator,Types}.h   stands in for the aws-crt-cpp submodule

vendor/         PRISTINE upstream sources. Never edited by hand.
                UPSTREAM_COMMIT / UPSTREAM_VERSION pin the provenance.
                Both ESBMC and the ASan build analyse exactly this tree.
                Pinned at the vulnerable 1.11.850; bumping it to 1.11.862 or
                later stops every target below reproducing.

esbmc_bug_repros/   reproducers for the ESBMC issues hit along the way
results/            build outputs and logs (regenerated; safe to delete)
```

Everything ESBMC or ASan analyses is byte-for-byte upstream code. There used to
be a second, generated tree (`model/`, built by `scripts/make_model_headers.sh`)
holding one mechanical transformation — `CryptoBuffer` cut out of `Array.h`,
because merely including its definition aborted ESBMC's GOTO conversion. That
crash was esbmc/esbmc#6184, fixed by
[PR #6195](https://github.com/esbmc/esbmc/pull/6195), and the surgery, the
generated tree and the script that produced it are all gone. The pristine header
now converts and reports the same defect at
`vendor/include/aws/core/utils/Array.h:208`.

## Running

```bash
make confirm  # ESBMC on the two named defect inputs (B-1, B-2)
make esbmc    # symbolic memory-safety harnesses
make smoke    # ESBMC frontend smoke test
make repros   # the ESBMC bug reproducers
make asan     # independent ASan cross-check; needs only GCC
make testgen  # ESBMC counterexamples -> executable tests, replayed under ASan
```

**ESBMC confirms both findings.** `make confirm` reports `VERIFICATION FAILED`
on `"AAAA="` (B-1, `assertion index < m_length` in `Array::GetItem`) and on
`\xFF\xFF\xFF\xFF` (B-2, out-of-bounds read), and `make esbmc` fails the same way
symbolically — with input bytes constrained to the RFC 4648 alphabet it finds
B-1, and with bytes unconstrained it finds B-2 first. `FAILED` is the desired
result; it is the confirmation. `make asan` is the independent cross-check and
`make testgen` replays each counterexample as a native crashing process.

One thing to know before changing anything:

* **Do not lower `UNWIND`.** The Base64 constructor fills a 256-entry decoding
  table in a loop; truncating it makes every byte decode to the sentinel, skips
  the overflowing writes, and yields `VERIFICATION SUCCESSFUL` on a program that
  overflows. The old value of 8 did exactly that. Tell-tale of a vacuous run:
  ~100 VCCs where a real one generates ~18000.

The harnesses carry no workarounds. The two that used to be here — padding the
backing array and excluding `'\0'` from every symbolic byte, both to dodge
esbmc/esbmc#6199 — were removed once [PR #6225](https://github.com/esbmc/esbmc/pull/6225)
fixed the underlying `basic_string(const char*, n)` constructor.

## Toolchain notes

* ESBMC 8.4.0 uses `--std c++11` and `--goto-functions-only`. The older
  `--cppstd` / `--parse-only` spellings do not exist.
* The ESBMC targets need a build carrying every fix this exercise produced:
  [#6190](https://github.com/esbmc/esbmc/pull/6190) (OM members, closing #6183),
  [#6195](https://github.com/esbmc/esbmc/pull/6195) (the GOTO-conversion crash,
  closing #6184), [#6225](https://github.com/esbmc/esbmc/pull/6225) (the string
  range constructor, closing #6199) and
  [#6209](https://github.com/esbmc/esbmc/pull/6209)/[#6210](https://github.com/esbmc/esbmc/pull/6210)
  (test-case generation, closing #6207/#6208). Against an older build the runs
  stop at a parse error, abort during conversion, or report a spurious
  `basic_string overflow` instead.
* **The one remaining OM gap is `std::allocate_shared`**, shimmed in
  `stubs/esbmc_compat.h` behind `-D ESBMC_OM_MISSING_ALLOCATE_SHARED`.
  [#6403](https://github.com/esbmc/esbmc/pull/6403) modelled `shared_ptr`,
  `weak_ptr` and `make_shared`, but `AWSAllocator.h:117` calls
  `std::allocate_shared`, whose absence is a *parse* error rather than a link
  error — naming it in an uninstantiated function template is enough to block
  the whole translation unit. Note this define is **required**, and **must not**
  be paired with the older `shared_ptr` shim, which would now be a redefinition
  error against the OM.
* `make testgen` passes `--ctest-output-dir .`; current ESBMC otherwise writes
  the generated files into an `esbmc-ctest/` subdirectory.
* `--memory-leak-check` is usable against this model again, though the Makefile
  still does not pass it (the harnesses assert memory safety, not ownership).
  It used to be meaningless here because the OM's `unique_ptr` had its
  destructor `#if 0`-ed out with a `// TODO: fix remove goto sideeffect`, so
  nothing was ever released and a clean leak verdict was unearned. That
  destructor now calls `deleter(ptr)` in both specialisations, and the check
  distinguishes both directions: a raw `new` with no `delete` reports
  `dereference failure: forgotten memory`, while the same allocation held in a
  `unique_ptr` reports `VERIFICATION SUCCESSFUL`.

## Adding a target

1. Vendor the pristine source and its transitive SDK headers under `vendor/`
   (`g++ -MM` gives the exact set).
2. Write a smoke harness with concrete input first. Get it green before writing
   a symbolic one — otherwise a modelling failure reads as a finding.
3. Then write the symbolic harness, and give it both an unconstrained mode and
   a realistic-precondition mode. A violation that survives the constrained
   mode is the one worth reporting.
