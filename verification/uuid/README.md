# verification/uuid/

Sanitizer and bounded-model-checking harnesses for
`Aws::Utils::UUID::UUID(const Aws::String&)` in `aws-cpp-sdk-core`.

**Findings live in [REPORT.md](REPORT.md).** One memory-safety defect (**U-1**)
is confirmed under AddressSanitizer *and* ESBMC against byte-for-byte upstream
1.11.869: the string constructor `memcpy`s a decoded byte string into a fixed
16-byte member using the *input-derived* length, guarded only by `assert`s that
vanish under `NDEBUG`, so a string whose de-dashed hex body exceeds 32
characters overflows `m_uuid`. ESBMC brackets it exactly — every dash-free hex
string of up to 33 characters verifies, 34 is the minimal overflowing length —
and its counterexample crashes the native ASan build on replay.

Reachability was enumerated against the full SDK tree at 1.11.869: no
untrusted-input caller of the string constructor exists — wire-sourced UUIDs use
the separate 16-byte binary constructor, and service clients keep UUIDs as
`Aws::String` rather than parsing them into `Aws::Utils::UUID`. So U-1 is a
latent hardening bug, not a remotely triggerable one (see REPORT.md
"Reachability"), and is handled as a public finding rather than a coordinated
disclosure.

## Layout

```
vendor/     PRISTINE upstream sources, pinned by UPSTREAM_VERSION / UPSTREAM_COMMIT
            at 1.11.869. Never edited by hand.
  source/utils/UUID.cpp        the function under test
  include/aws/core/...         the real Array/String/memory headers it needs

stubs/      verification-only substitutes, each documenting what it replaces
  aws_str_hash_extract.cpp     verbatim HexDecode + Replace (the ctor's two
                               helpers), lifted from the 1.11.869 sources so the
                               constructor runs without vendoring the whole
                               hashing/crypto subsystem; plus link stubs for the
                               unreached RandomUUID/PseudoRandomUUID factories
  aws/core/utils/HashingUtils.h, StringUtils.h   minimal decls for the above
  aws/core/utils/crypto/*, local/Random.h        minimal decls so UUID.cpp's
                               Random* methods compile (never called)
  aws_memory_stub.cpp          Aws::Malloc/Free (default no-memory-system path)
  aws/core/SDKConfig.h, aws/crt/*  stand in for the generated header / CRT submodule

../stubs/esbmc_compat.h        NOT copied here: the ESBMC operational-model shim
                               is shared with the Base64 harnesses one directory
                               up, so the single remaining OM gap
                               (std::allocate_shared) is described and removed in
                               one place

harnesses/
  uuid_ctor_asan.cpp           concrete reproducer, argv-driven, for ASan/UBSan
  uuid_ctor_concrete.cpp       ESBMC on one named input, both semantics
  uuid_ctor_harness.cpp        ESBMC over a symbolic Aws::String

results/    build outputs (regenerated; gitignored)
```

## Running

```bash
make asan          # release (-DNDEBUG) and debug builds, over a table of inputs
make confirm       # ESBMC on the named input, plus the safe control
make esbmc         # ESBMC over the symbolic harness, both input models
make esbmc-debug   # the same named input with asserts live
```

Canonical 36-character UUID strings decode to exactly 16 bytes and are `ok`.
Over-length inputs report `heap-buffer-overflow` under `-DNDEBUG` (asserts
compiled out) and trip a length assert without it.

The ESBMC targets run under release semantics (`--no-assertions`), which is
where the defect bites. The input they use is 36 characters — it *passes* the
constructor's documented `length() == UUID_STR_SIZE` precondition and overflows
anyway. See REPORT.md "Symbolic confirmation" for why that matters, and for the
one per-loop unwind bound these runs need.
