# Three defects on the SDK's JSON number path — J-1, J-2, J-3

Every JSON-protocol response body the SDK receives is parsed by the copy of
cJSON vendored in `aws-cpp-sdk-core`, and read back through
`Aws::Utils::Json::JsonView` (or `Aws::Utils::DocumentView`, which repeats the
same code). Pinned here at **1.11.886** (`31583cee6ed69015a7e63fefae5b931ae9f3196e`),
the current release on 2026-09-04; `vendor/` holds the four files unmodified.

The parser is not where the defects are. 595,000 libFuzzer executions over
parse / print / re-parse under ASan and UBSan found nothing, and normalising the
`cJSON_AS4CPP_` prefixes shows the fork sits 101 lines from upstream cJSON
v1.7.19 with no memory-safety drift. What upstream's fuzzing cannot see is the
one feature AWS added on top, and the C++ layer above it.

**The feature.** Upstream parses every number into a `double`. AWS also keeps the
literal, so that big integers do not lose precision (`cJSON.cpp:397-402`):

```cpp
    // For integer which is out of the range of [INT_MIN, INT_MAX], it may lose precision if we cast it to double.
    // Instead, we keep the integer literal as a string.
    if (!has_decimal_point && (number > INT_MAX || number < INT_MIN))
    {
        item->valuestring = (char*)cJSON_AS4CPP_strdup(number_c_string, &global_hooks);
    }
```

That puts a wire-controlled string of unbounded length on a field the rest of
cJSON treats as short and string-only. All three findings follow from it.

**J-1 — a response number can abort the process.** `print_number` prints the kept
literal through the 26-byte buffer upstream sized for a `double`, and fails the
whole document when it does not fit. The wrapper does not check the result:

```cpp
    auto temp = cJSON_AS4CPP_PrintUnformatted(m_value);   // JsonSerializer.cpp:680
    Aws::String out(temp);                                // :681  temp may be null
```

```
$ ./results/witness 5                        # paths and columns trimmed below
26-digits  {"n":99999999999999999999999999}  isInteger=1 isFloat=0 AsInt64=9223372036854775807 ...
terminate called after throwing an instance of 'std::logic_error'
  what():  basic_string: construction from null is not valid
Aborted (core dumped)                        # exit 134
```

25 characters print normally; 26 abort. ASan and UBSan stay silent throughout —
`snprintf`'s length guard holds, so nothing is written out of bounds. In the SDK
itself the path is `JsonErrorMarshaller::Marshall`, which parses the error body
off the wire and prints it back at trace level (`AWSErrorMarshaller.cpp:59`).

**J-2 — the double is converted without a range check.** Four sites in each of
the two files convert `valuedouble` to a 64-bit integer directly
(`JsonSerializer.cpp:502,515,641,656`). [conv.fpint]/1 (N3337 §4.9/1) leaves that
undefined when the value is not representable, and `valuedouble` is whatever
`strtod` returned for the literal — `inf`, for `1.0e999`:

```
$ ./results/witness 3                                    # GCC, ASan + UBSan
JsonSerializer.cpp:502: runtime error: 1.5e+300 is outside the range of representable values of type 'long int'
JsonSerializer.cpp:515: runtime error: 1.5e+300 is outside the range of representable values of type 'long int'
JsonSerializer.cpp:656: runtime error: 1.5e+300 is outside the range of representable values of type 'long long int'
JsonSerializer.cpp:641: runtime error: 1.5e+300 is outside the range of representable values of type 'long long int'
exp-dot  {"n":1.5e300}  isInteger=0 isFloat=1 AsInt64=-9223372036854775808 GetInt64=-9223372036854775808 ...
```

`:502` is `GetInt64`, which is the accessor generated deserializers call.

This one needs no logging and no application involvement: generated
deserializers read every `int64` model field through `GetInt64`
(`FunctionConfiguration.cpp:43`, `m_codeSize = jsonValue.GetInt64("CodeSize")`).

**J-3 — the kept literal is read with `atoll`.** `StringUtils::ConvertToInt64` is
`std::atoll`, which is undefined on overflow (C 7.22.1.2p3) and stops at the
first character that cannot continue a decimal integer. A literal is kept for
exponent forms too, so:

```
$ ./results/witness 6
exp-in-range  {"n":5e9}    isInteger=0 isFloat=1 AsInt64=5 GetInt64=5 AsDouble=5e+09
$ ./results/witness 2
exp-no-dot    {"n":1e300}  isInteger=0 isFloat=1 AsInt64=1 GetInt64=1 AsDouble=1e+300
```

Five billion is exactly representable as an `int64`, the SDK has the literal in
hand, and the application reads **5**. `parse_number` keeps a literal for
anything outside **`int`**'s range, so this is not confined to numbers too large
to represent.

This one is a **regression**. Until 1.11.659 the guard was `isInteger`, cleared
on `e`/`E` as well as on `.`, so an exponent form kept no literal and `AsInt64`
answered `5000000000`. Commit `87042947e93a` ("update cjson dep to 1.7.19")
replaced it with `has_decimal_point`, which only `.` sets. Built against each
release's own parser, `{"n":5e9}` gives `5000000000` at 1.11.659 and `5` at
1.11.660 — `AsInt64` itself is byte-identical across the change.

## Layout

```
vendor/         PRISTINE upstream sources -- cJSON.cpp, JsonSerializer.cpp,
                Document.cpp, StringUtils.cpp and the header cone they need.
                Never edited by hand. UPSTREAM_COMMIT / UPSTREAM_VERSION pin the
                provenance; the reachability leg re-checks all 25 files.
reference/      upstream cJSON v1.7.19, for the delta leg. Third-party, and the
                only thing here that is not AWS's code.
harnesses/      json_number_witness.cpp   fifteen response bodies through
                                          JsonValue and through Document
                json_number_esbmc.cpp     the conversion, over a symbolic double
                cjson_parse_fuzz.cpp      libFuzzer entry point for the parser
stubs/          verification-only substitutes (memory system, logging, the two
                CRT headers Array.h pulls in), each documenting what it replaces
fix/            the proposed patch, 17 hunks across the four files
results/        build outputs and logs (regenerated; safe to delete)
```

## Running

```sh
./reproduce.sh              # 70 checks, ~30 s
./reproduce.sh sanitizer    # or one leg: sanitizer, esbmc, fuzz, delta,
                            # reachability, fix
```

The run exits 0 only if every check matches **and nothing was skipped** — a leg
that cannot run has not agreed with anything, so it must not read as a pass.

## Toolchain notes

* **GCC leaves `float-cast-overflow` out of `-fsanitize=undefined`.** Under plain
  `-fsanitize=undefined` a GCC build reports nothing for J-2 and the run looks
  clean. `reproduce.sh` names the check explicitly; clang enables it as part of
  `undefined`.
* **ESBMC has no check for this conversion.** `--overflow-check --nan-check`
  reports `VERIFICATION SUCCESSFUL` on a bare `(long long)1e300`, so
  `harnesses/json_number_esbmc.cpp` states [conv.fpint]'s precondition itself
  with `__ESBMC_assert`. The suite runs the bare conversion as a check of its
  own, so the row fails the day ESBMC gains the check and this note needs
  removing.
* The fuzz leg needs clang with libFuzzer; the proofs need ESBMC 8.5.0 with both
  Z3 and Bitwuzla, and every proof row is run under both.
* **The allocator model is faithful, but not because hooks are absent.**
  `Aws::InitAPI` does install cJSON hooks (`Aws.cpp:165-168`) — they route to
  `Aws::Malloc`/`Aws::Free`, which fall through to `malloc`/`free` when no memory
  system is installed and `USE_AWS_MEMORY_MANAGEMENT` is undefined
  (`AWSMemory.cpp:130-174`, which `stubs/aws_memory_stub.cpp` models). Nothing
  here calls `InitHooks`, so ASan sees real `malloc`/`free` either way.

Findings generated with AI tools and reviewed by Lucas Cordeiro, University of
Manchester.
