# ESBMC, libFuzzer and sanitizers vs. the SDK's JSON number path — findings

**Target:** `aws/aws-sdk-cpp` @ `31583cee6ed69015a7e63fefae5b931ae9f3196e`
(v1.11.886, the current release at the time of writing)
**Code under analysis:** the vendored cJSON fork's number handling —
`parse_number` and `print_number`
(`src/aws-cpp-sdk-core/source/external/cjson/cJSON.cpp:314-424,607-675`) — and the
C++ accessors layered over it:
`Aws::Utils::Json::JsonView::{GetInt64,AsInt64,IsIntegerType,IsFloatingPointType,WriteCompact,WriteReadable}`
(`.../source/utils/json/JsonSerializer.cpp:491-517,629-657,669-701`) and the
identical members of `Aws::Utils::DocumentView` (`.../source/utils/Document.cpp`)
**Cross-check:** GCC and clang with AddressSanitizer and UBSan, libFuzzer over
the parser, and ESBMC 8.5.0 under both Bitwuzla and Z3
**Status:** three defects, all on the path a **service response body** takes into
an application. The parser itself is not one of them: 595k libFuzzer executions
over parse / print / re-parse under ASan and UBSan found nothing, and the fork
carries no memory-safety drift from upstream cJSON v1.7.19. All three grow out of
one feature AWS added on top of upstream, and all three are closed by the patch
in `fix/`.

---

## Summary

Upstream cJSON parses every JSON number into a `double`. AWS added a
precision-preserving feature on top: when a literal has no decimal point and its
value falls outside `[INT_MIN, INT_MAX]`, `parse_number` also keeps the literal
itself, in `item->valuestring` (`cJSON.cpp:397-402`). That breaks cJSON's
invariant that only *string* items carry a `valuestring`, and it puts a
wire-controlled, unbounded-length string on a field the printer assumes is short.

| # | Defect | Effect | Trigger |
|---|--------|--------|---------|
| **J-1** | `WriteCompact`/`WriteReadable` build `Aws::String` from whatever `cJSON_AS4CPP_Print*` returns, with no null check (`JsonSerializer.cpp:680,697`; `Document.cpp:655,668`) — and `print_number`'s 26-byte buffer cannot hold a longer literal, so the whole document fails to print | `std::logic_error`, **process abort** (exit 134) | a response number of 26 or more characters |
| **J-2** | `static_cast<long long>(valuedouble)` with no range check, at four sites (`JsonSerializer.cpp:502,515,641,656`; `Document.cpp:492,506,519,549`) | undefined behaviour, [conv.fpint]/1; in practice a garbage value — `INT64_MIN` on x86-64 | any response number outside the `int64` range written with a decimal point, e.g. `1.5e300`, or `inf` from `1.0e999` |
| **J-3** | the kept literal is read with `std::atoll` (`StringUtils.cpp:337-349`), which stops at the exponent and is undefined on overflow (C 7.22.1.2p3) | **`{"n":5e9}` reads back as `5`** | any integer written in exponent form, in range or not |

J-1 aborts. J-2 and J-3 are wrong answers, one of them undefined.

The three are independent, and none of them needs a malformed document: every
input below is well-formed JSON that a service is free to return.

## J-1 — a response number can abort the process

### The defect

`parse_number` keeps the literal:

```cpp
    // For integer which is out of the range of [INT_MIN, INT_MAX], it may lose precision if we cast it to double.
    // Instead, we keep the integer literal as a string.
    if (!has_decimal_point && (number > INT_MAX || number < INT_MIN))
    {
        item->valuestring = (char*)cJSON_AS4CPP_strdup(number_c_string, &global_hooks);
    }
```

`print_number` prints it through the buffer upstream sized for a `double`:

```cpp
    unsigned char number_buffer[26] = {0}; /* temporary buffer to print the number into */
    ...
    if (item->valuestring)
    {
        length = snprintf((char*)number_buffer, sizeof(number_buffer), "%s", item->valuestring);
    }
    ...
    /* snprintf failed or buffer overrun occurred */
    if ((length < 0) || (length > (int)(sizeof(number_buffer) - 1)))
    {
        return false;
    }
```

`snprintf` truncates safely and returns the length it *would* have written, so
the guard catches the overflow — there is no buffer overrun. It fails the print
instead, and that failure propagates: `print_value` → `print_object` →
`cJSON_AS4CPP_PrintUnformatted` returns `NULL`. The wrapper does not check:

```cpp
    auto temp = cJSON_AS4CPP_PrintUnformatted(m_value);
    Aws::String out(temp);
    cJSON_AS4CPP_free(temp);
```

`std::string(nullptr)` is undefined. libstdc++ hardens it into a thrown
`std::logic_error`, which nothing on this path catches.

### Evidence

`./reproduce.sh sanitizer`, on the pristine sources:

| Input | Result |
|---|---|
| `{"n":99999999999999999999999999}` | `AsInt64` returns first — the read works |
| the `WriteCompact` that follows | `terminate called after throwing an instance of 'std::logic_error'` / `what(): basic_string: construction from null is not valid` |
| process status | **134 (SIGABRT)** |
| the same body through `DocumentView::WriteCompact` | 134 |
| 25 characters instead of 26 | prints normally |
| ASan and UBSan | silent — no out-of-bounds access anywhere on this path |

26 characters is the boundary because the guard rejects `length > 25`. A
26-digit integer is unremarkable in a JSON payload; so is a 20-digit one with a
sign and an exponent.

## J-2 — the double is converted without a range check

### The defect

Four sites read `valuedouble` straight into a 64-bit integer:

```cpp
int64_t JsonView::AsInt64() const
{
    assert(cJSON_AS4CPP_IsNumber(m_value));
    if (m_value->valuestring)
    {
        return Aws::Utils::StringUtils::ConvertToInt64(m_value->valuestring);
    }
    else
    {
        return static_cast<int64_t>(m_value->valuedouble);
    }
}
```

and, in the two predicates,
`m_value->valuedouble == static_cast<long long>(m_value->valuedouble)`.

[conv.fpint]/1 (N3337 §4.9/1) leaves the conversion undefined when the truncated
value cannot be represented in the destination type. `valuedouble` is whatever
`strtod` returned for the literal, which for `1.0e999` is `inf`.

The SDK is aware of the class elsewhere in the same file — `AsInteger` carries
the comment *"can be double or value larger than int_max, but at least not UB"*
(`JsonSerializer.cpp:487`), because `valueint` is saturated by cJSON. The
`int64` path has no such saturation.

### Evidence

| Input | Diagnostic |
|---|---|
| `{"n":1.5e300}` | `JsonSerializer.cpp:641` `1.5e+300 is outside the range of representable values` |
| | `JsonSerializer.cpp:656` — same |
| | `JsonSerializer.cpp:515` — same, in `AsInt64` |
| | `JsonSerializer.cpp:502` — same, in `GetInt64`, which is the one generated code calls |
| `{"n":1.0e999}` | the same three sites, `inf is outside the range` |
| `{"n":1.5e300}` through `Document` | `Document.cpp:492` and `Document.cpp:519` |
| observed value | `AsInt64` returns `-9223372036854775808` |

**Note for anyone re-running this:** GCC does not include
`float-cast-overflow` in `-fsanitize=undefined`. Under plain `-fsanitize=undefined`
GCC reports nothing here and the run looks clean. `reproduce.sh` names the check
explicitly; clang includes it by default.

## J-3 — the kept literal is read with `atoll`

### The defect

```cpp
long long StringUtils::ConvertToInt64(const char* source)
{
    if(!source) { return 0; }
#ifdef __ANDROID__
    return atoll(source);
#else
    return std::atoll(source);
#endif // __ANDROID__
}
```

Two problems on a literal that came off the wire. `atoll` is undefined if the
value is not representable (C 7.22.1.2p3) — a 26-digit literal is not. And it
stops at the first character that cannot continue a decimal integer, which for
`1e300` is the `e`: the mantissa is returned and the exponent is silently
dropped.

`parse_number` keeps a literal for **any** number outside `[INT_MIN, INT_MAX]`
without a decimal point (`cJSON.cpp:399`). That range is `int`'s, not `int64`'s,
so the literal is kept for values `int64_t` represents exactly — and the
exponent form of one of those is where this stops being a precision complaint:

```
{"n":5e9}   AsInt64=5   GetInt64=5
```

Five billion — an unremarkable `ContentLength`, `CodeSize` or epoch-milliseconds
value — read back as **5**. The number is exactly representable, the SDK has the
literal in hand, and the answer is wrong by nine orders of magnitude.

### Evidence

| Input | `AsInt64` | `IsIntegerType` |
|---|---|---|
| `{"n":42}` | 42 | true |
| `{"n":9223372036854775807}` | 9223372036854775807 | true |
| `{"n":5e9}` | **5** | false |
| `{"n":1e300}` | **1** | false |
| `{"n":99999999999999999999999999}` | 9223372036854775807 (glibc saturates; the standard does not require it to) | true |

`GetInt64(key)`, which is what generated deserializers call, returns the same
values through its own copy of the branch (`JsonSerializer.cpp:502`).

No sanitizer fires on any of these: J-3 is a wrong answer, not a memory error.

## Symbolic confirmation (ESBMC)

### Configuration, and why each flag is there

| Flag | Why |
|---|---|
| `--std c++11` | the SDK's baseline, and the revision every paragraph number in this document is quoted from (N3337) |
| `--z3` / `--bitwuzla` | every row is run under both; agreement is required |
| `-D FIXED` | selects the patched conversion, for the second half of the pair |

Input model: `valuedouble` is a symbolic `double`, constrained only by
`__ESBMC_assume(d == d)` — JSON's grammar has no NaN literal, but it can spell
an infinity, as an exponent that overflows. Properties are stated with
`__ESBMC_assert` (`harnesses/json_number_esbmc.cpp`).

**Why the property is stated rather than inferred.** An out-of-range
floating-point to integer conversion is not one of ESBMC's checks:
`esbmc bare_conversion.c --overflow-check --nan-check` reports
`VERIFICATION SUCCESSFUL` on a bare `(long long)1e300`. The suite runs that case
as a check of its own, so the day ESBMC gains the check, the row fails and this
paragraph gets deleted. Reported upstream separately.

### Results

| Harness | Property | Verdict |
|---|---|---|
| pristine | `[conv.fpint]` the double is representable as `long long` | **FAILED** — Z3 and Bitwuzla |
| `-D FIXED` | the guard implies that precondition | SUCCESSFUL — Z3 and Bitwuzla |
| `-D FIXED` | below the range, saturates low | SUCCESSFUL — Z3 and Bitwuzla |
| `-D FIXED` | above the range, saturates high | SUCCESSFUL — Z3 and Bitwuzla |
| `-D FIXED -D EQUIVALENCE` | the patch's own `ToInt64Saturating` agrees with the model above, for every non-NaN double | SUCCESSFUL — Z3 and Bitwuzla |

### Fidelity of the model

The harness reasons about the conversion, not about `strtod`: it takes
`valuedouble` as an arbitrary double rather than deriving it from a literal.
That is the right abstraction for J-2 — the conversion's precondition depends on
the value and nothing else — and it is *not* a proof about the parser, which is
covered by the fuzz leg instead.

The other gap would be transcription: `JsonSerializer.cpp` is not in the
harness's translation unit, so the `-D FIXED` rows are about a restatement of the
fix rather than the fix itself. The `EQUIVALENCE` row closes that by carrying the
patch's `ToInt64Saturating` verbatim beside the model and asserting they agree.
Mutating the shipped copy's saturation branch breaks it, so the row has content.
Nothing here covers `LiteralToInt64`, which is exercised by the native witness
instead.

## Fuzzing — where the defects are not

The parser was fuzzed on the assumption that a hand-written C parser on the wire
path is where a memory-safety defect would be. It is not, and the negative
result is worth recording:

| Run | Result |
|---|---|
| 595,000 executions, ASan + UBSan, corpus seeded with AWS-shaped bodies | no crash, no diagnostic |
| coverage reached | 309 edges over parse / print / re-parse |
| `reproduce.sh fuzz` | 60,000 executions, bounded for reproducibility |

That is unsurprising in hindsight: upstream cJSON is continuously fuzzed by
OSS-Fuzz, and the fork tracks it closely. What upstream's fuzzing cannot cover is
the delta below, and the C++ layer above.

## The delta against upstream cJSON v1.7.19

Normalising the `cJSON_AS4CPP_` prefixes back makes the two files comparable:
101 changed lines. All of them fall into four groups.

| Group | What | Bearing on the findings |
|---|---|---|
| big-integer literals | `parse_number` keeps the literal, `print_number` prints it, `cJSON_CreateInt64` sets it | **the origin of all three findings** |
| hardening | `sprintf` → `snprintf`, `strcpy` → `memcpy` with explicit sizes | none — these are improvements |
| thread safety | the `global_error` position is no longer written or read ([PR #2231](https://github.com/aws/aws-sdk-cpp/pull/2231)) | none |
| build glue | include path, the `true`/`false` macros commented out | none |

We read the 101 lines and found no memory-safety drift: every place upstream
bounds a write, the fork bounds it the same way or more tightly. That reading is
a human judgement, not a checked property — so the leg pins the *content* of the
normalised diff by hash as well as its size, which is what forces the next drift
to be re-read rather than absorbed.

## Reachability

Enumerated over `aws/aws-sdk-cpp` at 1.11.886. This is the response path, so
unlike the earlier targets in this repository there is no "no untrusted input
reaches it" caveat to make — the input *is* the service's response body.

**J-2 and J-3 need no particular configuration.** Generated deserializers read
every `int64` model field through the defective accessor:

```cpp
    m_codeSize = jsonValue.GetInt64("CodeSize");
```

— `generated/src/aws-cpp-sdk-lambda/source/model/FunctionConfiguration.cpp:43`,
one of many. A service that returns such a field outside the `int64` range, or in
exponent form, gets the SDK to convert it out of range (J-2) or to drop the
exponent (J-3), on any build, with no logging enabled and no application
involvement.

**J-1 has one in-SDK path and it is conditional.** `JsonErrorMarshaller::Marshall`
parses the error body off the wire and prints it back:

```cpp
  auto exceptionPayload = GetJsonPayloadHttpResponse(httpResponse);
  auto payloadView = JsonView(exceptionPayload);
  ...
  if (exceptionPayload.WasParseSuccessful()) {
    AWS_LOGSTREAM_TRACE(AWS_ERROR_MARSHALLER_LOG_TAG, "Error response is " << payloadView.WriteReadable());
```

— `source/client/AWSErrorMarshaller.cpp:45-59`. `AWS_LOGSTREAM_TRACE` expands to
a level-guarded block (`LogMacros.h`: `if (logSystem && logSystem->GetLogLevel() >= level)`),
so the call is made only when trace logging is on. With it on, an error body
carrying a 26-character number aborts the process.

Beyond that, `WriteCompact` and `WriteReadable` are public API applied to
response-derived documents by applications and by every service model whose
members are `Aws::Utils::Document`.

**Not established:** we did not enumerate which services can actually emit a
26-character number or an out-of-range `int64` in a given field. The SDK's
behaviour is determined by the bytes on the connection, and a compromised or
hostile endpoint is the threat model these findings are stated under, as it was
for the Base64 defects.

## Suggested fix

`fix/json-number-range-and-print.patch`, 17 hunks across four files:

```c
-        length = snprintf((char*)number_buffer, sizeof(number_buffer), "%s", item->valuestring);
+        const size_t literal_length = strlen(item->valuestring);
+        output_pointer = ensure(output_buffer, literal_length + sizeof(""));
+        ...
+        memcpy(output_pointer, item->valuestring, literal_length + sizeof(""));
```
```cpp
-        return static_cast<int64_t>(m_value->valuedouble);
+        return ToInt64Saturating(m_value->valuedouble);
```
```cpp
+    if (!temp)
+    {
+        AWS_LOGSTREAM_ERROR("JsonView", "Failed to print JSON document");
+        return {};
+    }
     Aws::String out(temp);
```

- **cJSON.cpp** prints a kept literal straight into the output buffer, which
  `ensure` sizes for it, instead of through the 26-byte stack buffer. The literal
  never contains a decimal point — `parse_number` only keeps it when there is
  none — so it needs no locale translation. This removes J-1 at its source: the
  document round-trips instead of failing to print.
- **JsonSerializer.cpp** and **Document.cpp** gain one file-local helper each:
  `ToInt64Saturating`, which clamps outside the representable range the way cJSON
  already clamps `valueint`, and `LiteralToInt64`, which returns `strtoll`'s
  answer when it consumed the whole literal — including `strtoll`'s own
  saturation, which is exact — and otherwise falls back to the saturating
  conversion. That is what turns `5e9` from `5` into `5000000000` and `1e300`
  from `1` into `INT64_MAX`. The two predicates test representability before
  converting. The writers log at ERROR and return an **empty** string when the
  printer fails, rather than the `"{}"`/`"null"` each returns for an empty
  document; see below.
- **StringUtils.cpp** replaces `atoll`/`atol` with `strtoll`/`strtol`, which are
  defined on overflow. Reached from JSON via `AsInt64`, and from other callers.
  The `__ANDROID__` arm goes with it: it existed to avoid `std::atoll` on old
  bionic, and both arms would otherwise call the same function.

After the patch: all six response bodies read back with no diagnostic under ASan
and UBSan, none aborts, the 26-digit literal survives the round trip, and the
guarded conversion is SUCCESSFUL under both solvers.

### Why the writers return an empty string

`View().WriteReadable()` is the whole body of `SerializePayload()` in every
generated request class — `return payload.View().WriteReadable();`,
`PutItemRequest.cpp` and thousands like it. Anything the writers return on
failure is what the SDK will send. Returning `"{}"` there would make a failed
print indistinguishable from a document the caller left empty, and the service
would accept it: a silently wrong API call in place of an abort. An empty body is
rejected by the service, and the ERROR log says why. The request path cannot
reach the failure after the cJSON fix — a literal built by `cJSON_CreateInt64`
is at most 20 characters — so this governs allocation failure and any future
printer error, not J-1 itself.

### What the patch does not do

- **It does not make an out-of-range number an error.** Saturation is a choice,
  and it is the one cJSON already makes for `valueint`. An API that could report
  "this number does not fit" would be better, and would be a breaking change.
- **It does not touch `AsDouble`.** `1.0e999` still reads back as `inf`, and
  still prints as `null`; that is upstream cJSON's behaviour for a
  non-finite double and is out of scope here.
- **It does not add a length limit to `parse_number`.** A response can still make
  the parser allocate a literal as long as the number it sends. That is bounded
  by the response body itself.
- **It does not touch `cJSON_AS4CPP_SetNumberHelper`** (`cJSON.cpp:427`), which
  updates `valuedouble` and `valueint` without clearing `valuestring`. An item
  parsed from a big-integer literal and then reset through `cJSON_SetNumberValue`
  prints its stale literal. That is the fork's, not the patch's — but the patch
  does change its symptom, since the stale literal now prints instead of failing
  the document. No in-SDK caller does this; reported here so a reviewer does not
  find it and wonder whether it was missed.

## Not claimed

- **No memory corruption.** Nothing here reads or writes out of bounds: the
  `snprintf` guard holds, and ASan is silent on every input. J-1 is a null
  pointer handed to a string constructor — a thrown `logic_error` on libstdc++,
  undefined behaviour in general, and an abort either way.
- **No exploit.** J-2's conversion yields a garbage value on the platforms we
  ran; what an application does with a garbage length or count is its own
  question and we did not investigate it.
- **Nothing about the other protocols.** The XML, CBOR and query paths were not
  analysed. `CborValue` reads response bodies through a different parser
  entirely.
- **Not a regression.** The literal-keeping feature is present at 1.11.0 and
  absent at 1.9.99, so it predates every release this exercise has looked at.
- **The fuzzing bound is a bound.** 595k executions over one entry point is not a
  proof of the parser's memory safety; it is the reason this report does not
  claim a defect there.

## Reproducing

```sh
./reproduce.sh              # 55 checks, ~25 s
./reproduce.sh sanitizer    # or one leg at a time: sanitizer, esbmc, fuzz,
                            # delta, reachability, fix
```

Everything the sanitizers, ESBMC and libFuzzer analyse is byte-for-byte upstream
1.11.886, pinned by `vendor/UPSTREAM_VERSION` and `vendor/UPSTREAM_COMMIT` and
re-checked file by file — all 25 — against `raw.githubusercontent.com` by the
reachability leg, which fetches by commit rather than by the movable tag.
`reference/` holds upstream cJSON v1.7.19 for the delta leg, and `stubs/` only
verification-only substitutes, each documenting what it stands in for.

Findings generated with AI tools and reviewed by Lucas Cordeiro, University of
Manchester.
