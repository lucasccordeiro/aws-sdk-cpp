# ESBMC vs. the SDK's JSON number path — findings

**Target:** `aws/aws-sdk-cpp` @ `31583cee6ed69015a7e63fefae5b931ae9f3196e`
(v1.11.886, the current release at the time of writing)
**Code under analysis:** the vendored cJSON fork's number handling —
`parse_number` and `print_number`
(`src/aws-cpp-sdk-core/source/external/cjson/cJSON.cpp:314-424,607-675`) — and the
C++ accessors layered over it:
`Aws::Utils::Json::JsonView::{GetInt64,AsInt64,IsIntegerType,IsFloatingPointType,WriteCompact,WriteReadable}`
(`.../source/utils/json/JsonSerializer.cpp:491-517,629-657,669-701`) and the
identical members of `Aws::Utils::DocumentView` (`.../source/utils/Document.cpp`)
**Method:** ESBMC 8.5.0 under both Bitwuzla and Z3 states each defect as a
property over symbolic input and refutes it; its test-case generator turns the
counterexamples into executable tests; those run against the pristine sources
under GCC and clang with AddressSanitizer and UBSan. libFuzzer covers the parser
separately.
**Status:** three defects, all on the path a **service response body** takes into
an application, one of them a **regression first shipped in 1.11.660**. The
parser itself is not one of them: 595k libFuzzer executions over parse / print /
re-parse under ASan and UBSan found nothing, and the fork carries no
memory-safety drift from upstream cJSON v1.7.19. All three grow out of
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
| **J-1** | `WriteCompact`/`WriteReadable` build `Aws::String` from whatever `cJSON_AS4CPP_Print*` returns, with no null check (`JsonSerializer.cpp:680,697`; `Document.cpp:655,668`) — and `print_number`'s 26-byte buffer cannot hold a longer literal, so the whole document fails to print | `std::logic_error`, **process abort** (exit 134) | a response number of 26 or more characters, written without a decimal point |
| **J-2** | `static_cast<long long>(valuedouble)` with no range check, at four sites in each of the two files (`JsonSerializer.cpp:502,515,641,656`; `Document.cpp:492,506,519,549`) | undefined behaviour, [conv.fpint]/1; in practice a garbage value — `INT64_MIN` on x86-64 | any response number outside the `int64` range written with a decimal point, e.g. `1.5e300`, or `inf` from `1.0e999` |
| **J-3** | the kept literal is read with `std::atoll` (`StringUtils.cpp:337-349`), which stops at the exponent and is undefined on overflow (C11 7.22.1p1) | **`{"n":5e9}` reads back as `5`**, since 1.11.660 | any integer written in exponent form, in range or not |

J-1 aborts. J-2 and J-3 are wrong answers, one of them undefined.

The three are independent, and none of them needs a malformed document: every
input below is well-formed JSON that a service is free to return.

## ESBMC finds all three, from symbolic input alone

Each defect is stated as a property over symbolic input and handed to ESBMC. No
harness names a triggering value — the length, the double, the mantissa and the
exponent are all free — so the concrete numbers below are the solver's, not ours.
Every row is run under both Bitwuzla and Z3, and agreement is required.

| Harness | Property | Free variable | Verdict |
|---|---|---|---|
| `json_print_esbmc.cpp` | J-1 — the pointer `Aws::String` receives is not null | the literal's length, 1..40 | **FAILED** |
| `json_print_esbmc.cpp -D BOUNDED` | the same, for 25 characters or fewer | length, 1..25 | SUCCESSFUL |
| `json_number_esbmc.cpp` | J-2 — [conv.fpint]/1: the double is representable as `long long` | the `double`, any non-NaN | **FAILED** |
| `json_literal_esbmc.cpp` | J-3 — the accessor returns the value the kept literal denotes | mantissa 1..9, exponent 1..18 | **FAILED** |
| `-D FIXED`, all three | the patched code satisfies each property | as above | SUCCESSFUL |

No witness is quoted in that table on purpose. The two solvers agree on the
verdict, which is what the suite asserts, and not on the violating input, which
it never does — that is the solver's own choice and varies with the encoding and
between runs. Concrete values belong to the next section, where the generator is
asked for one per region and the suite pins the *behaviour* each produces.

`-D BOUNDED` is the row that makes J-1's boundary a boundary rather than a
complaint: without it, a printer that rejected *every* literal would satisfy the
FAILED row just as well. Shrinking the modelled buffer from 26 bytes to 20 breaks
it, so it is not decoration.

### Configuration, and why each flag is there

| Flag | Why |
|---|---|
| `--std c++11` | the SDK's baseline, and the revision every paragraph number in this document is quoted from (N3337) |
| `--z3` / `--bitwuzla` | every row is run under both; agreement is required |
| `--unwind 45` (J-1) | clears the longest literal the harness can build, so every unwinding assertion is reported PASSED |
| `--unwind 10 --array-flattener` (J-3) | `atoll`'s digit map is a 256-entry array indexed by a symbolic character. Under Z3's array theory that row takes over two minutes; flattened, seven seconds. Bitwuzla is fast either way and agrees with both encodings. |
| `-D FIXED` | selects the patched code, for the second half of each pair |

### What ESBMC supplies, and what had to be transcribed

The J-3 harness calls `atoll` and lets ESBMC supply it, from
`src/c2goto/library/stdlib.c`'s `ATOI_DEF` — C11 7.22.1.2p2's "equivalent to
`strtoll(nptr, NULL, 10)`", stopping at the first character that cannot continue
the subject sequence (7.22.1.4p4). That last clause *is* J-3, so the defect is
found in the library model rather than asserted by us. The patched row likewise
uses ESBMC's own `strtoll`, including its saturation.

The other two harnesses transcribe the code under analysis, for reasons worth
recording because they are limitations of the tool rather than choices:

* **ESBMC 8.5.0 does not finish on the vendored `cJSON.cpp`.** Its `memset` and
  `memcpy` models unwind once per byte, and `print`'s 256-byte buffer alone puts
  the run past any bound this suite could wait for — measured: no verdict in
  110 s at `--unwind` 32, 40 or 70, on a harness that only prints one object.
* **Passing `cJSON.cpp` as a second C++ translation unit is worse than slow.**
  The frontend drops its function bodies without a diagnostic; a call to
  `cJSON_AS4CPP_Parse` then returns nondeterministically, and *every* property
  "fails" for a reason that has nothing to do with the code. `esbmc a.cpp b.cpp`
  links correctly on a two-file toy, so this is specific to something in this
  file — but the silence is the hazard. A run that fails for this reason looks
  exactly like a run that found a defect.
* **ESBMC's `snprintf` model does not return the length it would have written**
  (C11 7.21.6.5p3). `print_number`'s guard is written against that return value,
  so the harness substitutes `strlen`, which is what the standard defines the
  call to return here.
* **ESBMC's C++ frontend rejects `StringUtils.cpp`** — its `std::string`
  operational model has no `rbegin`/`rend`, and `::isspace` is not in the global
  namespace. `ConvertToInt64`'s body is one line, quoted in the harness, and its
  callee analysed directly.
* **An out-of-range floating-point to integer conversion is not one of ESBMC's
  checks.** `esbmc bare_conversion.c --overflow-check --nan-check` reports
  `VERIFICATION SUCCESSFUL` on a bare `(long long)1e300`, so the J-2 harness
  states [conv.fpint]/1's precondition itself. The suite runs that case as a
  check of its own, so the day ESBMC gains the check, the row fails and this
  bullet gets deleted.

So the honest summary of the modelling: J-3's defect is found in code ESBMC
supplies; J-1's and J-2's are found in a transcription of the SDK's own
statements, quoted line by line in the harness headers. The gap that closes is
the next section — the counterexamples are executed against the real accessors,
which is where a transcription that lied would show up.

### The `-D FIXED` rows are about a restatement of the patch

The same gap runs the other way, and the counterexamples do not close it. None of
the four modules is in a harness's translation unit, so a `-D FIXED` row says the
patched *logic* satisfies the property, not that the shipped patch does. One row
narrows that by a level: `-D FIXED -D EQUIVALENCE` carries a hand-transcription of
the patch's `ToInt64Saturating` — `long long` for `int64_t`, integer literals for
`std::numeric_limits` — beside the model and asserts the two agree for every
non-NaN double. Mutating *that copy* breaks the row; mutating the copy the patch
actually ships does not, because nothing feeds `fix/` to ESBMC. What catches a
mutation of the shipped helper is the native fix leg, which builds the patched
tree and checks its answers, and the counterexample replays, which link the
patched modules. `LiteralToInt64` and the `cJSON.cpp` hunk are covered by those
two alone.

## Executable counterexamples, run against the SDK

A `VERIFICATION FAILED` verdict says a violating input exists; it does not hand
anyone a test they can run. ESBMC's test-case generation does
([docs](https://esbmc.github.io/docs/c-cpp/ctest-gen/)):

```sh
esbmc harnesses/json_print_ctest.cpp --std c++11 --branch-coverage \
      --generate-ctest-testcase --ctest-output-dir results/esbmc-ctest-print
```

Each `*_ctest.cpp` splits its harness's input into the regions the defect's
condition distinguishes, so covering every branch forces the solver to name a
concrete value in each. All three report `Branch Coverage: 100%` and write
`test_case_N.cpp`, each a compilable `__VERIFIER_nondet_*` body.

The generated `CMakeLists.txt` would rebuild the *harness* with those values,
which only re-runs the model. Each `*_replay.cpp` links the generated
`__VERIFIER_nondet_*` against the **real** `JsonSerializer.cpp` and
`Document.cpp` instead, renders the value as a response body and reads it back
the way a generated deserializer does — under ASan and UBSan. On our runs:

| Defect | Witness ESBMC chose | Region | On the pristine SDK |
|---|---|---|---|
| J-1 | 28 digits | past the printer's buffer | **SIGABRT** — `basic_string: construction from null is not valid` |
| J-1 | 10 digits | inside it | round-trips |
| J-2 | `9.2233720368547759e+18` (2^63) | above the range | undefined — `:502`, `:515`, `:641`, `:656`, `Document.cpp:519` |
| J-2 | `1.0261342003245943e-289` | representable | defined; reads back as `0` |
| J-2 | `-1.8446744073709555e+19` (≈ −2^64) | below the range | undefined — the same sites |
| J-3 | `4e11` | the parser keeps the literal | **reads back as `4`** |
| J-3 | `4e3` | in exponent form, but too small to keep a literal | exact |
| J-3 | `4` | no exponent | exact |

ESBMC picked 2^63 for J-2 with nothing to go on but the branch condition — the
same boundary the hand analysis below arrives at, reached independently. Under
the patch all eight are clean, and the suite checks that as presence of an
answer rather than absence of a crash — on both sides, since a binary that
printed nothing is also a binary with no diagnostic. Pristine and patched alike,
all three J-2 witnesses must read a value; under the patch both J-1 witnesses
must print their document back and all three J-3 witnesses must read back
exactly.

Two guards keep the replays honest. The J-2 driver checks that its rendered text
parses back bit-identical to the double the solver chose before trusting the
replay — rendering with `%.6g` instead makes that check fire. The J-3 driver
recomputes the expected value from the mantissa and exponent itself rather than
taking it from the harness, so the two arrive at it independently. Which witness
lands in which region is the solver's choice, so each leg counts outcomes rather
than assuming an order.

**Scope.** This is all three defects, executed. What it is not is a proof about
the parser: every harness starts from the value or the literal `parse_number`
produces, and takes for granted that a response body can produce it. The native
witness table below closes that by going in through `JsonValue`'s string
constructor, and the fuzz leg covers the parser itself.

---

## The three defects in detail

What follows is each defect on its own terms — the code, the standard's words,
and the fifteen-body witness table that the `sanitizer` leg runs over both
accessors. It is the same three findings the two sections above state and refute.
The inputs here were chosen by hand rather than by the solver, and go further
into each defect's behaviour than a counterexample needs to; where the two
coincide, as they do at 2^63, they were arrived at independently.

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

Four sites in each of the two files read `valuedouble` straight into a 64-bit
integer:

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
| `{"n":1.0e999}` | the same four sites, `inf is outside the range` |
| `{"n":1.5e300}` through `Document` | `Document.cpp:492`, `:506`, `:519` and `:549` |
| observed value | `AsInt64` returns `-9223372036854775808` |
| `{"n":9223372036854775808.0}` — exactly 2^63 | the same four sites; a **positive** wire value reads back as `-9223372036854775808` |
| `{"n":-9223372036854775808.0}` — exactly −2^63 | clean, and exact |

The last two rows are the boundary. 2^63 is the smallest double outside
`int64`'s range, so the defect does not need an absurd magnitude; −2^63 *is*
representable, because the range is asymmetric. Any fix has to saturate the first
and not the second, which rules out the guard one would write first:
`d <= (double)INT64_MAX` is `d <= 2^63` after the conversion rounds up, and it
admits exactly the value that is still undefined.

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
value is not representable (C11 7.22.1p1, "If the value of the result cannot be
represented, the behavior is undefined") — a 26-digit literal is not. And it
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

### When it started

Until 1.11.659 the guard was `isInteger`, and `isInteger` was cleared on `e`/`E`
as well as on `.`, so an exponent form kept **no literal at all**: `valuestring`
was null, `AsInt64` took the double branch, and the answer was right. Commit
[`87042947e93a`](https://github.com/aws/aws-sdk-cpp/commit/87042947e93a)
("update cjson dep to 1.7.19", 2025-09-30) replaced the flag with
`has_decimal_point`, which only `.` sets:

```diff
-    bool isInteger = true;
+    cJSON_AS4CPP_bool has_decimal_point = false;
             case 'e':
             case 'E':
-                isInteger = false;      /* the arm that no longer exists */
             case '.':
-                isInteger = false;
+                has_decimal_point = true;
-    if (isInteger && (number > INT_MAX || number < INT_MIN))
+    if (!has_decimal_point && (number > INT_MAX || number < INT_MIN))
```

`JsonView::AsInt64` is byte-identical across the change, so the parser's decision
to keep the literal is the whole of the difference. Built against each release's
own `cJSON.cpp`, driving the accessor's exact branch:

| Release | `valuestring` for `{"n":5e9}` | `AsInt64` |
|---|---|---|
| 1.11.659 | none | **5000000000** — correct |
| 1.11.660 | `5e9` | **5** |

By tag bisection 1.11.659 is the last release without the defect and 1.11.660
(2025-10-01) the first with it.

The same change reshapes J-2 rather than causing it: at 1.11.659 `{"n":1e300}`
had no literal either, so it reached the unguarded conversion and was undefined
(observed `INT64_MIN`); at 1.11.886 it takes the literal path and reads `1`. The
defect moved, it did not close.

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
  defined on overflow. `ConvertToInt64` is reached from JSON through `AsInt64`
  and from other callers besides. The `__ANDROID__` arm goes with it: it existed
  to avoid `std::atoll` on old bionic, and both arms would otherwise call the
  same function.

The two helpers are duplicated into `JsonSerializer.cpp` and `Document.cpp`
rather than shared through a header, because `Document.cpp` already carries its
own copy of every accessor body the patch touches; a shared internal header would
be the cleaner shape and a wider change than this patch.

After the patch: all fifteen response bodies read back with no diagnostic under
ASan and UBSan, through `JsonValue` and through `Document`, none aborts, the
26-digit literal survives the round trip, the boundary saturates on one side and
stays exact on the other, and the guarded conversion is SUCCESSFUL under both
solvers. Mutating the guard to `d <= (double)INT64_MAX` reintroduces the 2^63
diagnostic and fails the suite, so those rows are not decoration.

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
- **It does not reconcile the predicates with the value.** `IsIntegerType` and
  `IsFloatingPointType` keep their unchanged `valuestring` branch, which
  classifies any literal containing `e` as non-integer; the patch adds the range
  test only to the `valuedouble` branch. So after the fix `{"n":5e9}` reports
  `IsIntegerType() == false` while `AsInt64()` returns the exact `5000000000`,
  and the 26-digit case reports `true` while the value saturates. Before the fix
  the two agreed by both being wrong. Reconciling them would change what
  `IsIntegerType` means for a literal, which is a wider change than this patch.
- **It does not touch `cJSON_AS4CPP_SetNumberHelper`** (`cJSON.cpp:427`), which
  updates `valuedouble` and `valueint` without clearing `valuestring`. An item
  parsed from a big-integer literal and then reset through `cJSON_SetNumberValue`
  prints its stale literal. That is the fork's, not the patch's. The patch changes
  the symptom only for a stale literal of 26 or more characters, which needs a
  parsed big literal followed by `cJSON_SetNumberValue` — `cJSON_AS4CPP_CreateInt64`
  caps at 20 (`char buf[21]`, `%lld`). Shorter stale literals printed before the
  patch too. No in-SDK caller does this; reported here so a reviewer does not
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
- **J-1 and J-2 are not regressions. J-3 is.** The literal-keeping feature is
  already present at 1.9.99
  (`aws-cpp-sdk-core/source/external/cjson/cJSON.cpp:361-366`, before the tree
  moved under `src/`), so J-1 and J-2 predate every release this exercise has
  looked at. J-3's exponent-form corruption does not — it was introduced by
  `87042947e93a` and first shipped in **1.11.660**; see *When it started*.
- **The fuzzing bound is a bound.** 595k executions over one entry point is not a
  proof of the parser's memory safety; it is the reason this report does not
  claim a defect there.
- **The proofs are bounded, and they are about models.** Each ESBMC row holds
  over the range its harness constrains — a literal of at most 40 characters, an
  exponent of at most 18 — not over every input a response can carry. And with
  the exception of J-3's `atoll`, which ESBMC supplies, the code each row reasons
  about is a transcription of the SDK's statements rather than the SDK's own
  translation units; the reasons are in *What ESBMC supplies, and what had to be
  transcribed*. The executed counterexamples are what makes the transcriptions
  answerable: those run against the real modules.

## Reproducing

```sh
./reproduce.sh              # 107 checks, ~5 min
./reproduce.sh esbmc        # or one leg at a time, in the order they run:
                            # esbmc, ctest, sanitizer, fuzz, delta,
                            # reachability, fix
```

Everything the sanitizers, ESBMC and libFuzzer analyse is byte-for-byte upstream
1.11.886, pinned by `vendor/UPSTREAM_VERSION` and `vendor/UPSTREAM_COMMIT` and
re-checked file by file — all 25 — against `raw.githubusercontent.com` by the
reachability leg, which fetches by commit rather than by the movable tag.
`reference/` holds upstream cJSON v1.7.19 for the delta leg, and `stubs/` only
verification-only substitutes, each documenting what it stands in for.

Findings generated with AI tools and reviewed by Lucas Cordeiro, University of
Manchester.
