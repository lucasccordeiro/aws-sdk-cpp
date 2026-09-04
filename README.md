# aws-sdk-cpp
AWS SDK for C++

Working tree for a formal-verification exercise against the SDK's hand-written
codecs and timestamp parsers. The harnesses, the findings and the ESBMC record
are under [verification/](verification/).

Two memory-safety defects in `Aws::Utils::Base64::Base64::Decode` were found and
confirmed here, reported to AWS Security on 2026-07-29, and published on
2026-08-12 as
[CVE-2026-19642](https://github.com/aws/aws-sdk-cpp/security/advisories/GHSA-wxx3-prfc-69xx)
(heap buffer overflow, write) and
[CVE-2026-19643](https://github.com/aws/aws-sdk-cpp/security/advisories/GHSA-mxm9-xpf9-x66x)
(out-of-bounds read), and covered by
[Security Bulletin 2026-080-AWS](https://aws.amazon.com/security/security-bulletins/2026-080-aws/).
Both affect `<= 1.11.861` and are fixed in
**[1.11.862](https://github.com/aws/aws-sdk-cpp/releases/tag/1.11.862)**.

Two integer-overflow defects in `Aws::Utils::DateTime`'s timestamp parsers were
found the same way and reported on 2026-08-18. AWS fixed both in
[PR #3896](https://github.com/aws/aws-sdk-cpp/pull/3896), merged 2026-08-24 and
first tagged in
**[1.11.877](https://github.com/aws/aws-sdk-cpp/releases/tag/1.11.877)**, taking
our field-width patch verbatim and adding a range check of its own. These went
out as a defense-in-depth change with no CVE — neither is memory corruption. See
[verification/datetime/](verification/datetime/).

`Aws::Utils::HashingUtils::HexDecode` was examined the same way and does not
validate its input: the character guard admits every letter rather than the hex
digits, and reports a failure only through an `assert`. Malformed strings decode
to full-length buffers, and distinct strings alias to the same bytes — `"K1"`
decodes to the byte `"41"` decodes to. Through the one public API that hands it
a caller-supplied string, `UUID(const Aws::String&)`, that means
`550e8400-e29b-K1d4-a716-446655440000` parses to the bytes of
`550e8400-e29b-41d4-a716-446655440000` and renders as it, in release and debug
builds alike, with ASan and UBSan silent. There is no memory-safety consequence
and no untrusted caller inside the SDK, so this is a latent hardening bug in
public API rather than a security report. A patch and the proofs are in
[verification/hex/](verification/hex/).

Two of the SDK's hand-written stream buffers were examined next, at 1.11.884, and
carry three defects between them. `SimpleStreamBuf` re-points the end of its get
area at the put pointer even when that is behind the read position — in
`underflow` and again in `xsputn` — so an ordinary write / read / `seekp`
backwards / read sequence hands `setg` an inverted range and the next read
`memcpy`s a negative length —
`negative-size-param: (size=-41)` under ASan, and SIGSEGV in a stock release
build. Both buffers also subtract the offset on end-relative seeks where the
standard adds it, so `seekg(-3, end)` fails while `seekg(+3, end)` succeeds
inside the buffer, and both report success from a `pubseekpos` that moves no
pointer at all. Nothing untrusted reaches any of them and no in-SDK caller
performs the seeks the last two need, so these are again defects in public API —
with the difference that the first one is memory corruption. A patch and the
proofs are in [verification/streambuf/](verification/streambuf/).

The JSON number path was examined next, at 1.11.886, and this time the target was
chosen for reachability: it is what every JSON-protocol response body goes
through. The vendored cJSON parser itself came out clean — 595k libFuzzer
executions under ASan and UBSan found nothing, and the fork carries no
memory-safety drift from upstream v1.7.19 — but the feature AWS added on top of
it does not survive contact with the rest of the code. `parse_number` keeps a
big integer's literal in `valuestring`, a field the printer assumes is short and
the wrapper assumes belongs to a string: a response number of 26 or more
characters makes `cJSON_AS4CPP_Print` fail, and `JsonView::WriteCompact` then
builds an `Aws::String` from the null pointer it returns — `std::logic_error`,
process abort. Inside the SDK that one needs trace logging on, since the error
marshaller's call to it sits in `AWS_LOGSTREAM_TRACE`; it is unconditional for an
application that prints a document it received. Separately, four sites convert
the parsed `double` to a 64-bit integer with no range check, which is undefined
for `{"n":1.5e300}` and for the `inf` that `{"n":1.0e999}` parses to, and the
kept literal is read back with `atoll`, which stops at the exponent — so
`{"n":5e9}` reads as `5`, nine orders of magnitude off a value `int64` holds
exactly. Generated deserializers reach the last two on every `int64` field, with
no logging and no application involvement. A patch and
the proofs are in [verification/cjson/](verification/cjson/).

A short public write-up of the exercise was
[posted on 2026-08-13](https://www.linkedin.com/posts/lucas-cordeiro-3156233_formalverification-memorysafety-esbmc-share-7493503595426963457-OZeH/),
with AWS's permission.
