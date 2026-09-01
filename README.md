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

A short public write-up of the exercise was
[posted on 2026-08-13](https://www.linkedin.com/posts/lucas-cordeiro-3156233_formalverification-memorysafety-esbmc-share-7493503595426963457-OZeH/),
with AWS's permission.
