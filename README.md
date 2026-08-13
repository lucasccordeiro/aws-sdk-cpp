# aws-sdk-cpp
AWS SDK for C++

Working tree for a formal-verification exercise against the SDK's hand-written
codecs. The harnesses, the findings and the ESBMC record are under
[verification/](verification/).

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

A short public write-up of the exercise was
[posted on 2026-08-13](https://www.linkedin.com/posts/lucas-cordeiro-3156233_formalverification-memorysafety-esbmc-share-7493503595426963457-OZeH/),
with AWS's permission.
