# aws-sdk-cpp
AWS SDK for C++

Formal verification of the SDK's hand-written parsers and codecs with
[ESBMC](https://github.com/esbmc/esbmc). Each defect is found as a property
violation over symbolic input, and ESBMC's counterexamples are replayed against
the pristine SDK under ASan and UBSan.

| Component | Defect | Impact | Status | Details |
|---|---|---|---|---|
| `Base64::Decode` | Heap overflow (write) and out-of-bounds read | Memory corruption | [CVE-2026-19642](https://github.com/aws/aws-sdk-cpp/security/advisories/GHSA-wxx3-prfc-69xx), [CVE-2026-19643](https://github.com/aws/aws-sdk-cpp/security/advisories/GHSA-mxm9-xpf9-x66x); fixed in [1.11.862](https://github.com/aws/aws-sdk-cpp/releases/tag/1.11.862) | [verification/](verification/) |
| `UUID(const Aws::String&)` | Heap overflow on over-long input | Latent; no untrusted caller | Public hardening finding | [verification/uuid/](verification/uuid/) |
| `DateTime` parsers | Signed and `time_point` overflow; dates after 2262 parse as 1816 | Wrong timestamps, UB | Fixed in [1.11.877](https://github.com/aws/aws-sdk-cpp/releases/tag/1.11.877) ([PR #3896](https://github.com/aws/aws-sdk-cpp/pull/3896)), includes our patch | [verification/datetime/](verification/datetime/) |
| `HashingUtils::HexDecode` | Accepts non-hex letters; `"K1"` decodes as `"41"` | Distinct UUID strings alias | Public hardening finding | [verification/hex/](verification/hex/) |
| `SimpleStreamBuf`, `PreallocatedStreamBuf` | Inverted get area; wrong end-relative seeks | SIGSEGV in release builds | Public hardening finding | [verification/streambuf/](verification/streambuf/) |
| JSON number path | Null-pointer abort on long numbers; UB in `double`→`int64`; `{"n":5e9}` reads as `5` | Process abort and wrong values from any response body | Fixed in [1.11.891](https://github.com/aws/aws-sdk-cpp/releases/tag/1.11.891) ([PR #3921](https://github.com/aws/aws-sdk-cpp/pull/3921)), our patch | [verification/cjson/](verification/cjson/) |

The Base64, DateTime and JSON defects went to AWS Security under coordinated
disclosure. The Base64 defects are covered by
[Security Bulletin 2026-080-AWS](https://aws.amazon.com/security/security-bulletins/2026-080-aws/).
AWS fixed the JSON defects in 1.11.891 and assessed them as out of scope for a
CVE: the abort needs existing control of the service endpoint or the TLS
connection, and the other two are correctness defects. The
[release notes](https://github.com/aws/aws-sdk-cpp/releases/tag/1.11.891)
acknowledge the report. The others are latent
bugs in public API with no untrusted caller, published directly with a patch.

Each directory has a `README.md` and a `REPORT.md` with the full analysis, plus
a `reproduce.sh` or `Makefile` that reruns its checks.

A short write-up of the exercise was
[posted on 2026-08-13](https://www.linkedin.com/posts/lucas-cordeiro-3156233_formalverification-memorysafety-esbmc-share-7493503595426963457-OZeH/),
with AWS's permission.
