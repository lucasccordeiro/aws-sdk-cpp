# Public-exposure record for the `Base64::Decode` disclosure

Snapshot of GitHub's traffic API for `lucasccordeiro/aws-sdk-cpp`, captured
**2026-07-29**, immediately after the repository was set to private at AWS
Security's request.

## Why this exists

The repository was public from **2026-07-18 to 2026-07-29** (~11 days). During
that window `verification/REPORT.md` carried the analysis of the two
`Base64::Decode` memory-safety defects, and
`verification/harnesses/base64_decode_asan.cpp` carried a working
AddressSanitizer reproducer.

GitHub's traffic API retains only **14 days**. These files are therefore the
only durable record of who fetched that content while it was public — the
2026-07-18..20 activity below rolls out of the API within days of capture and
cannot be re-queried. A copy is also held outside this repository, since this
branch is scheduled for deletion (see the caveat at the bottom).

## Files

| File | API endpoint |
|---|---|
| `traffic-clones-2026-07-29.json` | `/repos/{owner}/{repo}/traffic/clones` |
| `traffic-views-2026-07-29.json` | `/repos/{owner}/{repo}/traffic/views` |
| `traffic-paths-2026-07-29.json` | `/repos/{owner}/{repo}/traffic/popular/paths` |
| `traffic-referrers-2026-07-29.json` | `/repos/{owner}/{repo}/traffic/popular/referrers` |

## What the data shows

Facts, as reported by GitHub:

- **72 clones from 58 unique sources**, concentrated immediately after the
  repository was created: 11 clones (11 unique) on 18 Jul, 33 (25 unique) on
  19 Jul, 16 (15 unique) on 20 Jul, then a tail in the low single digits.
- **38 page views from 3 unique visitors** over the same period.
- **One referrer**: `github.com`, 22 hits, 1 unique.
- Most-viewed path was `blob/main/verification/REPORT.md` (10 views, 1 unique);
  the remainder are the repository overview, the `verification/` tree, and the
  project's own pull requests, each at 1-2 uniques.

## Interpretation — inference, not fact

The asymmetry between 58 unique cloners and 3 unique page viewers, the absence
of any external referrer, and the spike beginning the day the repository was
created together resemble automated collection from GitHub's public events
feed rather than targeted human interest. The path and referrer data suggest
the page views were the repository owner.

This is not established. **GitHub does not identify who clones a repository**,
so the 58 sources cannot be attributed, and this record should not be read as
evidence that no human obtained the reproducer.

The inference also does not reduce the exposure. If mirroring services, code
search indexers, or security scanners were among those 58, the reproducer may
persist in third-party indexes that making this repository private does not
reach.

## Caveat

This file sits on `docs/base64-reachability`, which **must be deleted from the
remote before this repository is ever made public again** — that branch also
carries the withheld reachability analysis. Preserve the copy held outside the
repository before deleting.
