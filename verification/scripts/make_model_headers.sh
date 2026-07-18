#!/usr/bin/env bash
#
# Generate the model header tree used by the ESBMC harnesses.
#
# Everything under vendor/ is pristine upstream aws-sdk-cpp and is NEVER edited
# by hand. This script mechanically derives model/ from it, so the delta between
# what upstream ships and what ESBMC actually sees is one reviewable diff
# (`diff -u vendor/include/... model/include/...`) rather than a hand-maintained
# fork.
#
# Currently one transformation is applied:
#
#   Array.h: drop the CryptoBuffer class.
#
#     Why: ESBMC 8.4.0 aborts during GOTO conversion (SIGABRT, "Fatal glibc
#     error: pthread_mutex_lock ... assertion failed: e != ESRCH || !robust")
#     on merely *including* the definition of CryptoBuffer -- no code in main()
#     is required. Truncating the header before CryptoBuffer makes the same
#     input convert and verify. See esbmc_bug_repros/ for the reduced case.
#
#     Why this does not weaken the result: CryptoBuffer is not in the call
#     graph of anything under analysis. Base64::Encode/Decode and the hex codec
#     traffic exclusively in ByteBuffer (= Array<unsigned char>), which is kept
#     byte-for-byte. CryptoBuffer only adds a zeroing destructor and CRT
#     move-interop on top. Removing a class the target never mentions cannot
#     mask a bug in the target.
#
#     Remove this transformation once the ESBMC crash is fixed.
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vendor="$here/vendor"
model="$here/model"

src="$vendor/include/aws/core/utils/Array.h"
dst="$model/include/aws/core/utils/Array.h"

rm -rf "$model"
mkdir -p "$model"
cp -r "$vendor/include" "$model/include"

# Locate the CryptoBuffer class and the doc comment immediately above it, so we
# cut at a syntactically clean boundary instead of a hardcoded line number.
decl="$(grep -n 'class AWS_CORE_API CryptoBuffer' "$src" | cut -d: -f1)"
if [ -z "${decl:-}" ]; then
    echo "make_model_headers: CryptoBuffer not found in $src -- upstream layout changed." >&2
    exit 1
fi

# Walk back over the preceding doc comment block (ending in */).
cut_at="$decl"
while [ "$cut_at" -gt 1 ]; do
    prev=$((cut_at - 1))
    line="$(sed -n "${prev}p" "$src")"
    case "$line" in
        *'*/'* | *'/**'* | *'*'* | '') cut_at="$prev" ;;
        *) break ;;
    esac
done

{
    head -n "$((cut_at - 1))" "$src"
    printf '\n'
    printf '        /* CryptoBuffer removed by scripts/make_model_headers.sh --\n'
    printf '           see that script for the ESBMC crash it works around. */\n'
    printf '\n'
    printf '    } // namespace Utils\n'
    printf '} // namespace Aws\n'
} > "$dst"

echo "make_model_headers: wrote $dst (CryptoBuffer dropped at line $cut_at of $(wc -l < "$src") )"
