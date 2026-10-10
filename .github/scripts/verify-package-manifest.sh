#!/usr/bin/env bash
#
# Fails unless SHA256SUMS covers every unsigned gateway package artifact.
# Counts are deliberate: change the Package matrix, change this file.
set -euo pipefail

manifest="${1:?usage: verify-package-manifest.sh SHA256SUMS}"

if [ ! -r "$manifest" ]; then
    echo "no readable manifest at ${manifest}" >&2
    exit 1
fi

# filename pattern:count
# POSIX/epoll hosts only. Windows mill extra stays empty until a Windows port.
required=(
    'datum_gateway-linux-x64\.zip$:1'
    'datum_gateway-linux-arm64\.zip$:1'
    'datum_gateway-macos-arm64\.zip$:1'
    'datum_gateway-macos-x64\.zip$:1'
)

short=0
for spec in "${required[@]}"; do
    pattern="${spec%:*}"
    expected="${spec##*:}"
    actual=$(grep -cE -- "$pattern" "$manifest") || [ $? -eq 1 ] || exit 1
    if [ "$actual" -ne "$expected" ]; then
        echo "manifest carries $actual file(s) matching ${pattern}, expected ${expected}" >&2
        short=1
    fi
done

while read -r name; do
    case "$name" in
        *.zip) ;;
        "") ;;
        *) echo "manifest carries ${name}, which is not a kind of file Package publishes" >&2; short=1 ;;
    esac
done < <(awk '{print $2}' "$manifest")

if [ "$short" -ne 0 ]; then
    echo "" >&2
    echo "The manifest does not cover every platform, which means a build job failed and this ran anyway." >&2
    echo "Do not create a draft GitHub Release from a partial unsigned set." >&2
    exit 1
fi

echo "manifest covers all $(wc -l < "$manifest") expected artifacts"
