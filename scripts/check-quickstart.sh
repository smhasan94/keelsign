#!/usr/bin/env bash
# Run the fenced `sh` block under README.md's `## Quickstart` heading verbatim, from the
# repository root, with `bash -euo pipefail`, and fail if it takes longer than the
# 300-second budget the README promises (SHA-53).
#
# Usage:
#   scripts/check-quickstart.sh [--keelsign DIR]
#
# --keelsign DIR is put first on PATH (for example target/release after
# `cargo build --release -p keelsign --locked`); without it, `keelsign` must already be on
# PATH. CI runs this after a release build (.github/workflows/ci.yml); the Rust test
# keelsign/tests/quickstart.rs runs it with the debug binary.
set -euo pipefail

usage() {
    echo "usage: scripts/check-quickstart.sh [--keelsign DIR]" >&2
    exit 2
}

budget=300
keelsign_dir=""
while [ $# -gt 0 ]; do
    case "$1" in
        --keelsign)
            [ $# -ge 2 ] || usage
            keelsign_dir="$2"
            shift 2
            ;;
        -h | --help)
            echo "usage: scripts/check-quickstart.sh [--keelsign DIR]"
            exit 0
            ;;
        *)
            usage
            ;;
    esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [ -n "$keelsign_dir" ]; then
    PATH="$(cd "$keelsign_dir" && pwd):$PATH"
    export PATH
fi
if ! command -v keelsign > /dev/null; then
    echo "check-quickstart: keelsign is not on PATH (give --keelsign DIR)" >&2
    exit 1
fi

# The first ```sh block after the `## Quickstart` heading, up to its closing fence.
block="$(awk '
    /^## / { in_section = ($0 == "## Quickstart"); next }
    in_section && !done && $0 == "```sh" { in_block = 1; next }
    in_block && $0 == "```" { in_block = 0; done = 1; next }
    in_block { print }
' README.md)"
if [ -z "$block" ]; then
    echo "check-quickstart: README.md has no \`\`\`sh block under ## Quickstart" >&2
    exit 1
fi

# The quickstart's `mktemp -d` work directory lands under this scratch TMPDIR, which is
# removed on exit so repeated runs leave nothing behind.
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
export TMPDIR="$scratch"

echo "check-quickstart: running the README quickstart with $(command -v keelsign)"
SECONDS=0
bash -euo pipefail -c "$block"
elapsed=$SECONDS
echo "check-quickstart: done in ${elapsed} s (budget ${budget} s)"
if [ "$elapsed" -gt "$budget" ]; then
    echo "check-quickstart: the quickstart took ${elapsed} s, over the ${budget} s budget" >&2
    exit 1
fi
