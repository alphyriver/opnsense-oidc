#!/bin/sh
# Verify the vendored OIDC library against vendor-lock.json. Fails (non-zero) on
# any drift, so a hand-edit of lib/, a stale checksum, or a patch that no longer
# reflects the committed files cannot slip through review.
#
# Three checks:
#   1. committed lib/ files match `.files`            (offline drift gate)
#   2. pinned upstream <version> matches `.upstream_files`  (provenance)
#   3. upstream + patches/ re-derives `.files` exactly (patch integrity)
#
# Checks 2-3 fetch the pinned upstream tag and need network; check 1 is offline.
# Requires: jq, sha256sum, curl, tar, patch.
set -eu

ROOT=$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)
LOCK="$ROOT/vendor-lock.json"

repo=$(jq -r '.repository' "$LOCK")
version=$(jq -r '.version' "$LOCK")
vpath=$(jq -r '.vendored_path' "$LOCK")
slug=$(printf '%s' "$repo" | sed -E 's#https?://github.com/##; s#\.git$##')

fail=0
check_dir_against() { # <dir> <lock-key> <label>
    dir=$1; key=$2; label=$3
    # Every file recorded under <key> must exist in <dir> with a matching sha256.
    for f in $(jq -r ".${key} | keys[]" "$LOCK"); do
        want=$(jq -r ".${key}[\"$f\"]" "$LOCK")
        if [ ! -f "$dir/$f" ]; then
            echo "::error::$label: $f missing"; fail=1; continue
        fi
        got=$(sha256sum "$dir/$f" | cut -d' ' -f1)
        if [ "$got" != "$want" ]; then
            echo "::error::$label: $f sha256 mismatch (want $want, got $got)"; fail=1
        fi
    done
}

# 1. Committed lib/ matches the recorded patched checksums (offline drift gate).
echo "==> [1/3] committed lib/ vs .files"
check_dir_against "$ROOT/$vpath" files "committed lib"

# 2 + 3. Fetch pristine upstream, check provenance, re-apply patches, compare.
echo "==> [2/3] pinned upstream $version vs .upstream_files"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://codeload.github.com/$slug/tar.gz/refs/tags/$version" -o "$tmp/lib.tgz"
tar -xzf "$tmp/lib.tgz" -C "$tmp"
srcdir=$(find "$tmp" -maxdepth 2 -type d -name src | head -1)
[ -d "$srcdir" ] || { echo "::error::no src/ in upstream tarball for $version" >&2; exit 1; }
check_dir_against "$srcdir" upstream_files "pristine upstream"

echo "==> [3/3] upstream + patches re-derives .files"
work="$tmp/work"; mkdir -p "$work/$vpath"; cp "$srcdir"/*.php "$work/$vpath/"
for p in $(jq -r '.patches[]?' "$LOCK"); do
    patch -p1 -d "$work" < "$ROOT/patches/$p" >/dev/null || {
        echo "::error::patch $p does not apply to pristine $version" >&2; fail=1; break
    }
done
check_dir_against "$work/$vpath" files "upstream+patches"

if [ "$fail" -ne 0 ]; then
    echo "vendor-verify: FAILED"; exit 1
fi
echo "vendor-verify: OK ($version + $(jq -r '.patches | length' "$LOCK") patch(es))"
