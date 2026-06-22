#!/bin/sh
# Re-vendor the OIDC client library from upstream when a newer release exists,
# re-applying the local security patches so they survive the bump.
#
# Reads ../vendor-lock.json, compares the pinned version against the latest
# upstream GitHub release, and if newer: downloads it, replaces the vendored
# files under vendored_path, RE-APPLIES every patch listed in `.patches` (from
# patches/), and rewrites the lock with BOTH pristine upstream checksums
# (`upstream_files`) and the post-patch checksums (`files`).
#
# This is what keeps local security modifications (e.g. dropping JWE RSA1_5)
# from being silently reverted on the next upstream bump: a patch that no longer
# applies fails the run loudly instead of vanishing. scripts/vendor-verify.sh
# (run in CI) independently re-derives and checks both checksum sets.
#
# Output: "up-to-date (<ver>)" with no file changes, or "updated <old> -> <new>"
# with the working tree modified. Safe to run manually for a dry run; CI runs it
# on a schedule and opens a PR when it changes files. Requires: curl, jq, tar,
# sha256sum, patch.
#
# It deliberately does NOT touch OidcClient.php — if upstream adds/renames files,
# the require_once list there may need a manual follow-up, which the PR review
# (and the lint/test CI on the PR) is there to catch.
set -eu

ROOT=$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)
LOCK="$ROOT/vendor-lock.json"

repo=$(jq -r '.repository' "$LOCK")
current=$(jq -r '.version' "$LOCK")
vpath=$(jq -r '.vendored_path' "$LOCK")
slug=$(printf '%s' "$repo" | sed -E 's#https?://github.com/##; s#\.git$##')

latest=$(curl -fsSL "https://api.github.com/repos/$slug/releases/latest" | jq -r '.tag_name')
[ -n "$latest" ] && [ "$latest" != "null" ] || { echo "could not determine latest release for $slug" >&2; exit 1; }

if [ "$latest" = "$current" ]; then
    echo "up-to-date ($current)"
    exit 0
fi

echo "updating $current -> $latest"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://codeload.github.com/$slug/tar.gz/refs/tags/$latest" -o "$tmp/lib.tgz"
tar -xzf "$tmp/lib.tgz" -C "$tmp"
srcdir=$(find "$tmp" -maxdepth 2 -type d -name src | head -1)
[ -d "$srcdir" ] || { echo "no src/ directory in upstream tarball" >&2; exit 1; }

# Replace vendored PHP files with the new release's src/*.php (pristine upstream).
rm -f "$ROOT/$vpath"/*.php
cp "$srcdir"/*.php "$ROOT/$vpath/"

# Record pristine upstream checksums BEFORE patching.
checksums() {
    (cd "$1" && for f in *.php; do
        printf '%s %s\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"
    done | jq -R 'split(" ") | {(.[0]): .[1]}' | jq -s 'add')
}
upstream_json=$(checksums "$ROOT/$vpath")

# Re-apply local security patches, in listed order, against the new upstream.
# A patch that no longer applies aborts the run (fix the patch, don't drop it).
for p in $(jq -r '.patches[]?' "$LOCK"); do
    echo "applying patch: $p"
    patch -p1 -d "$ROOT" < "$ROOT/patches/$p" || {
        echo "::error::patch $p failed to apply against $latest; resolve before bumping" >&2
        exit 1
    }
done

# Record post-patch checksums (the committed state).
files_json=$(checksums "$ROOT/$vpath")

tmplock=$(mktemp)
jq --arg v "$latest" --argjson up "$upstream_json" --argjson files "$files_json" \
   '.version = $v | .upstream_files = $up | .files = $files' "$LOCK" > "$tmplock"
mv "$tmplock" "$LOCK"

echo "updated $current -> $latest"
