#!/bin/sh
# Re-vendor the OIDC client library from upstream when a newer release exists.
#
# Reads ../vendor-lock.json, compares the pinned version against the latest
# upstream GitHub release, and if newer: downloads it, replaces the vendored
# files under vendored_path, and rewrites the lock (version + per-file sha256).
#
# Output: "up-to-date (<ver>)" with no file changes, or "updated <old> -> <new>"
# with the working tree modified. Safe to run manually for a dry run; CI runs it
# on a schedule and opens a PR when it changes files. Requires: curl, jq, tar,
# sha256sum.
#
# It deliberately does NOT touch OidcClient.php — if upstream adds/renames files,
# the require_once list there may need a manual follow-up, which the PR review
# (and the lint/test CI on the PR) is there to catch.
set -eu

ROOT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
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

# Replace vendored PHP files with the new release's src/*.php
rm -f "$ROOT/$vpath"/*.php
cp "$srcdir"/*.php "$ROOT/$vpath/"

# Rebuild the lock: bump version and recompute per-file checksums
files_json=$(cd "$ROOT/$vpath" && for f in *.php; do
    printf '%s %s\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"
done | jq -R 'split(" ") | {(.[0]): .[1]}' | jq -s 'add')

tmplock=$(mktemp)
jq --arg v "$latest" --argjson files "$files_json" '.version = $v | .files = $files' "$LOCK" > "$tmplock"
mv "$tmplock" "$LOCK"

echo "updated $current -> $latest"
