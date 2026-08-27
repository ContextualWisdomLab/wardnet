#!/usr/bin/env bash
# Fail closed unless REF is a signed annotated tag that peels to the fetched
# origin/main commit.
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi
ref="$1"
if [[ ! "$ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "admit-release-tag: $ref is not a vX.Y.Z tag" >&2
  exit 1
fi
kind="$(git cat-file -t "$ref" 2>/dev/null || true)"
if [[ "$kind" != "tag" ]]; then
  echo "admit-release-tag: $ref is ${kind:-missing}, not an annotated tag; use git tag -a" >&2
  exit 1
fi
if ! git verify-tag "$ref" >/dev/null 2>&1; then
  echo "admit-release-tag: $ref is not a cryptographically signed annotated tag" >&2
  exit 1
fi
git fetch --quiet origin main
tag_commit="$(git rev-parse "${ref}^{commit}")"
main_commit="$(git rev-parse "origin/main^{commit}")"
if [[ "$tag_commit" != "$main_commit" ]]; then
  echo "admit-release-tag: $ref peels to $tag_commit, expected origin/main $main_commit" >&2
  exit 1
fi
echo "admit-release-tag: admitted signed annotated tag $ref at $tag_commit"
