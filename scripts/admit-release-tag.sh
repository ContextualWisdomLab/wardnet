#!/usr/bin/env bash
# Fail closed unless REF is an annotated git tag (lightweight/unsigned refs
# are not admitted to the release pipeline).
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
echo "admit-release-tag: admitted annotated tag $ref"
