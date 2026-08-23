#!/usr/bin/env bash
# Emit SHA-256 checksums for release artifacts (GNU sha256sum or BSD shasum).
set -euo pipefail
if [[ $# -lt 1 ]]; then
  echo "usage: $0 <file>..." >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$@"
else
  shasum -a 256 "$@"
fi
