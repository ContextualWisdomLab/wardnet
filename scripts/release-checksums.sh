#!/usr/bin/env bash
# Emit SHA-256 checksums with basename-only paths so `sha256sum -c`
# works next to the downloaded GitHub Release binary.
set -euo pipefail
if [[ $# -lt 1 ]]; then
  echo "usage: $0 <file>..." >&2
  exit 1
fi

hash_one() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$file"
  else
    shasum -a 256 -- "$file"
  fi
}

for file in "$@"; do
  line="$(hash_one "$file")"
  digest="${line%% *}"
  name="$(basename -- "$file")"
  printf '%s  %s\n' "$digest" "$name"
done
