#!/usr/bin/env bash
# Generate an SPDX 2.3 JSON SBOM with Syft. Fail closed if syft is missing
# or the output is not SPDX JSON. Used by tagged releases (issue #84).
set -euo pipefail

usage() {
  echo "usage: $0 --output FILE SOURCE" >&2
  echo "SOURCE is a file, directory, or image reference Syft accepts." >&2
  exit 1
}

output=""
source=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || usage
      output="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    --)
      shift
      break
      ;;
    -*)
      usage
      ;;
    *)
      if [[ -n "$source" ]]; then
        usage
      fi
      source="$1"
      shift
      ;;
  esac
done

if [[ -z "$output" || -z "$source" ]]; then
  usage
fi

if ! command -v syft >/dev/null 2>&1; then
  echo "syft is required to generate an SPDX SBOM" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$output")"
syft "$source" -o "spdx-json=$output"

python3 - "$output" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    document = json.load(handle)
version = document.get("spdxVersion") or document.get("spdx_version")
if not isinstance(version, str) or not version.startswith("SPDX-"):
    raise SystemExit(f"{path} is not SPDX JSON (spdxVersion={version!r})")
packages = document.get("packages")
if not isinstance(packages, list):
    raise SystemExit(f"{path} SPDX document has no packages list")
print(f"{path}: {version} packages={len(packages)}")
PY
