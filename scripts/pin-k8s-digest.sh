#!/usr/bin/env bash
# Fail closed unless IMAGE-DIGEST.txt is a GHCR content digest, then print
# the Kubernetes image line operators must pin (never a floating tag).
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "usage: $0 <IMAGE-DIGEST.txt>" >&2
  exit 1
fi
file="$1"
if [[ ! -f "$file" ]]; then
  echo "pin-k8s-digest: missing $file" >&2
  exit 1
fi
ref="$(tr -d '[:space:]' < "$file")"
if [[ ! "$ref" =~ ^ghcr\.io/contextualwisdomlab/waf-ids-ai-soc@sha256:[0-9a-f]{64}$ ]]; then
  echo "pin-k8s-digest: refused non-digest or wrong image: $ref" >&2
  exit 1
fi
printf 'image: %s\nimagePullPolicy: IfNotPresent\n' "$ref"
