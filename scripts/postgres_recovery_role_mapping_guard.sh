#!/usr/bin/env bash
set -euo pipefail

readonly POSTGRES_IMAGE="${WARDNET_POSTGRES_IMAGE:-postgres:18.4-bookworm}"
readonly PINNED_POSTGRES_IMAGE="postgres:18.4-bookworm"
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SUFFIX="$$-${RANDOM:-0}"
readonly CONTAINER="wardnet-recovery-role-guard-${SUFFIX}"
readonly UNSAFE_PRINCIPAL="wardnet_recovery_unsafe_${SUFFIX//-/_}"

fail() {
  printf 'wardnet recovery role-mapping guard: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

[[ "$POSTGRES_IMAGE" == "$PINNED_POSTGRES_IMAGE" ]] || \
  fail "WARDNET_POSTGRES_IMAGE must remain pinned to ${PINNED_POSTGRES_IMAGE}"
docker version >/dev/null 2>&1 || fail "Docker is required for the recovery role-mapping guard"

docker run --rm -d \
  --name "$CONTAINER" \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -v "${ROOT}:/repo:ro" \
  "$POSTGRES_IMAGE" >/dev/null

deadline=$((SECONDS + 60))
until docker exec "$CONTAINER" pg_isready -U postgres -d postgres >/dev/null 2>&1; do
  (( SECONDS < deadline )) || fail "PostgreSQL did not become ready"
  sleep 0.5
done

for path in \
  /repo/migrations/0001_reputation_source_generation.sql \
  /repo/migrations/0002_reputation_source_generation_admission.sql \
  /repo/migrations/0003_reputation_source_publication.sql \
  /repo/migrations/0004_reputation_state_schema_version.sql \
  /repo/migrations/0005_reputation_source_publication_audit.sql \
  /repo/deploy/postgresql/reputation_state_roles.sql; do
  docker exec "$CONTAINER" \
    psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres -f "$path" >/dev/null
done

printf '%s\n' \
  "CREATE ROLE ${UNSAFE_PRINCIPAL} LOGIN INHERIT NOSUPERUSER CREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;" \
  | docker exec -i "$CONTAINER" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres >/dev/null

if docker exec "$CONTAINER" \
  psql -X -q -v ON_ERROR_STOP=1 \
  -v "wardnet_runtime_principal=${UNSAFE_PRINCIPAL}" \
  -U postgres -d postgres \
  -f /repo/deploy/postgresql/reputation_state_runtime_principal.sql >/dev/null 2>&1; then
  fail "runtime mapper accepted a CREATEDB recovery principal"
fi

membership_count="$(
  printf "SELECT count(*) FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname='wardnet_runtime' AND u.rolname='%s';\n" "$UNSAFE_PRINCIPAL" \
    | docker exec -i "$CONTAINER" psql -X -q -A -t -v ON_ERROR_STOP=1 -U postgres -d postgres \
    | tr -d '[:space:]'
)"
[[ "$membership_count" == "0" ]] || fail "failed mapping left a runtime membership edge behind"

printf '{"unsafe_role_mapping_failed_closed":true}\n'
