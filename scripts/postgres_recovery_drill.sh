#!/usr/bin/env bash
set -euo pipefail

readonly POSTGRES_IMAGE="${WARDNET_POSTGRES_IMAGE:-postgres:18.4-bookworm}"
readonly PINNED_POSTGRES_IMAGE="postgres:18.4-bookworm"
readonly RUNTIME_PRINCIPAL="wardnet_recovery_runtime"
readonly FINAL_STARTUP_MARKER="PostgreSQL init process complete; ready for start up."
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SUFFIX="$$-${RANDOM:-0}"

source_container="wardnet-pitr-source-${SUFFIX}"
restore_container="wardnet-pitr-restore-${SUFFIX}"
missing_container="wardnet-pitr-missing-wal-${SUFFIX}"
unreachable_container="wardnet-pitr-unreachable-${SUFFIX}"
source_volume="wardnet-pitr-source-data-${SUFFIX}"
backup_volume="wardnet-pitr-backup-${SUFFIX}"
archive_volume="wardnet-pitr-archive-${SUFFIX}"
restore_volume="wardnet-pitr-restore-data-${SUFFIX}"
corrupt_volume="wardnet-pitr-corrupt-backup-${SUFFIX}"
missing_volume="wardnet-pitr-missing-data-${SUFFIX}"
unreachable_volume="wardnet-pitr-unreachable-data-${SUFFIX}"

fail() {
  printf 'wardnet PostgreSQL recovery drill: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local container volume
  for container in \
    "$source_container" "$restore_container" "$missing_container" "$unreachable_container"; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
  for volume in \
    "$source_volume" "$backup_volume" "$archive_volume" "$restore_volume" \
    "$corrupt_volume" "$missing_volume" "$unreachable_volume"; do
    docker volume rm -f "$volume" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT INT TERM

[[ "$POSTGRES_IMAGE" == "$PINNED_POSTGRES_IMAGE" ]] || \
  fail "WARDNET_POSTGRES_IMAGE must remain pinned to ${PINNED_POSTGRES_IMAGE}"

docker version >/dev/null 2>&1 || fail "Docker is required for the physical recovery drill"

create_volume() {
  docker volume create "$1" >/dev/null
}

for volume in \
  "$source_volume" "$backup_volume" "$archive_volume" "$restore_volume" \
  "$corrupt_volume" "$missing_volume" "$unreachable_volume"; do
  create_volume "$volume"
done

# pg_basebackup and PostgreSQL archive_command run as the postgres OS user.
docker run --rm \
  -v "${backup_volume}:/backup" \
  -v "${archive_volume}:/archive" \
  "$POSTGRES_IMAGE" \
  bash -ceu 'chown postgres:postgres /backup /archive' >/dev/null

psql_super() {
  local container="$1"
  local database="$2"
  docker exec -i "$container" \
    psql -X -q -A -t -v ON_ERROR_STOP=1 -U postgres -d "$database"
}

psql_runtime() {
  local container="$1"
  docker exec -i "$container" \
    psql -X -q -A -t -v ON_ERROR_STOP=1 -U "$RUNTIME_PRINCIPAL" -d postgres
}

run_sql_file() {
  local container="$1"
  local database="$2"
  local path="$3"
  docker exec "$container" \
    psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$database" -f "$path" >/dev/null
}

wait_for_source() {
  local container="$1"
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if docker exec "$container" pg_isready -U postgres -d postgres >/dev/null 2>&1 \
      && docker logs "$container" 2>&1 | grep -Fq "$FINAL_STARTUP_MARKER"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_for_promoted_restore() {
  local container="$1"
  local deadline=$((SECONDS + 60))
  local promoted
  while (( SECONDS < deadline )); do
    if docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -qx true; then
      promoted="$(
        printf 'SELECT (NOT pg_is_in_recovery())::text;\n' \
          | psql_super "$container" postgres 2>/dev/null \
          | tr -d '[:space:]' || true
      )"
      if [[ "$promoted" == "t" ]]; then
        return 0
      fi
    else
      return 1
    fi
    sleep 0.5
  done
  return 1
}

assert_never_promotes() {
  local container="$1"
  local deadline=$((SECONDS + 8))
  local promoted
  while (( SECONDS < deadline )); do
    if ! docker inspect -f '{{.State.Running}}' "$container" >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != "true" ]]; then
      return 0
    fi
    promoted="$(
      printf 'SELECT (NOT pg_is_in_recovery())::text;\n' \
        | psql_super "$container" postgres 2>/dev/null \
        | tr -d '[:space:]' || true
    )"
    [[ "$promoted" != "t" ]] || return 1
    sleep 0.5
  done
  return 0
}

copy_backup_to_volume() {
  local target_volume="$1"
  docker run --rm \
    -v "${backup_volume}:/backup:ro" \
    -v "${target_volume}:/restore" \
    "$POSTGRES_IMAGE" \
    bash -ceu 'cp -a /backup/base/. /restore/; chown -R postgres:postgres /restore' >/dev/null
}

configure_recovery_volume() {
  local target_volume="$1"
  local restore_command="$2"
  local recovery_target="$3"
  docker run --rm \
    -v "${target_volume}:/data" \
    "$POSTGRES_IMAGE" \
    bash -ceu "
      touch /data/recovery.signal
      cat >> /data/postgresql.auto.conf <<'WARDNET_RECOVERY'
restore_command = '${restore_command}'
recovery_target_lsn = '${recovery_target}'
recovery_target_action = 'promote'
WARDNET_RECOVERY
      chown postgres:postgres /data/recovery.signal /data/postgresql.auto.conf
    " >/dev/null
}

publish_runtime() {
  local container="$1"
  local tenant="$2"
  local expected_prior="$3"
  local generation="$4"
  local ordinal="$5"
  local actor="$6"
  local decision="$7"
  local prior_sql="NULL"
  if [[ -n "$expected_prior" ]]; then
    prior_sql="'${expected_prior}'"
  fi
  psql_runtime "$container" <<SQL
BEGIN;
SET LOCAL wardnet.tenant_id = '${tenant}';
SET LOCAL wardnet.actor_subject_id = '${actor}';
SET LOCAL wardnet.decision_id = '${decision}';
SELECT public.wardnet_publish_reputation_source_generation(
  '${tenant}',
  'urlhaus',
  ${prior_sql},
  '${generation}',
  ${ordinal},
  $((1700000000 + ordinal)),
  'provenance-${generation}',
  'snapshot-${generation}',
  'complete-${generation}',
  'lifecycle-${generation}'
);
COMMIT;
SQL
}

runtime_visible_publications() {
  local container="$1"
  local tenant="$2"
  psql_runtime "$container" <<SQL
BEGIN;
SET LOCAL wardnet.tenant_id = '${tenant}';
SELECT count(*) FROM public.reputation_source_publication;
ROLLBACK;
SQL
}

# The source owns archive production only for the duration of this destructive
# fixture. Backup storage and credentials remain external deployment concerns.
docker run --rm -d \
  --name "$source_container" \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -e PGDATA=/var/lib/postgresql/data \
  -v "${source_volume}:/var/lib/postgresql/data" \
  -v "${backup_volume}:/backup" \
  -v "${archive_volume}:/archive" \
  -v "${ROOT}:/repo:ro" \
  "$POSTGRES_IMAGE" \
  postgres \
  -c wal_level=replica \
  -c archive_mode=on \
  -c "archive_command=test ! -f /archive/%f && cp %p /archive/%f" >/dev/null

wait_for_source "$source_container" || fail "source PostgreSQL final server did not become ready"

for path in \
  /repo/migrations/0001_reputation_source_generation.sql \
  /repo/migrations/0002_reputation_source_generation_admission.sql \
  /repo/migrations/0003_reputation_source_publication.sql \
  /repo/migrations/0004_reputation_state_schema_version.sql \
  /repo/migrations/0005_reputation_source_publication_audit.sql \
  /repo/deploy/postgresql/reputation_state_roles.sql; do
  run_sql_file "$source_container" postgres "$path"
done

printf '%s\n' \
  "CREATE ROLE ${RUNTIME_PRINCIPAL} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;" \
  | psql_super "$source_container" postgres >/dev/null

docker exec "$source_container" \
  psql -X -q -v ON_ERROR_STOP=1 \
  -v "wardnet_runtime_principal=${RUNTIME_PRINCIPAL}" \
  -U postgres -d postgres \
  -f /repo/deploy/postgresql/reputation_state_runtime_principal.sql >/dev/null

[[ "$(publish_runtime "$source_container" tenant-a '' generation-8 8 subject:recovery-a decision:a-8 | tr -d '[:space:]')" == "committed" ]] \
  || fail "tenant-a generation-8 publication did not commit"
[[ "$(publish_runtime "$source_container" tenant-b '' generation-1 1 subject:recovery-b decision:b-1 | tr -d '[:space:]')" == "committed" ]] \
  || fail "tenant-b generation-1 publication did not commit"

# The physical base backup carries its own signed-by-content manifest and a WAL
# stream sufficient for the backup boundary. Later committed state is recovered
# only from the independent archive volume.
docker exec -u postgres "$source_container" \
  pg_basebackup \
  -h 127.0.0.1 \
  -U postgres \
  -D /backup/base \
  -Fp \
  -X stream \
  --checkpoint=fast \
  --manifest-checksums=SHA256 >/dev/null

docker exec -u postgres "$source_container" pg_verifybackup /backup/base >/dev/null

manifest="$(docker exec "$source_container" cat /backup/base/backup_manifest)"
backup_start_lsn="$(printf '%s\n' "$manifest" | awk -F'"' '/"Start-LSN"/ {for (i=1; i<=NF; i++) if ($i == "Start-LSN") {print $(i+2); exit}}')"
backup_end_lsn="$(printf '%s\n' "$manifest" | awk -F'"' '/"End-LSN"/ {for (i=1; i<=NF; i++) if ($i == "End-LSN") {print $(i+2); exit}}')"
[[ -n "$backup_start_lsn" && -n "$backup_end_lsn" ]] \
  || fail "backup manifest did not expose WAL range identity"
backup_manifest_sha256="$(
  docker exec "$source_container" sha256sum /backup/base/backup_manifest | awk '{print $1}'
)"
[[ "$backup_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] \
  || fail "backup manifest SHA-256 identity is invalid"

# Close the base-backup WAL segment before the post-backup publication so the
# recovery target is provably in a later archived segment, not in copied base WAL.
printf 'SELECT pg_switch_wal();\n' | psql_super "$source_container" postgres >/dev/null

[[ "$(publish_runtime "$source_container" tenant-a generation-8 generation-9 9 subject:recovery-a decision:a-9 | tr -d '[:space:]')" == "committed" ]] \
  || fail "post-backup tenant-a generation-9 publication did not commit"

# Close the segment containing the post-backup publication, then write a named
# restore-point WAL record in the following segment. The target is therefore a
# concrete post-commit WAL record beyond the backup replay floor rather than a
# sampled flush pointer that can coincide with a segment boundary.
printf 'SELECT pg_switch_wal();\n' | psql_super "$source_container" postgres >/dev/null
recovery_target_name="wardnet-pitr-${SUFFIX}"
recovery_target_lsn="$(
  printf "SELECT pg_create_restore_point('%s')::text;\n" "$recovery_target_name" \
    | psql_super "$source_container" postgres \
    | tr -d '[:space:]'
)"
source_wal_lsn="$(
  printf 'SELECT pg_current_wal_flush_lsn()::text;\n' \
    | psql_super "$source_container" postgres \
    | tr -d '[:space:]'
)"
source_timeline="$(
  printf 'SELECT timeline_id::text FROM pg_control_checkpoint();\n' \
    | psql_super "$source_container" postgres \
    | tr -d '[:space:]'
)"
unreachable_target_lsn="$(
  printf "SELECT ('%s'::pg_lsn + 4294967296)::text;\n" "$recovery_target_lsn" \
    | psql_super "$source_container" postgres \
    | tr -d '[:space:]'
)"
[[ -n "$recovery_target_lsn" && -n "$source_timeline" && -n "$unreachable_target_lsn" ]] \
  || fail "source WAL/timeline identity is incomplete"

[[ "$(
  printf "SELECT ('%s'::pg_lsn > '%s'::pg_lsn)::text;\n" "$recovery_target_lsn" "$backup_end_lsn" \
    | psql_super "$source_container" postgres \
    | tr -d '[:space:]'
)" == "t" ]] || fail "post-backup target must be beyond the base backup WAL boundary"

target_wal_file="$(
  printf "SELECT pg_walfile_name('%s'::pg_lsn);\n" "$recovery_target_lsn" \
    | psql_super "$source_container" postgres \
    | tr -d '[:space:]'
)"
printf 'SELECT pg_switch_wal();\n' | psql_super "$source_container" postgres >/dev/null
archive_deadline=$((SECONDS + 30))
until docker exec "$source_container" test -s "/archive/${target_wal_file}" >/dev/null 2>&1; do
  (( SECONDS < archive_deadline )) || fail "post-backup target WAL was not archived"
  sleep 0.25
done
docker exec "$source_container" test ! -e "/backup/base/pg_wal/${target_wal_file}" \
  || fail "target WAL unexpectedly exists inside the base backup"

source_publication_count="$(
  printf 'SELECT count(*) FROM public.reputation_source_publication;\n' \
    | psql_super "$source_container" postgres \
    | tr -d '[:space:]'
)"
[[ "$source_publication_count" == "3" ]] \
  || fail "controlled source must contain exactly three committed publications"

# Corrupt-manifest refusal is proved against a disposable byte-for-byte copy.
docker run --rm \
  -v "${backup_volume}:/backup:ro" \
  -v "${corrupt_volume}:/corrupt" \
  "$POSTGRES_IMAGE" \
  bash -ceu 'cp -a /backup/base/. /corrupt/; printf "corrupt\n" >> /corrupt/backup_manifest' >/dev/null
if docker run --rm \
  -v "${corrupt_volume}:/corrupt:ro" \
  "$POSTGRES_IMAGE" \
  bash -ceu 'pg_verifybackup --no-parse-wal /corrupt >/dev/null 2>&1'; then
  fail "corrupt backup manifest was accepted"
fi

# RTO starts before destructive source loss. The source container and its data
# volume are removed before any recovery copy is materialized.
rto_start_ms="$(date +%s%3N)"
docker rm -f "$source_container" >/dev/null
source_container=""
docker volume rm -f "$source_volume" >/dev/null
source_volume=""
if docker volume inspect "wardnet-pitr-source-data-${SUFFIX}" >/dev/null 2>&1; then
  fail "source data volume survived the destruction boundary"
fi

copy_backup_to_volume "$restore_volume"
configure_recovery_volume "$restore_volume" 'cp /archive/%f %p' "$recovery_target_lsn"
docker run --rm -d \
  --name "$restore_container" \
  -e PGDATA=/var/lib/postgresql/data \
  -v "${restore_volume}:/var/lib/postgresql/data" \
  -v "${archive_volume}:/archive:ro" \
  -v "${ROOT}:/repo:ro" \
  "$POSTGRES_IMAGE" >/dev/null
wait_for_promoted_restore "$restore_container" \
  || fail "restored PostgreSQL did not reach and promote at the declared recovery target"
rto_end_ms="$(date +%s%3N)"
rto_ms=$((rto_end_ms - rto_start_ms))
(( rto_ms > 0 )) || fail "measured recovery time must be positive"

latest_recovered_lsn="$(
  printf 'SELECT coalesce(pg_last_wal_replay_lsn(), pg_current_wal_lsn())::text;\n' \
    | psql_super "$restore_container" postgres \
    | tr -d '[:space:]'
)"
[[ "$(
  printf "SELECT ('%s'::pg_lsn >= '%s'::pg_lsn)::text;\n" "$latest_recovered_lsn" "$recovery_target_lsn" \
    | psql_super "$restore_container" postgres \
    | tr -d '[:space:]'
)" == "t" ]] || fail "recovered WAL position did not reach declared target"

recovered_publication_count="$(
  printf 'SELECT count(*) FROM public.reputation_source_publication;\n' \
    | psql_super "$restore_container" postgres \
    | tr -d '[:space:]'
)"
[[ "$recovered_publication_count" == "$source_publication_count" ]] \
  || fail "committed publication transactions were lost across physical recovery"
rpo_lost_publication_transactions=0

runtime_superuser="$(
  printf "SELECT rolsuper::text FROM pg_catalog.pg_roles WHERE rolname = '%s';\n" "$RUNTIME_PRINCIPAL" \
    | psql_super "$restore_container" postgres \
    | tr -d '[:space:]'
)"
[[ "$runtime_superuser" == "f" ]] || fail "restored runtime LOGIN is unexpectedly superuser"

rls_count="$(
  psql_super "$restore_container" postgres <<'SQL' | tr -d '[:space:]'
SELECT count(*)
FROM pg_catalog.pg_class
WHERE oid IN (
  'public.reputation_source_generation'::regclass,
  'public.reputation_source_publication'::regclass,
  'public.reputation_source_publication_head'::regclass,
  'public.reputation_source_publication_audit'::regclass
)
AND relrowsecurity
AND relforcerowsecurity;
SQL
)"
[[ "$rls_count" == "4" ]] || fail "restored reputation state lost FORCE RLS"

unbound_count="$(
  printf 'SELECT count(*) FROM public.reputation_source_publication;\n' \
    | psql_runtime "$restore_container" \
    | tr -d '[:space:]'
)"
[[ "$unbound_count" == "0" ]] || fail "unbound runtime retained tenant authority after restore"

tenant_a_visible="$(runtime_visible_publications "$restore_container" tenant-a | tr -d '[:space:]')"
tenant_b_visible="$(runtime_visible_publications "$restore_container" tenant-b | tr -d '[:space:]')"
[[ "$tenant_a_visible" == "2" && "$tenant_b_visible" == "1" ]] \
  || fail "runtime tenant isolation did not survive recovery"

history_tuple="$(
  psql_super "$restore_container" postgres <<'SQL' | tr -d '[:space:]'
SELECT concat_ws(':',
  (SELECT count(*) FROM public.reputation_source_generation),
  (SELECT count(*) FROM public.reputation_source_publication),
  (SELECT count(*) FROM public.reputation_source_publication_audit),
  (SELECT count(*) FROM public.reputation_source_publication_head));
SQL
)"
[[ "$history_tuple" == "3:3:3:2" ]] \
  || fail "immutable publication/audit/head evidence did not survive recovery"

attributed_count="$(
  psql_super "$restore_container" postgres <<'SQL' | tr -d '[:space:]'
SELECT count(*)
FROM public.reputation_source_publication_audit
WHERE actor_subject_id IN ('subject:recovery-a', 'subject:recovery-b')
  AND decision_id IN ('decision:a-8', 'decision:a-9', 'decision:b-1');
SQL
)"
[[ "$attributed_count" == "3" ]] || fail "publication audit attribution did not survive recovery"

head_tuple="$(
  psql_super "$restore_container" postgres <<'SQL' | tr -d '[:space:]'
SELECT string_agg(
  tenant_id || ':' || source_generation || ':' || source_generation_ordinal::text,
  ',' ORDER BY tenant_id
)
FROM public.reputation_source_publication_head;
SQL
)"
[[ "$head_tuple" == "tenant-a:generation-9:9,tenant-b:generation-1:1" ]] \
  || fail "last-known-good publication heads did not survive recovery"

schema_version="$(
  printf "SELECT schema_version::text FROM public.wardnet_schema_version WHERE component='reputation_state';\n" \
    | psql_super "$restore_container" postgres \
    | tr -d '[:space:]'
)"
[[ "$schema_version" == "5" ]] || fail "restored schema version is not 5"

# The historical source token cannot be rebound at a newer ordinal, and an
# existing generation cannot replay with changed immutable evidence.
if publish_runtime "$restore_container" tenant-a generation-9 generation-8 10 subject:recovery-a decision:aba >/dev/null 2>&1; then
  fail "historical source-generation ABA was accepted after restore"
fi
if psql_runtime "$restore_container" >/dev/null 2>&1 <<'SQL'; then
BEGIN;
SET LOCAL wardnet.tenant_id = 'tenant-a';
SET LOCAL wardnet.actor_subject_id = 'subject:recovery-a';
SET LOCAL wardnet.decision_id = 'decision:divergent';
SELECT public.wardnet_publish_reputation_source_generation(
  'tenant-a', 'urlhaus', 'generation-8', 'generation-9', 9, 1700000009,
  'provenance-generation-9', 'snapshot-generation-9-changed',
  'complete-generation-9', 'lifecycle-generation-9'
);
COMMIT;
SQL
  fail "divergent immutable publication replay was accepted after restore"
fi

# A fresh publication through the ordinary mapped runtime LOGIN proves that the
# restored state is usable without state-owner or superuser application access.
[[ "$(publish_runtime "$restore_container" tenant-a generation-9 generation-10 10 subject:recovery-a decision:a-10 | tr -d '[:space:]')" == "committed" ]] \
  || fail "post-restore runtime publication did not commit"

# Missing archived WAL must never promote the base backup to the post-backup
# target. It may remain in recovery or terminate, but it cannot become writable.
copy_backup_to_volume "$missing_volume"
configure_recovery_volume "$missing_volume" 'false' "$recovery_target_lsn"
docker run --rm -d \
  --name "$missing_container" \
  -e PGDATA=/var/lib/postgresql/data \
  -v "${missing_volume}:/var/lib/postgresql/data" \
  "$POSTGRES_IMAGE" >/dev/null
assert_never_promotes "$missing_container" || fail "restore promoted without required archived WAL"
docker rm -f "$missing_container" >/dev/null 2>&1 || true
missing_container=""

# Even with the real archive mounted, a target beyond all produced WAL must not
# silently promote at the archive end.
copy_backup_to_volume "$unreachable_volume"
configure_recovery_volume "$unreachable_volume" 'cp /archive/%f %p' "$unreachable_target_lsn"
docker run --rm -d \
  --name "$unreachable_container" \
  -e PGDATA=/var/lib/postgresql/data \
  -v "${unreachable_volume}:/var/lib/postgresql/data" \
  -v "${archive_volume}:/archive:ro" \
  "$POSTGRES_IMAGE" >/dev/null
assert_never_promotes "$unreachable_container" || fail "restore promoted at an unreachable WAL target"
docker rm -f "$unreachable_container" >/dev/null 2>&1 || true
unreachable_container=""

# Startup migration validation is the repository's canonical shape guard. A
# scratch database with one FORCE-RLS bit removed must be rejected rather than
# normalized into an apparently healthy recovered state.
printf 'CREATE DATABASE wardnet_recovery_partial TEMPLATE template0;\n' \
  | psql_super "$restore_container" postgres >/dev/null
for path in \
  /repo/migrations/0001_reputation_source_generation.sql \
  /repo/migrations/0002_reputation_source_generation_admission.sql \
  /repo/migrations/0003_reputation_source_publication.sql \
  /repo/migrations/0004_reputation_state_schema_version.sql \
  /repo/migrations/0005_reputation_source_publication_audit.sql; do
  run_sql_file "$restore_container" wardnet_recovery_partial "$path"
done
printf 'ALTER TABLE public.reputation_source_publication_head NO FORCE ROW LEVEL SECURITY;\n' \
  | psql_super "$restore_container" wardnet_recovery_partial >/dev/null
if docker exec "$restore_container" \
  psql -X -q -v ON_ERROR_STOP=1 -U postgres -d wardnet_recovery_partial \
  -f /repo/deploy/postgresql/reputation_state_migrate.sql >/dev/null 2>&1; then
  fail "startup migration accepted partial RLS recovery state"
fi
printf 'DROP DATABASE wardnet_recovery_partial WITH (FORCE);\n' \
  | psql_super "$restore_container" postgres >/dev/null

printf '{"postgres_image":"%s","source_timeline":"%s","source_wal_lsn":"%s","backup_start_lsn":"%s","backup_end_lsn":"%s","backup_manifest_sha256":"%s","recovery_target_lsn":"%s","latest_recovered_lsn":"%s","backup_manifest_verified":true,"used_archived_wal_beyond_base_backup":true,"source_destroyed_before_restore":true,"recovery_reached_declared_target":true,"rpo_lost_publication_transactions":%s,"rto_ms":%s,"runtime_login_is_superuser":false,"runtime_rls_enforced":true,"tenant_isolation_verified":true,"publication_history_verified":true,"audit_attribution_verified":true,"current_head_verified":true,"schema_version_verified":true,"historical_aba_rejected":true,"divergent_replay_rejected":true,"unbound_runtime_has_no_tenant_authority":true,"post_restore_publication_committed":true,"hostile_cases":{"corrupt_manifest_failed_closed":true,"missing_wal_failed_closed":true,"unreachable_target_failed_closed":true,"partial_role_or_rls_state_failed_closed":true}}\n' \
  "$POSTGRES_IMAGE" \
  "$source_timeline" \
  "$source_wal_lsn" \
  "$backup_start_lsn" \
  "$backup_end_lsn" \
  "$backup_manifest_sha256" \
  "$recovery_target_lsn" \
  "$latest_recovered_lsn" \
  "$rpo_lost_publication_transactions" \
  "$rto_ms"