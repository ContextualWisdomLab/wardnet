-- Map one externally managed PostgreSQL LOGIN identity to Wardnet's existing
-- least-privilege runtime capability role.
--
-- This artifact deliberately does not CREATE ROLE, set passwords, own schema
-- objects, or enable the application PostgreSQL adapter. Deployment/IAM owns
-- login lifecycle and credentials; Wardnet owns only the bounded membership
-- edge required by its reputation-state repository boundary.
--
-- Usage:
--   psql -v ON_ERROR_STOP=1 \
--        -v wardnet_runtime_principal='wardnet_app' \
--        -f deploy/postgresql/reputation_state_runtime_principal.sql
\set ON_ERROR_STOP on

\if :{?wardnet_runtime_principal}
\else
DO $wardnet_missing_runtime_principal$
BEGIN
    RAISE EXCEPTION 'Wardnet runtime principal mapping requires wardnet_runtime_principal.';
END
$wardnet_missing_runtime_principal$;
\endif

BEGIN;

-- The capability roles are installed by reputation_state_roles.sql. Refuse to
-- grant through drifted or nested capability roles: an unexpected membership
-- can import authority that this mapper cannot safely characterize.
SELECT
    count(*) = 2
        AND bool_and(NOT rolcanlogin)
        AND bool_and(NOT rolsuper)
        AND bool_and(NOT rolcreatedb)
        AND bool_and(NOT rolcreaterole)
        AND bool_and(NOT rolinherit)
        AND bool_and(NOT rolreplication)
        AND bool_and(NOT rolbypassrls)
        AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members membership
            JOIN pg_catalog.pg_roles member_role
              ON member_role.oid = membership.member
            WHERE member_role.rolname IN ('wardnet_runtime', 'wardnet_state_owner')
        ) AS capability_roles_safe
FROM pg_catalog.pg_roles
WHERE rolname IN ('wardnet_runtime', 'wardnet_state_owner')
\gset

\if :capability_roles_safe
\else
DO $wardnet_unsafe_capability_roles$
BEGIN
    RAISE EXCEPTION 'Wardnet runtime principal mapping refused: capability-role attributes or memberships are unsafe.';
END
$wardnet_unsafe_capability_roles$;
\endif

-- The supplied login must already exist and remain an ordinary inheriting
-- application identity. Special PostgreSQL role attributes are not inherited,
-- but SET-capable membership in an elevated role could still acquire them, so
-- reject any direct or indirect privileged-role membership as well as any
-- access to Wardnet's state-owner role. The principal must also arrive without
-- out-of-band mutation or inner-admission privileges on Wardnet state objects;
-- otherwise adding wardnet_runtime would preserve a wider effective authority
-- than this mapper is allowed to establish. Runtime membership is valid only
-- when absent (first mapping) or already present as the mapper's exact bounded
-- direct edge (idempotent replay); any alternate role path to wardnet_runtime
-- is outside this artifact's authority and therefore fails closed.
SELECT
    count(*) = 1
        AND bool_and(rolcanlogin)
        AND bool_and(NOT rolsuper)
        AND bool_and(NOT rolcreatedb)
        AND bool_and(NOT rolcreaterole)
        AND bool_and(rolinherit)
        AND bool_and(NOT rolreplication)
        AND bool_and(NOT rolbypassrls)
        AND NOT pg_catalog.pg_has_role(
            :'wardnet_runtime_principal',
            'wardnet_state_owner',
            'MEMBER'
        )
        AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_roles elevated_role
            WHERE (
                elevated_role.rolsuper
                OR elevated_role.rolcreatedb
                OR elevated_role.rolcreaterole
                OR elevated_role.rolreplication
                OR elevated_role.rolbypassrls
            )
              AND pg_catalog.pg_has_role(
                  :'wardnet_runtime_principal',
                  elevated_role.oid,
                  'MEMBER'
              )
        )
        AND NOT pg_catalog.has_table_privilege(
            :'wardnet_runtime_principal',
            'public.reputation_source_generation',
            'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        )
        AND NOT pg_catalog.has_any_column_privilege(
            :'wardnet_runtime_principal',
            'public.reputation_source_generation',
            'INSERT,UPDATE,REFERENCES'
        )
        AND NOT pg_catalog.has_table_privilege(
            :'wardnet_runtime_principal',
            'public.reputation_source_publication',
            'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        )
        AND NOT pg_catalog.has_any_column_privilege(
            :'wardnet_runtime_principal',
            'public.reputation_source_publication',
            'INSERT,UPDATE,REFERENCES'
        )
        AND NOT pg_catalog.has_table_privilege(
            :'wardnet_runtime_principal',
            'public.reputation_source_publication_head',
            'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        )
        AND NOT pg_catalog.has_any_column_privilege(
            :'wardnet_runtime_principal',
            'public.reputation_source_publication_head',
            'INSERT,UPDATE,REFERENCES'
        )
        AND NOT pg_catalog.has_function_privilege(
            :'wardnet_runtime_principal',
            'public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)',
            'EXECUTE'
        )
        AND (
            SELECT
                count(*) = 0
                    OR (
                        count(*) = 1
                        AND bool_and(NOT membership.admin_option)
                        AND bool_and(membership.inherit_option)
                        AND bool_and(NOT membership.set_option)
                    )
            FROM pg_catalog.pg_auth_members membership
            JOIN pg_catalog.pg_roles granted_role
              ON granted_role.oid = membership.roleid
            JOIN pg_catalog.pg_roles member_role
              ON member_role.oid = membership.member
            WHERE granted_role.rolname = 'wardnet_runtime'
              AND member_role.rolname = :'wardnet_runtime_principal'
        )
        AND NOT EXISTS (
            WITH RECURSIVE alternate_memberships(roleid) AS (
                SELECT membership.roleid
                FROM pg_catalog.pg_auth_members membership
                JOIN pg_catalog.pg_roles member_role
                  ON member_role.oid = membership.member
                JOIN pg_catalog.pg_roles granted_role
                  ON granted_role.oid = membership.roleid
                WHERE member_role.rolname = :'wardnet_runtime_principal'
                  AND granted_role.rolname <> 'wardnet_runtime'
                UNION
                SELECT membership.roleid
                FROM pg_catalog.pg_auth_members membership
                JOIN alternate_memberships inherited
                  ON inherited.roleid = membership.member
            )
            SELECT 1
            FROM alternate_memberships inherited
            JOIN pg_catalog.pg_roles inherited_role
              ON inherited_role.oid = inherited.roleid
            WHERE inherited_role.rolname = 'wardnet_runtime'
        ) AS runtime_principal_safe
FROM pg_catalog.pg_roles
WHERE rolname = :'wardnet_runtime_principal'
\gset

\if :runtime_principal_safe
\else
DO $wardnet_unsafe_runtime_principal$
BEGIN
    RAISE EXCEPTION 'Wardnet runtime principal mapping refused: principal is absent, non-login, non-inheriting, privileged, state-owner capable, already has Wardnet mutation/inner-admission authority, or already has an unbounded runtime membership path.';
END
$wardnet_unsafe_runtime_principal$;
\endif

-- format(%I) is the sole conversion from the supplied identity string to a SQL
-- identifier. INHERIT exposes only wardnet_runtime object privileges; SET FALSE
-- prevents the login from changing current_user to the capability role, and
-- ADMIN FALSE prevents delegation of the capability to another principal.
SELECT pg_catalog.format(
    'GRANT wardnet_runtime TO %I WITH ADMIN FALSE, INHERIT TRUE, SET FALSE',
    :'wardnet_runtime_principal'
)
\gexec

SELECT
    count(*) = 1
        AND bool_and(NOT membership.admin_option)
        AND bool_and(membership.inherit_option)
        AND bool_and(NOT membership.set_option) AS runtime_mapping_complete
FROM pg_catalog.pg_auth_members membership
JOIN pg_catalog.pg_roles granted_role
  ON granted_role.oid = membership.roleid
JOIN pg_catalog.pg_roles member_role
  ON member_role.oid = membership.member
WHERE granted_role.rolname = 'wardnet_runtime'
  AND member_role.rolname = :'wardnet_runtime_principal'
\gset

\if :runtime_mapping_complete
    COMMIT;
\else
DO $wardnet_runtime_mapping_failed$
BEGIN
    RAISE EXCEPTION 'Wardnet runtime principal mapping refused: bounded membership postcondition is incomplete.';
END
$wardnet_runtime_mapping_failed$;
\endif
