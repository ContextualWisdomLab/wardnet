-- Re-converge Wardnet's publication schema and least-privilege authority from
-- supported recovery states without normalizing an unknown partial boundary.
--
-- Migrations remain the canonical schema owner and reputation_state_roles.sql
-- remains the canonical owner for cluster roles and positive grants. This file
-- sequences those owners and may only make the resulting runtime capability
-- stricter while authoritative publication evidence is missing.
--
-- `\ir` resolves relative to this script, so the recovery tree can be staged
-- and executed independently of the caller's working directory.
\set ON_ERROR_STOP on

-- The publication layer still has only two recoverable structural inputs:
--   * complete 0002: the entire publication boundary is absent; or
--   * complete 0003-or-later: publication tables and outer capability exist.
-- Anything between those states needs diagnosis. Once the complete publication
-- layer exists, the canonical serialized startup migrator owns version 3 -> 5,
-- version 4 -> 5, current-version replay, and future/partial refusal.
SELECT
    to_regclass('public.reputation_source_publication') IS NULL
        AND to_regclass('public.reputation_source_publication_head') IS NULL
        AND to_regprocedure(
            'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)'
        ) IS NULL AS publication_boundary_absent,
    to_regclass('public.reputation_source_publication') IS NOT NULL
        AND to_regclass('public.reputation_source_publication_head') IS NOT NULL
        AND to_regprocedure(
            'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)'
        ) IS NOT NULL AS publication_boundary_complete
\gset

\if :publication_boundary_absent
    \ir ../../migrations/0003_reputation_source_publication.sql
\elif :publication_boundary_complete
    \echo 'Wardnet publication schema is structurally complete; reconverging supported version.'
\else
    DO $wardnet_partial_recovery$
    BEGIN
        RAISE EXCEPTION 'Wardnet recovery refused: partial publication schema requires diagnosis.';
    END
    $wardnet_partial_recovery$;
\endif

\ir reputation_state_migrate.sql
\ir reputation_state_roles.sql

-- A supported publication rollback intentionally removes publication history
-- and the last-known-good head while preserving admitted generation identity.
-- Reapply plus role convergence must not turn that surviving identity into
-- permission to establish an unrelated `expected_prior = NULL` head. Withhold
-- the runtime publication capability globally while any recovered source chain
-- has durable generation identity but no authoritative publication head. The
-- deployment/recovery principal may replay verified evidence through the
-- SECURITY DEFINER capability; rerunning this script then re-enables the bounded
-- runtime grant through the canonical role installer once every evidence gap is
-- closed.
DO $wardnet_recovery$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.reputation_source_generation AS generation
        WHERE NOT EXISTS (
            SELECT 1
            FROM public.reputation_source_publication_head AS head
            WHERE head.tenant_id = generation.tenant_id
              AND head.source_id = generation.source_id
        )
    ) THEN
        REVOKE EXECUTE ON FUNCTION public.wardnet_publish_reputation_source_generation(
            text,
            text,
            text,
            text,
            bigint,
            bigint,
            text,
            text,
            text,
            text
        ) FROM wardnet_runtime;
    END IF;
END
$wardnet_recovery$;
