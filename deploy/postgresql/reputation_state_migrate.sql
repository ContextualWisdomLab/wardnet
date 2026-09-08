-- Canonical startup migration sequencer for Wardnet-owned PostgreSQL reputation
-- state. It serializes deployers for the entire multi-transaction migration
-- sequence and refuses unknown/partial or future schema boundaries before any
-- mutation. Cluster roles and runtime grants remain owned by the separate role
-- installer; application repository authority remains disabled.
--
-- PostgreSQL session advisory locks are intentional here: migrations 0001..0004
-- each own their transaction, while this lock must survive those commits until
-- the whole startup sequence has reached one verified durable boundary.
\set ON_ERROR_STOP on

SELECT pg_catalog.pg_advisory_lock(
    pg_catalog.hashtextextended('wardnet.reputation_state.schema_migration', 0)
);

-- Supported startup inputs are deliberately narrow:
--   * empty: no migration-owned reputation-state objects exist;
--   * complete 0003: all durable publication objects exist, version receipt absent;
--   * versioned: complete publication boundary plus the version receipt.
-- Any mixture is diagnostic evidence, not permission to normalize a schema.
SELECT
    to_regclass('public.reputation_source_generation') IS NULL
        AND to_regprocedure(
            'public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)'
        ) IS NULL
        AND to_regclass('public.reputation_source_publication') IS NULL
        AND to_regclass('public.reputation_source_publication_head') IS NULL
        AND to_regprocedure(
            'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)'
        ) IS NULL
        AND to_regclass('public.wardnet_schema_version') IS NULL AS empty_schema,
    to_regclass('public.reputation_source_generation') IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'reputation_source_generation'
              AND column_name = 'provenance_ref'
              AND data_type = 'text'
              AND is_nullable = 'NO'
        )
        AND to_regprocedure(
            'public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)'
        ) IS NOT NULL
        AND to_regclass('public.reputation_source_publication') IS NOT NULL
        AND to_regclass('public.reputation_source_publication_head') IS NOT NULL
        AND to_regprocedure(
            'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)'
        ) IS NOT NULL
        AND (
            SELECT count(*) = 3
            FROM pg_catalog.pg_class
            WHERE oid IN (
                to_regclass('public.reputation_source_generation'),
                to_regclass('public.reputation_source_publication'),
                to_regclass('public.reputation_source_publication_head')
            )
              AND relrowsecurity
              AND relforcerowsecurity
        )
        AND to_regclass('public.wardnet_schema_version') IS NULL AS supported_v3_schema,
    to_regclass('public.reputation_source_generation') IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'reputation_source_generation'
              AND column_name = 'provenance_ref'
              AND data_type = 'text'
              AND is_nullable = 'NO'
        )
        AND to_regprocedure(
            'public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)'
        ) IS NOT NULL
        AND to_regclass('public.reputation_source_publication') IS NOT NULL
        AND to_regclass('public.reputation_source_publication_head') IS NOT NULL
        AND to_regprocedure(
            'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)'
        ) IS NOT NULL
        AND (
            SELECT count(*) = 3
            FROM pg_catalog.pg_class
            WHERE oid IN (
                to_regclass('public.reputation_source_generation'),
                to_regclass('public.reputation_source_publication'),
                to_regclass('public.reputation_source_publication_head')
            )
              AND relrowsecurity
              AND relforcerowsecurity
        )
        AND to_regclass('public.wardnet_schema_version') IS NOT NULL AS versioned_schema
\gset

\if :empty_schema
    \ir ../../migrations/0001_reputation_source_generation.sql
    \ir ../../migrations/0002_reputation_source_generation_admission.sql
    \ir ../../migrations/0003_reputation_source_publication.sql
    \ir ../../migrations/0004_reputation_state_schema_version.sql
\elif :supported_v3_schema
    \ir ../../migrations/0004_reputation_state_schema_version.sql
\elif :versioned_schema
    -- Reading the migration-owned columns is itself a fail-closed shape check:
    -- a foreign relation with this name but an incompatible layout errors here
    -- before any mutation occurs.
    SELECT
        count(*) = 1
            AND min(component) = 'reputation_state'
            AND min(schema_version) = 4 AS schema_version_current,
        count(*) = 1
            AND min(component) = 'reputation_state'
            AND min(schema_version) > 4 AS schema_version_future
    FROM public.wardnet_schema_version
    \gset

    \if :schema_version_current
        \echo 'Wardnet reputation_state schema is already at supported version 4.'
    \elif :schema_version_future
        DO $wardnet_future_schema$
        BEGIN
            RAISE EXCEPTION 'Wardnet reputation_state schema is newer than supported Wardnet schema version 4.';
        END
        $wardnet_future_schema$;
    \else
        DO $wardnet_unsupported_version$
        BEGIN
            RAISE EXCEPTION 'Wardnet startup migration refused: unsupported or partial schema-version receipt requires diagnosis.';
        END
        $wardnet_unsupported_version$;
    \endif
\else
    DO $wardnet_partial_schema$
    BEGIN
        RAISE EXCEPTION 'Wardnet startup migration refused: partial reputation-state schema requires diagnosis.';
    END
    $wardnet_partial_schema$;
\endif

-- Verify the exact supported postcondition before releasing serialization.
SELECT
    to_regclass('public.reputation_source_generation') IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'reputation_source_generation'
              AND column_name = 'provenance_ref'
              AND data_type = 'text'
              AND is_nullable = 'NO'
        )
        AND to_regprocedure(
            'public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)'
        ) IS NOT NULL
        AND to_regclass('public.reputation_source_publication') IS NOT NULL
        AND to_regclass('public.reputation_source_publication_head') IS NOT NULL
        AND to_regprocedure(
            'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)'
        ) IS NOT NULL
        AND (
            SELECT count(*) = 3
            FROM pg_catalog.pg_class
            WHERE oid IN (
                to_regclass('public.reputation_source_generation'),
                to_regclass('public.reputation_source_publication'),
                to_regclass('public.reputation_source_publication_head')
            )
              AND relrowsecurity
              AND relforcerowsecurity
        )
        AND to_regclass('public.wardnet_schema_version') IS NOT NULL
        AND (
            SELECT count(*) = 1
                AND min(component) = 'reputation_state'
                AND min(schema_version) = 4
            FROM public.wardnet_schema_version
        ) AS migration_complete
\gset

\if :migration_complete
    SELECT pg_catalog.pg_advisory_unlock(
        pg_catalog.hashtextextended('wardnet.reputation_state.schema_migration', 0)
    ) AS migration_lock_released
    \gset
    \if :migration_lock_released
        \echo 'Wardnet reputation_state startup migration reached supported version 4.'
    \else
        DO $wardnet_unlock_failed$
        BEGIN
            RAISE EXCEPTION 'Wardnet startup migration completed but could not release its advisory lock.';
        END
        $wardnet_unlock_failed$;
    \endif
\else
    DO $wardnet_postcondition_failed$
    BEGIN
        RAISE EXCEPTION 'Wardnet startup migration refused readiness: supported schema postcondition is incomplete.';
    END
    $wardnet_postcondition_failed$;
\endif
