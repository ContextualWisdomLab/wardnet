-- Tenant-scoped idempotent admission for immutable reputation-source generations.
--
-- This migration deliberately exposes only an atomic admission function over
-- the generation-history relation created by 0001. It does not enable the
-- production PostgreSQL repository adapter or publish evidence snapshots.

CREATE FUNCTION public.wardnet_admit_reputation_source_generation(
    p_tenant_id text,
    p_source_id text,
    p_source_generation text,
    p_source_generation_ordinal bigint,
    p_completed_at_unix bigint,
    p_provenance_ref text
)
RETURNS text
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    token_binding public.reputation_source_generation%ROWTYPE;
    ordinal_binding public.reputation_source_generation%ROWTYPE;
BEGIN
    IF p_tenant_id IS DISTINCT FROM nullif(current_setting('wardnet.tenant_id', true), '') THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'reputation_source_generation_tenant_context_mismatch';
    END IF;

    BEGIN
        INSERT INTO public.reputation_source_generation (
            tenant_id,
            source_id,
            source_generation,
            source_generation_ordinal,
            completed_at_unix,
            provenance_ref
        )
        VALUES (
            p_tenant_id,
            p_source_id,
            p_source_generation,
            p_source_generation_ordinal,
            p_completed_at_unix,
            p_provenance_ref
        );

        RETURN 'committed';
    EXCEPTION
        WHEN unique_violation THEN
            SELECT *
            INTO token_binding
            FROM public.reputation_source_generation
            WHERE tenant_id = p_tenant_id
              AND source_id = p_source_id
              AND source_generation = p_source_generation;

            IF FOUND THEN
                IF token_binding.source_generation_ordinal = p_source_generation_ordinal
                   AND token_binding.completed_at_unix = p_completed_at_unix
                   AND token_binding.provenance_ref = p_provenance_ref THEN
                    RETURN 'replay';
                END IF;

                RAISE EXCEPTION USING
                    ERRCODE = '23505',
                    MESSAGE = 'reputation_source_generation_replay_conflict';
            END IF;

            SELECT *
            INTO ordinal_binding
            FROM public.reputation_source_generation
            WHERE tenant_id = p_tenant_id
              AND source_id = p_source_id
              AND source_generation_ordinal = p_source_generation_ordinal;

            IF FOUND THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23505',
                    MESSAGE = 'reputation_source_generation_ordinal_conflict';
            END IF;

            RAISE;
    END;
END;
$$;

REVOKE ALL ON FUNCTION public.wardnet_admit_reputation_source_generation(
    text,
    text,
    text,
    bigint,
    bigint,
    text
) FROM PUBLIC;

COMMENT ON FUNCTION public.wardnet_admit_reputation_source_generation(
    text,
    text,
    text,
    bigint,
    bigint,
    text
) IS
    'Admits one immutable tenant/source generation binding; exact duplicates replay idempotently and divergent token/ordinal reuse fails closed.';
