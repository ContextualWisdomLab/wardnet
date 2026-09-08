-- Atomic publication boundary for tenant-scoped reputation-source generations.
--
-- Publication couples immutable generation identity, evidence/completeness
-- references, producer lifecycle identity, and the last-known-good pointer in
-- one PostgreSQL transaction. The production runtime adapter remains disabled
-- until its separate repository, pooling, migration, and recovery contracts
-- are complete.

CREATE TABLE reputation_source_publication (
    tenant_id text NOT NULL
        CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    source_id text NOT NULL
        CHECK (source_id <> '' AND source_id = btrim(source_id)),
    prior_source_generation text
        CHECK (
            prior_source_generation IS NULL
            OR (prior_source_generation <> '' AND prior_source_generation = btrim(prior_source_generation))
        ),
    source_generation text NOT NULL
        CHECK (source_generation <> '' AND source_generation = btrim(source_generation)),
    source_generation_ordinal bigint NOT NULL
        CHECK (source_generation_ordinal >= 0),
    completed_at_unix bigint NOT NULL
        CHECK (completed_at_unix >= 0),
    provenance_ref text NOT NULL
        CHECK (provenance_ref <> '' AND provenance_ref = btrim(provenance_ref)),
    evidence_snapshot_ref text NOT NULL
        CHECK (evidence_snapshot_ref <> '' AND evidence_snapshot_ref = btrim(evidence_snapshot_ref)),
    completeness_ref text NOT NULL
        CHECK (completeness_ref <> '' AND completeness_ref = btrim(completeness_ref)),
    producer_lifecycle_ref text NOT NULL
        CHECK (producer_lifecycle_ref <> '' AND producer_lifecycle_ref = btrim(producer_lifecycle_ref)),
    published_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT reputation_source_publication_token_key
        PRIMARY KEY (tenant_id, source_id, source_generation),
    CONSTRAINT reputation_source_publication_ordinal_key
        UNIQUE (tenant_id, source_id, source_generation_ordinal),
    CONSTRAINT reputation_source_publication_generation_token_fk
        FOREIGN KEY (tenant_id, source_id, source_generation)
        REFERENCES reputation_source_generation (tenant_id, source_id, source_generation),
    CONSTRAINT reputation_source_publication_generation_ordinal_fk
        FOREIGN KEY (tenant_id, source_id, source_generation_ordinal)
        REFERENCES reputation_source_generation (tenant_id, source_id, source_generation_ordinal),
    CONSTRAINT reputation_source_publication_prior_fk
        FOREIGN KEY (tenant_id, source_id, prior_source_generation)
        REFERENCES reputation_source_publication (tenant_id, source_id, source_generation)
);

CREATE TABLE reputation_source_publication_head (
    tenant_id text NOT NULL
        CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    source_id text NOT NULL
        CHECK (source_id <> '' AND source_id = btrim(source_id)),
    source_generation text NOT NULL
        CHECK (source_generation <> '' AND source_generation = btrim(source_generation)),
    source_generation_ordinal bigint NOT NULL
        CHECK (source_generation_ordinal >= 0),
    advanced_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT reputation_source_publication_head_key
        PRIMARY KEY (tenant_id, source_id),
    CONSTRAINT reputation_source_publication_head_token_fk
        FOREIGN KEY (tenant_id, source_id, source_generation)
        REFERENCES reputation_source_publication (tenant_id, source_id, source_generation),
    CONSTRAINT reputation_source_publication_head_ordinal_fk
        FOREIGN KEY (tenant_id, source_id, source_generation_ordinal)
        REFERENCES reputation_source_publication (tenant_id, source_id, source_generation_ordinal)
);

REVOKE ALL ON TABLE reputation_source_publication FROM PUBLIC;
REVOKE ALL ON TABLE reputation_source_publication_head FROM PUBLIC;

ALTER TABLE reputation_source_publication ENABLE ROW LEVEL SECURITY;
ALTER TABLE reputation_source_publication FORCE ROW LEVEL SECURITY;
ALTER TABLE reputation_source_publication_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE reputation_source_publication_head FORCE ROW LEVEL SECURITY;

CREATE POLICY reputation_source_publication_tenant_read
    ON reputation_source_publication
    FOR SELECT
    USING (
        tenant_id = nullif(current_setting('wardnet.tenant_id', true), '')
    );

CREATE POLICY reputation_source_publication_tenant_insert
    ON reputation_source_publication
    FOR INSERT
    WITH CHECK (
        tenant_id = nullif(current_setting('wardnet.tenant_id', true), '')
    );

CREATE POLICY reputation_source_publication_head_tenant_read
    ON reputation_source_publication_head
    FOR SELECT
    USING (
        tenant_id = nullif(current_setting('wardnet.tenant_id', true), '')
    );

CREATE POLICY reputation_source_publication_head_tenant_insert
    ON reputation_source_publication_head
    FOR INSERT
    WITH CHECK (
        tenant_id = nullif(current_setting('wardnet.tenant_id', true), '')
    );

CREATE POLICY reputation_source_publication_head_tenant_update
    ON reputation_source_publication_head
    FOR UPDATE
    USING (
        tenant_id = nullif(current_setting('wardnet.tenant_id', true), '')
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('wardnet.tenant_id', true), '')
    );

CREATE FUNCTION public.wardnet_publish_reputation_source_generation(
    p_tenant_id text,
    p_source_id text,
    p_expected_prior_generation text,
    p_source_generation text,
    p_source_generation_ordinal bigint,
    p_completed_at_unix bigint,
    p_provenance_ref text,
    p_evidence_snapshot_ref text,
    p_completeness_ref text,
    p_producer_lifecycle_ref text
)
RETURNS text
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    existing_publication public.reputation_source_publication%ROWTYPE;
    current_head public.reputation_source_publication_head%ROWTYPE;
BEGIN
    IF p_tenant_id IS DISTINCT FROM nullif(current_setting('wardnet.tenant_id', true), '') THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'reputation_source_publication_tenant_context_mismatch';
    END IF;

    -- Serialize one tenant/source publication chain, including its initial
    -- transition before a head row exists. Hash collisions only over-serialize
    -- unrelated sources; they cannot weaken correctness.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(p_tenant_id || pg_catalog.chr(31) || p_source_id, 0)
    );

    SELECT *
    INTO existing_publication
    FROM public.reputation_source_publication
    WHERE tenant_id = p_tenant_id
      AND source_id = p_source_id
      AND source_generation = p_source_generation;

    IF FOUND THEN
        IF existing_publication.prior_source_generation IS NOT DISTINCT FROM p_expected_prior_generation
           AND existing_publication.source_generation_ordinal = p_source_generation_ordinal
           AND existing_publication.completed_at_unix = p_completed_at_unix
           AND existing_publication.provenance_ref = p_provenance_ref
           AND existing_publication.evidence_snapshot_ref = p_evidence_snapshot_ref
           AND existing_publication.completeness_ref = p_completeness_ref
           AND existing_publication.producer_lifecycle_ref = p_producer_lifecycle_ref THEN
            RETURN 'replay';
        END IF;

        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'reputation_source_publication_conflict';
    END IF;

    SELECT *
    INTO current_head
    FROM public.reputation_source_publication_head
    WHERE tenant_id = p_tenant_id
      AND source_id = p_source_id
    FOR UPDATE;

    IF FOUND THEN
        IF p_expected_prior_generation IS DISTINCT FROM current_head.source_generation
           OR p_source_generation_ordinal <= current_head.source_generation_ordinal THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                MESSAGE = 'reputation_source_publication_conflict';
        END IF;
    ELSIF p_expected_prior_generation IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'reputation_source_publication_conflict';
    END IF;

    PERFORM public.wardnet_admit_reputation_source_generation(
        p_tenant_id,
        p_source_id,
        p_source_generation,
        p_source_generation_ordinal,
        p_completed_at_unix,
        p_provenance_ref
    );

    -- Evidence constraints intentionally execute after generation admission.
    -- Any failure below aborts the statement/transaction and therefore removes
    -- the candidate generation binding rather than exposing partial authority.
    INSERT INTO public.reputation_source_publication (
        tenant_id,
        source_id,
        prior_source_generation,
        source_generation,
        source_generation_ordinal,
        completed_at_unix,
        provenance_ref,
        evidence_snapshot_ref,
        completeness_ref,
        producer_lifecycle_ref
    )
    VALUES (
        p_tenant_id,
        p_source_id,
        p_expected_prior_generation,
        p_source_generation,
        p_source_generation_ordinal,
        p_completed_at_unix,
        p_provenance_ref,
        p_evidence_snapshot_ref,
        p_completeness_ref,
        p_producer_lifecycle_ref
    );

    IF current_head.tenant_id IS NULL THEN
        INSERT INTO public.reputation_source_publication_head (
            tenant_id,
            source_id,
            source_generation,
            source_generation_ordinal
        )
        VALUES (
            p_tenant_id,
            p_source_id,
            p_source_generation,
            p_source_generation_ordinal
        );
    ELSE
        UPDATE public.reputation_source_publication_head
        SET source_generation = p_source_generation,
            source_generation_ordinal = p_source_generation_ordinal,
            advanced_at = transaction_timestamp()
        WHERE tenant_id = p_tenant_id
          AND source_id = p_source_id;
    END IF;

    RETURN 'committed';
END;
$$;

REVOKE ALL ON FUNCTION public.wardnet_publish_reputation_source_generation(
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
) FROM PUBLIC;

COMMENT ON TABLE reputation_source_publication IS
    'Immutable tenant-scoped reputation source publication evidence and generation chain.';
COMMENT ON TABLE reputation_source_publication_head IS
    'Tenant/source last-known-good reputation publication pointer.';
COMMENT ON FUNCTION public.wardnet_publish_reputation_source_generation(
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
) IS
    'Atomically admits and publishes one evidence-complete source generation using exact-prior compare-and-swap semantics.';
