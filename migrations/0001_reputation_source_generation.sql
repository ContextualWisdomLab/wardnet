-- Wardnet reputation-source generation history.
--
-- This first durable PostgreSQL slice owns only immutable, tenant-scoped
-- generation identity. The runtime repository adapter remains disabled until
-- its separate port and transaction contracts are complete.

CREATE TABLE reputation_source_generation (
    tenant_id text NOT NULL
        CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    source_id text NOT NULL
        CHECK (source_id <> '' AND source_id = btrim(source_id)),
    source_generation text NOT NULL
        CHECK (source_generation <> '' AND source_generation = btrim(source_generation)),
    source_generation_ordinal bigint NOT NULL
        CHECK (source_generation_ordinal >= 0),
    completed_at_unix bigint NOT NULL
        CHECK (completed_at_unix >= 0),
    provenance_ref text NOT NULL
        CHECK (provenance_ref <> '' AND provenance_ref = btrim(provenance_ref)),
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT reputation_source_generation_token_key
        PRIMARY KEY (tenant_id, source_id, source_generation),
    CONSTRAINT reputation_source_generation_ordinal_key
        UNIQUE (tenant_id, source_id, source_generation_ordinal)
);

REVOKE ALL ON TABLE reputation_source_generation FROM PUBLIC;

ALTER TABLE reputation_source_generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE reputation_source_generation FORCE ROW LEVEL SECURITY;

CREATE POLICY reputation_source_generation_tenant_read
    ON reputation_source_generation
    FOR SELECT
    USING (
        tenant_id = nullif(current_setting('wardnet.tenant_id', true), '')
    );

CREATE POLICY reputation_source_generation_tenant_insert
    ON reputation_source_generation
    FOR INSERT
    WITH CHECK (
        tenant_id = nullif(current_setting('wardnet.tenant_id', true), '')
    );

COMMENT ON TABLE reputation_source_generation IS
    'Immutable tenant-scoped reputation source generation history.';
COMMENT ON COLUMN reputation_source_generation.source_generation IS
    'Source-issued generation token, unique within one tenant and source.';
COMMENT ON COLUMN reputation_source_generation.source_generation_ordinal IS
    'Monotonic source ordinal identity; ordering enforcement remains repository-owned.';
COMMENT ON COLUMN reputation_source_generation.provenance_ref IS
    'Credential-free immutable reference to completion provenance evidence.';
