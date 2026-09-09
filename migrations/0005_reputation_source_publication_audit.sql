-- Attributable audit evidence for tenant-scoped reputation-source publication.
--
-- Audit evidence is emitted by an AFTER INSERT trigger inside the same durable
-- transaction as the immutable publication and last-known-good head. The typed
-- repository supplies actor/decision references through transaction-local GUCs;
-- unaudited legacy calls remain compatible while production authority stays
-- disabled. Exact replay performs no INSERT and therefore cannot duplicate audit.
--
-- Schema version 4 is the sole supported input. Startup migration serialization
-- remains owned by deploy/postgresql/reputation_state_migrate.sql.

BEGIN;

DO $wardnet_audit_version_guard$
DECLARE
    version_row_count bigint;
    current_version integer;
BEGIN
    IF to_regclass('public.wardnet_schema_version') IS NULL THEN
        RAISE EXCEPTION 'Wardnet publication-audit migration refused: schema-version receipt is absent.';
    END IF;

    SELECT count(*), max(schema_version)
    INTO version_row_count, current_version
    FROM public.wardnet_schema_version
    WHERE component = 'reputation_state';

    IF version_row_count <> 1 OR current_version <> 4 THEN
        RAISE EXCEPTION 'Wardnet publication-audit migration refused: expected exact reputation_state schema version 4.';
    END IF;

    IF to_regclass('public.reputation_source_publication_audit') IS NOT NULL
       OR to_regprocedure('public.wardnet_record_reputation_source_publication_audit()') IS NOT NULL THEN
        RAISE EXCEPTION 'Wardnet publication-audit migration refused: audit objects already exist outside version 5.';
    END IF;
END
$wardnet_audit_version_guard$;

CREATE TABLE public.reputation_source_publication_audit (
    tenant_id text NOT NULL
        CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    source_id text NOT NULL
        CHECK (source_id <> '' AND source_id = btrim(source_id)),
    source_generation text NOT NULL
        CHECK (source_generation <> '' AND source_generation = btrim(source_generation)),
    actor_subject_id text NOT NULL
        CHECK (actor_subject_id <> '' AND actor_subject_id = btrim(actor_subject_id)),
    decision_id text NOT NULL
        CHECK (decision_id <> '' AND decision_id = btrim(decision_id)),
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT reputation_source_publication_audit_key
        PRIMARY KEY (tenant_id, source_id, source_generation),
    CONSTRAINT reputation_source_publication_audit_publication_fk
        FOREIGN KEY (tenant_id, source_id, source_generation)
        REFERENCES public.reputation_source_publication (tenant_id, source_id, source_generation)
        ON DELETE RESTRICT
);

REVOKE ALL ON TABLE public.reputation_source_publication_audit FROM PUBLIC;

ALTER TABLE public.reputation_source_publication_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reputation_source_publication_audit FORCE ROW LEVEL SECURITY;

CREATE POLICY reputation_source_publication_audit_tenant_read
    ON public.reputation_source_publication_audit
    FOR SELECT
    USING (
        tenant_id = nullif(current_setting('wardnet.tenant_id', true), '')
    );

CREATE POLICY reputation_source_publication_audit_tenant_insert
    ON public.reputation_source_publication_audit
    FOR INSERT
    WITH CHECK (
        tenant_id = nullif(current_setting('wardnet.tenant_id', true), '')
    );

CREATE FUNCTION public.wardnet_record_reputation_source_publication_audit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actor_subject text := nullif(current_setting('wardnet.actor_subject_id', true), '');
    publication_decision text := nullif(current_setting('wardnet.decision_id', true), '');
BEGIN
    IF actor_subject IS NULL AND publication_decision IS NULL THEN
        RETURN NEW;
    END IF;

    IF actor_subject IS NULL OR publication_decision IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'reputation_source_publication_audit_context_incomplete';
    END IF;

    INSERT INTO public.reputation_source_publication_audit (
        tenant_id,
        source_id,
        source_generation,
        actor_subject_id,
        decision_id
    )
    VALUES (
        NEW.tenant_id,
        NEW.source_id,
        NEW.source_generation,
        actor_subject,
        publication_decision
    );

    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.wardnet_record_reputation_source_publication_audit() FROM PUBLIC;

CREATE TRIGGER reputation_source_publication_audit_after_insert
AFTER INSERT ON public.reputation_source_publication
FOR EACH ROW
EXECUTE FUNCTION public.wardnet_record_reputation_source_publication_audit();

UPDATE public.wardnet_schema_version
SET schema_version = 5,
    recorded_at = transaction_timestamp()
WHERE component = 'reputation_state'
  AND schema_version = 4;

DO $wardnet_audit_version_postcondition$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM public.wardnet_schema_version
        WHERE component = 'reputation_state'
          AND schema_version = 5
    ) THEN
        RAISE EXCEPTION 'Wardnet publication-audit migration failed to record schema version 5.';
    END IF;
END
$wardnet_audit_version_postcondition$;

COMMENT ON TABLE public.reputation_source_publication_audit IS
    'One tenant-scoped actor/decision attribution record for each audited immutable reputation-source publication.';
COMMENT ON COLUMN public.reputation_source_publication_audit.actor_subject_id IS
    'Validated identity-subject reference supplied by the Wardnet repository transaction; not a credential or principal owner.';
COMMENT ON COLUMN public.reputation_source_publication_audit.decision_id IS
    'Validated decision reference that caused the immutable publication.';
COMMENT ON FUNCTION public.wardnet_record_reputation_source_publication_audit() IS
    'Records optional transaction-local actor/decision attribution atomically with a newly inserted publication; exact replay emits no duplicate audit.';

COMMIT;
