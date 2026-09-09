-- Roll attributable publication-audit schema version 5 back to exact version 4.
-- Immutable publication/generation state remains authoritative and untouched.

BEGIN;

DO $wardnet_audit_rollback_guard$
DECLARE
    version_row_count bigint;
    current_version integer;
BEGIN
    IF to_regclass('public.wardnet_schema_version') IS NULL THEN
        RAISE EXCEPTION 'Wardnet publication-audit rollback refused: schema-version receipt is absent.';
    END IF;

    SELECT count(*), max(schema_version)
    INTO version_row_count, current_version
    FROM public.wardnet_schema_version
    WHERE component = 'reputation_state';

    IF version_row_count <> 1 OR current_version <> 5 THEN
        RAISE EXCEPTION 'Wardnet publication-audit rollback refused: expected exact reputation_state schema version 5.';
    END IF;
END
$wardnet_audit_rollback_guard$;

DROP TRIGGER reputation_source_publication_audit_after_insert
    ON public.reputation_source_publication;
DROP FUNCTION public.wardnet_record_reputation_source_publication_audit();
DROP TABLE public.reputation_source_publication_audit;

UPDATE public.wardnet_schema_version
SET schema_version = 4,
    recorded_at = transaction_timestamp()
WHERE component = 'reputation_state'
  AND schema_version = 5;

DO $wardnet_audit_rollback_postcondition$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM public.wardnet_schema_version
        WHERE component = 'reputation_state'
          AND schema_version = 4
    ) THEN
        RAISE EXCEPTION 'Wardnet publication-audit rollback failed to restore schema version 4.';
    END IF;
END
$wardnet_audit_rollback_postcondition$;

COMMIT;
