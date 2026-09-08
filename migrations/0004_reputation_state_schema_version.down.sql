-- Roll only the migration-owned reputation-state compatibility receipt back to
-- the complete 0003 boundary. Immutable generation/publication state remains.

BEGIN;

DO $wardnet_schema_version_rollback$
DECLARE
    version_row_count bigint;
    current_version integer;
BEGIN
    IF to_regclass('public.wardnet_schema_version') IS NULL THEN
        RAISE EXCEPTION 'Wardnet schema-version rollback refused: migration-owned version receipt is absent.';
    END IF;

    SELECT count(*), max(schema_version)
    INTO version_row_count, current_version
    FROM public.wardnet_schema_version
    WHERE component = 'reputation_state';

    IF version_row_count <> 1 OR current_version <> 4 THEN
        RAISE EXCEPTION 'Wardnet schema-version rollback refused: expected exact reputation_state schema version 4.';
    END IF;

    IF (SELECT count(*) FROM public.wardnet_schema_version) <> 1 THEN
        RAISE EXCEPTION 'Wardnet schema-version rollback refused: unexpected component receipt requires diagnosis.';
    END IF;
END
$wardnet_schema_version_rollback$;

DROP TABLE public.wardnet_schema_version;

COMMIT;
