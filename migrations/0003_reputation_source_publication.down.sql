-- Roll publication state back to the preceding source-generation admission boundary.
--
-- Generation history admitted by migrations 0001..0002 is intentionally
-- preserved so a rollback/reapply cycle cannot rebind an existing generation
-- token or ordinal. Drop the publication capability before its backing tables,
-- then remove the head before immutable publication history because the head
-- references publication rows.

BEGIN;

DROP FUNCTION IF EXISTS public.wardnet_publish_reputation_source_generation(
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
);

DROP TABLE IF EXISTS public.reputation_source_publication_head;
DROP TABLE IF EXISTS public.reputation_source_publication;

COMMIT;
