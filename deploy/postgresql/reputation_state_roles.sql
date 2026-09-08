-- Least-privilege capability roles for Wardnet reputation-state publication.
--
-- Run this after migrations 0001..0003 as the database migration/cluster
-- administrator. These are NOLOGIN capability roles: credentials and login
-- principals stay in the deployment/IAM boundary rather than this repository
-- artifact. Schema migrations intentionally do not create cluster roles.
--
-- The outer publication function is SECURITY DEFINER. Its owner therefore gets
-- only the table/function privileges needed by that bounded transaction. The
-- runtime capability receives read access and outer-function EXECUTE, never
-- direct mutation or inner-admission authority.

DO $wardnet_roles$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles
        WHERE rolname = 'wardnet_state_owner'
    ) THEN
        EXECUTE 'CREATE ROLE wardnet_state_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles
        WHERE rolname = 'wardnet_runtime'
    ) THEN
        EXECUTE 'CREATE ROLE wardnet_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION';
    END IF;
END
$wardnet_roles$;

-- Converge pre-existing capability roles back to the required attributes.
ALTER ROLE wardnet_state_owner WITH
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
ALTER ROLE wardnet_runtime WITH
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;

REVOKE ALL PRIVILEGES ON TABLE
    public.reputation_source_generation,
    public.reputation_source_publication,
    public.reputation_source_publication_head
FROM wardnet_state_owner, wardnet_runtime;

REVOKE EXECUTE ON FUNCTION public.wardnet_admit_reputation_source_generation(
    text,
    text,
    text,
    bigint,
    bigint,
    text
) FROM wardnet_runtime;
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

-- PostgreSQL requires the new function owner to have CREATE on the containing
-- schema during ownership transfer. Grant it only for that operation and revoke
-- it immediately afterward so the state owner cannot create arbitrary objects.
GRANT USAGE, CREATE ON SCHEMA public TO wardnet_state_owner;

GRANT SELECT, INSERT ON TABLE public.reputation_source_generation
    TO wardnet_state_owner;
GRANT EXECUTE ON FUNCTION public.wardnet_admit_reputation_source_generation(
    text,
    text,
    text,
    bigint,
    bigint,
    text
) TO wardnet_state_owner;
GRANT SELECT, INSERT ON TABLE public.reputation_source_publication
    TO wardnet_state_owner;
GRANT SELECT, INSERT, UPDATE ON TABLE public.reputation_source_publication_head
    TO wardnet_state_owner;

ALTER FUNCTION public.wardnet_publish_reputation_source_generation(
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
) OWNER TO wardnet_state_owner;

REVOKE CREATE ON SCHEMA public FROM wardnet_state_owner;
GRANT USAGE ON SCHEMA public TO wardnet_state_owner, wardnet_runtime;
REVOKE CREATE ON SCHEMA public FROM wardnet_runtime;

GRANT SELECT ON TABLE
    public.reputation_source_generation,
    public.reputation_source_publication,
    public.reputation_source_publication_head
TO wardnet_runtime;
GRANT EXECUTE ON FUNCTION public.wardnet_publish_reputation_source_generation(
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
) TO wardnet_runtime;

-- Converge away any historical over-grants after the intended runtime grants
-- are installed. The outer publication EXECUTE capability remains the sole
-- mutation path exposed to the runtime role.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE
    public.reputation_source_generation,
    public.reputation_source_publication,
    public.reputation_source_publication_head
FROM wardnet_runtime;
REVOKE EXECUTE ON FUNCTION public.wardnet_admit_reputation_source_generation(
    text,
    text,
    text,
    bigint,
    bigint,
    text
) FROM wardnet_runtime;
