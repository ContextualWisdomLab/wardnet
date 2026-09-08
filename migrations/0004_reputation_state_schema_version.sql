-- Durable schema-version receipt for Wardnet-owned reputation state.
--
-- This migration does not create cluster roles, runtime principals, credentials,
-- or repository connections. The deployment startup sequencer owns ordering and
-- serialization; this migration owns only the durable compatibility receipt.

BEGIN;

CREATE TABLE public.wardnet_schema_version (
    component text NOT NULL
        CONSTRAINT wardnet_schema_version_component_key PRIMARY KEY
        CONSTRAINT wardnet_schema_version_component_reputation_state
            CHECK (component = 'reputation_state'),
    schema_version integer NOT NULL
        CONSTRAINT wardnet_schema_version_positive CHECK (schema_version > 0),
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

REVOKE ALL ON TABLE public.wardnet_schema_version FROM PUBLIC;

INSERT INTO public.wardnet_schema_version (component, schema_version)
VALUES ('reputation_state', 4);

COMMENT ON TABLE public.wardnet_schema_version IS
    'Migration-owned compatibility receipt for the bounded Wardnet reputation-state schema; not application authority.';
COMMENT ON COLUMN public.wardnet_schema_version.schema_version IS
    'Exact durable reputation-state schema version understood by the deployment migration sequencer.';

COMMIT;
