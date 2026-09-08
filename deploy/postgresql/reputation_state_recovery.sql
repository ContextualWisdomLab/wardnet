-- Re-converge Wardnet's least-privilege reputation publication authority after
-- schema rollback/reapply or restore has recreated publication functions.
--
-- Schema recovery and capability-role recovery are intentionally separate:
-- migrations own schema objects, while reputation_state_roles.sql remains the
-- canonical deployment-time owner for cluster roles and positive grants. This
-- recovery sequencer reuses that owner and may only make the boundary stricter
-- by withholding runtime publication while authoritative evidence is missing.
--
-- `\ir` resolves relative to this script, so operators can stage/run the two
-- deployment artifacts together without depending on the caller's cwd.
\set ON_ERROR_STOP on
\ir reputation_state_roles.sql

-- A supported 0003 rollback intentionally removes publication history and the
-- last-known-good head while preserving admitted generation identity. Reapply
-- plus role convergence must not turn that surviving identity into permission
-- to establish an unrelated `expected_prior = NULL` head. Withhold the runtime
-- publication capability globally while any recovered source chain has durable
-- generation identity but no authoritative publication head. The deployment /
-- recovery principal may replay verified evidence through the SECURITY DEFINER
-- capability; rerunning this script then re-enables the bounded runtime grant
-- through the canonical role installer once every such evidence gap is closed.
DO $wardnet_recovery$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.reputation_source_generation AS generation
        WHERE NOT EXISTS (
            SELECT 1
            FROM public.reputation_source_publication_head AS head
            WHERE head.tenant_id = generation.tenant_id
              AND head.source_id = generation.source_id
        )
    ) THEN
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
    END IF;
END
$wardnet_recovery$;
