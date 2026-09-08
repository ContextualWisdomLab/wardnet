-- Re-converge Wardnet's least-privilege reputation publication authority after
-- schema rollback/reapply or restore has recreated publication functions.
--
-- Schema recovery and capability-role recovery are intentionally separate:
-- migrations own schema objects, while reputation_state_roles.sql remains the
-- canonical deployment-time owner for cluster roles and grants. Keep this file
-- as sequencing only; do not duplicate role or privilege statements here.
--
-- `\ir` resolves relative to this script, so operators can stage/run the two
-- deployment artifacts together without depending on the caller's cwd.
\set ON_ERROR_STOP on
\ir reputation_state_roles.sql
