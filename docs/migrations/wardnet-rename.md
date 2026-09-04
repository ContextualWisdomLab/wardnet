# Wardnet rename

The product, Rust packages, binary, container image, deployment resources, and
documentation now use `wardnet`. The rename changes durable deployment
identifiers as well as labels. Treat an existing installation as a data
migration, not as a fresh deployment.

Two environment names remain as temporary startup-only compatibility aliases:

- `WAF_IDS_STATE_PATH` falls back when `WARDNET_STATE_PATH` is unset.
- `WAF_IDS_CREDENTIALS_PATH` falls back when `WARDNET_CREDENTIALS_PATH` is unset.

The `WARDNET_*` names take precedence when both are present. The aliases exist
only to avoid breaking an existing deployment during migration; new
configuration must use `WARDNET_*`.

## Preserve state before first Wardnet startup

Copy existing state before starting Wardnet. Do not start the renamed workload
against an empty destination and then copy state over it: an empty state
location can be initialized with seeded state, making it ambiguous which copy
is authoritative. Stop writes to the old workload, retain a rollback copy of
`state.json`, and verify the copied file by size and SHA-256 before starting the
new workload. Keep the old storage read-only until the renamed workload has
loaded the expected routes, threat indicators, DNSBL entries, feeds, and event
history.

The deployment mappings are:

| Deployment | Existing state | Wardnet state | Required cutover |
| --- | --- | --- | --- |
| Docker | `/var/lib/waf-ids-ai-soc/state.json` | `/var/lib/wardnet/state.json` | Stop the old container, copy the existing `state.json` to the new mount or volume, preserve ownership for runtime UID/GID `10001`, verify the copy, then start the Wardnet container. |
| Docker Compose | logical volume `waf_ids_state` | logical volume `wardnet_state` | Stop the old service, copy `state.json` from the old named volume into the new named volume before `docker compose up`, verify the copy, and retain the old volume for rollback. Remember that Compose may prefix the actual volume name with the project name. |
| Kubernetes | PVC `waf-ids-ai-soc-state` | PVC `wardnet-state` | Scale the old writer to zero, snapshot/clone or export/import `state.json` into storage backing `wardnet-state`, verify it before starting the new Deployment, and retain the old PVC/snapshot until validation completes. PVCs are namespaced; do not assume the new `wardnet` namespace can mount the old claim directly. |

The environment alias alone does not migrate a container path, Compose volume,
or Kubernetes PVC. If an operator intentionally keeps the old storage instead
of copying it, the runtime path must still resolve to that storage explicitly
and the rollback plan must record that choice.

## Migrate the Kubernetes administrator Secret before the Deployment

The renamed manifest requires `wardnet-admin` in namespace `wardnet` and reads
its `ADMIN_TOKEN` key with `optional: false`. Existing installations commonly
have only `waf-ids-ai-soc-admin`; Kubernetes Secrets are namespaced and are not
renamed automatically.

For an existing cluster, create the `wardnet` namespace first, then have the
organization's secret-management control plane create or synchronize
`wardnet-admin` with the required `ADMIN_TOKEN`. If the approved migration
procedure copies the value from `waf-ids-ai-soc-admin`, perform that copy
through the secret-management boundary rather than committing or echoing the
secret into repository files or shell history. Confirm that `wardnet-admin`
exists and contains the expected key before you apply `deploy/kubernetes/wardnet.yaml`.
The Deployment intentionally has no literal fallback and should remain unable
to start if the Secret is absent.

After state and Secret migration are verified, apply `deploy/kubernetes/wardnet.yaml`,
wait for readiness, compare buyer/operator state and audit evidence with the
pre-migration snapshot, and only then retire the old workload. A failed
readiness or state comparison means roll back to the retained old
workload/storage; do not delete the old PVC, volume, or Secret as part of the
same change that first starts Wardnet.

## Metrics compatibility

Prometheus metrics are now emitted with the `wardnet_` prefix. The previous
`waf_ids_` series are emitted in parallel as deprecated compatibility aliases
so existing dashboards and alerts continue to work during migration.
