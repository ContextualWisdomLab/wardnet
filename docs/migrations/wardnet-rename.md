# Wardnet rename

The product, Rust packages, binary, container image, deployment resources, and
documentation now use `wardnet`. Operators should rename persisted volume and
image references during deployment.

Two environment names remain as temporary startup-only compatibility aliases:

- `WAF_IDS_STATE_PATH` falls back when `WARDNET_STATE_PATH` is unset.
- `WAF_IDS_CREDENTIALS_PATH` falls back when `WARDNET_CREDENTIALS_PATH` is unset.

The `WARDNET_*` names take precedence when both are present. The aliases exist
only to avoid breaking an existing deployment during migration; new
configuration must use `WARDNET_*`.

Prometheus metrics are now emitted with the `wardnet_` prefix. The previous
`waf_ids_` series are emitted in parallel as deprecated compatibility aliases
so existing dashboards and alerts continue to work during migration.
