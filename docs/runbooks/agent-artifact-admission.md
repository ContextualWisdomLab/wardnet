# Agent Artifact Admission operations runbook

This runbook applies only to the `wardnet-agent-artifact-admission` bounded context. It is a pre-execution admission service; it does not install packages or execute commands.

## Safe deployment profile

The v0.1 service is intentionally loopback-only. Do not bind it directly to a LAN or Internet address. If another host must call it, keep Wardnet on loopback and place an authenticated TLS/mTLS or equivalent identity-aware proxy on the same host.

Create three local files with restrictive filesystem permissions:

1. the reviewed admission policy/configuration;
2. the credential file containing the administrator token;
3. an appendable audit destination owned by the service account.

Start from the committed deny-all example. A deny-all policy is an operationally safe initial state because it proves connectivity, authentication and audit durability without granting package authority.

Example process launch:

```bash
cargo run --locked --bin wardnet-agent-artifact-admission -- \
  --config ./agent-artifact-admission.json \
  --credentials ./agent-artifact-admission.credentials.json
```

The process must fail startup when configuration is malformed, the bind is non-loopback, the port is zero, credentials cannot be loaded, or required policy invariants are invalid.

## Health and authentication

`GET /healthz` is the non-secret process probe. It may report policy identifiers and bounded counts, but must not return the administrator token, policy secrets, request bodies or audit-path details.

`GET /v1/policy` and `POST /v1/admissions` require exactly one `X-Admin-Token` header. Missing, duplicate, malformed or incorrect credentials return `401` and must never disclose the configured token or a masked fragment of it.

Example probe:

```bash
curl -fsS http://127.0.0.1:8091/healthz
```

Authenticated policy inspection:

```bash
curl -fsS \
  -H "X-Admin-Token: ${WARDNET_ADMISSION_ADMIN_TOKEN:?}" \
  http://127.0.0.1:8091/v1/policy
```

The environment variable in this shell example is only a client-side convenience. The Wardnet service itself loads its administrator token from the configured credentials file, not from a runtime secret environment variable.

## Admission behavior

A valid request is a structured JSON `InstallIntent`. Never send a shell command string. Policy denials are normal application decisions and return a successful admission response whose body contains `decision=block`; a caller must not reinterpret that as a transport failure or search for a workaround.

Malformed structural input returns `400` after the minimized rejection fact has been appended to the audit log. A request above the configured body limit returns `413`, also only after its rejection has been durably audited. Authentication failures return `401` and intentionally do not process an admission decision.

An allow response is valid only after its audit record has been appended. If audit append, audit-record construction or the blocking audit task fails, Wardnet returns `503` with a block decision and the stable `audit_unavailable` reason. Operators must treat any `503` as fail-closed; never retry by bypassing Wardnet.

## Policy rollout

Treat the reviewed policy as immutable deployment configuration in v0.1.

1. Build the candidate policy from independently reviewed package evidence, not from agent-generated text.
2. Pin exact ecosystem, package name, version, registry, owner, SHA-256 and approved workspace-manifest digest.
3. Validate external provenance with its owning system where used. A registry string or package name alone is not publisher proof.
4. Run contract tests and a representative set of blocked and allowed intents before deployment.
5. Replace the configuration atomically according to the host deployment mechanism.
6. Restart the service and verify `/healthz` policy identifiers before the execution broker resumes admissions.
7. Retain the previous reviewed policy for rollback.

Do not add a runtime policy mutation endpoint as an operational shortcut. That would introduce a new policy-lifecycle aggregate, authorization model and audit contract and therefore requires an explicit architecture change.

## Audit operations

The audit file contains minimized decision facts only. It must not contain raw administrator tokens or raw command text.

Operational expectations:

- place the file on durable storage appropriate to the deployment;
- restrict read/write access to the Wardnet service account and approved security operators;
- ship or rotate it only through a process that preserves append ordering and provenance;
- monitor filesystem capacity and write failures;
- alert when `audit_unavailable` responses occur;
- do not truncate or rewrite evidence in place as a normal recovery action.

If the audit destination is unavailable, restore audit durability first. The correct degraded mode is blocked admissions, not unlogged allows.

## Incident response

### Unexpected allow

1. Stop the downstream execution broker from acting on new allow receipts.
2. Preserve the policy file, credential-file metadata, service binary identity and relevant audit records.
3. Identify the exact request ID, policy ID/revision, command digest and artifact coordinates from the receipt/audit fact.
4. Reproduce the decision with the same structured intent against the same policy revision.
5. Determine whether the defect is policy evidence, domain evaluation, adapter translation or downstream execution behavior.
6. Fix the owning boundary test-first. Do not add a one-off string denylist in the HTTP adapter if the invariant belongs to the domain policy.

### Audit unavailable

1. Confirm the service is returning `503`/`audit_unavailable`; this is the expected safe state.
2. Check ownership, permissions, filesystem capacity, path availability and host I/O errors without exposing audit content broadly.
3. Restore the append path and restart only if required by the host environment.
4. Submit a known blocked intent and confirm a new minimized record is appended before re-enabling the execution broker.

### Credential exposure

1. Stop callers that use the exposed credential.
2. Replace the credential file through the host secret-management process and restart the service.
3. Verify the old token is rejected and the new token succeeds.
4. Review access logs outside Wardnet for the exposure window; Wardnet's own admission audit intentionally does not record raw credentials.

### Suspected policy tampering

1. Freeze execution downstream.
2. Compare the deployed policy and workspace-manifest SHA-256 values with the reviewed source-of-truth revision.
3. Revert to the last reviewed policy if provenance cannot be established.
4. Treat the event as a supply-chain incident; a valid-looking package registry entry is not sufficient proof of legitimacy.

## Rollback

Rollback is configuration plus process rollback, not audit rollback. Restore the previous reviewed policy/configuration and, if necessary, the previous verified service artifact. Keep the audit trail intact. Verify health, authentication, a known-denied intent and one approved test fixture before allowing the execution broker to resume.

## Release acceptance

Before promoting a Wardnet build containing this context, require on the unchanged exact head:

- `cargo fmt --check`;
- locked workspace tests, including HTTP authentication, audit ordering/failure, provenance and DDD architecture contracts;
- strict Clippy with warnings denied;
- repository fuzz/property invariants where configured;
- SAST/security/SBOM/provenance gates required by live GitHub policy;
- zero valid unresolved review findings;
- the independent approval required by the live ruleset.

Queued, pending, skipped-required, cancelled, absent, stale or predecessor-head evidence is not release evidence.

## Ownership and escalation

Agent Artifact Admission owns the install-intent policy and minimized admission receipt. Execution brokers own process sandboxing and the actual install/execute step. Sigstore, TUF and SLSA remain external evidence authorities. Central CWL `.github` owns organization-wide workflow/review controls. A failure in one of those owners must be repaired at that owner boundary rather than duplicated inside this crate.
