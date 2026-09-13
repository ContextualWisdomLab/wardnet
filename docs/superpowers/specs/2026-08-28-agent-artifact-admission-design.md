# Agent Artifact Admission Controller Design

- Status: Proposed for implementation
- Date: 2026-08-28
- Issue: #128
- Owning repository: `ContextualWisdomLab/wardnet`

## Problem

AI coding agents can read `llms.txt`, `llms-full.txt`, README fragments, issue comments, retrieved pages, or tool output and translate text into package installation or code execution. The source document is not an authority for package ownership, registry identity, artifact integrity, or execution permission. A newly registered package name or domain can therefore turn a model hallucination or poisoned document into dependency confusion inside a trusted network.

Wardnet currently protects HTTP traffic, ingests threat evidence, and provides an AI SOC control plane, but it does not expose a pre-execution admission boundary for coding-agent package operations. A WAF signature alone cannot solve this: the decision must bind the proposed command to a reviewed dependency manifest and immutable artifact identity before the package manager or downloader runs.

## Goal

Add an independently deployable Rust service, `wardnet-agent-artifact-admission`, that answers one question:

> May this actor execute this exact structured package-install command, from this exact instruction source, against this reviewed manifest and these exact content-addressed artifacts?

The service never executes commands. It emits a deterministic allow/block decision and a durable audit record. An execution broker, CI runner, OpenCode/Codex/Claude/Hermes wrapper, or MCP tool must require an `allow` decision before invoking a package manager.

## Security invariants

1. Web pages, `llms.txt`, tool output, issue comments, and model text are untrusted data.
2. Source text cannot create package ownership, artifact trust, or execution capability.
3. Requests contain an argument vector (`argv`), never a shell command string.
4. An empty policy allows nothing.
5. The executable must be explicitly allowlisted and must not be a forbidden shell, downloader, package executor, or runtime-eval path.
6. Every direct artifact must match policy by ecosystem, exact name, exact version, normalized HTTPS registry URL, owner, and SHA-256 digest.
7. Every artifact must identify the exact argument token that represents it; that token must appear exactly once in `argv`.
8. The workspace dependency-manifest SHA-256 must match a reviewed policy entry.
9. Remote instruction sources require an HTTPS URI without user information and a SHA-256 content digest.
10. Package-manager hardening flags are mandatory: npm-family installs ignore lifecycle scripts, Python installs require hashes, Cargo installs use the lockfile, and container pulls use an image digest.
11. Policy and credentials are immutable for the process lifetime; changes require a reviewed configuration update and restart.
12. An allow response is returned only after the audit record has been appended and synchronized. Audit failure becomes a block with HTTP 503.
13. Audit data contains no admin token and no raw command text.
14. v0.1 binds only to a loopback address. Remote exposure is delegated to an authenticated TLS or mTLS proxy.

## Architecture

```text
AI coding agent / execution broker
             |
             | structured install intent
             v
+-----------------------------------------------+
| Wardnet Agent Artifact Admission Controller    |
|                                               |
| authentication -> structural validation       |
| -> source provenance -> command restrictions  |
| -> manifest admission -> artifact admission   |
| -> append-only audit -> allow/block response  |
+-----------------------------------------------+
             |
             | allow receipt only
             v
sandboxed package-manager executor
```

The controller is a separate workspace crate rather than a route in the existing large Wardnet gateway module. This keeps the executable independently deployable, limits privileges, and avoids giving the main gateway a command-execution responsibility.

## Files and components

```text
crates/agent-artifact-admission/
├── Cargo.toml
├── src/
│   ├── lib.rs          public API and re-exports
│   ├── model.rs        strict request, policy, response, and audit types
│   ├── policy.rs       pure validation and deterministic admission decision
│   ├── audit.rs        append-only NDJSON audit sinks
│   ├── config.rs       config, credential, and strict CLI loading
│   ├── http.rs         Axum routes, authentication, and audit-before-allow
│   └── main.rs         thin process entrypoint
└── tests/
    ├── admission_contract.rs
    ├── http_contract.rs
    └── cli_contract.rs
```

## Request contract

`POST /v1/admissions` receives JSON with unknown fields rejected:

```json
{
  "request_id": "req-20260828-0001",
  "actor_id": "agent:codex:workspace-17",
  "workspace_id": "ContextualWisdomLab/wardnet",
  "operation": "install",
  "argv": ["npm", "install", "@cwl/example@1.2.3", "--ignore-scripts"],
  "manifest_sha256": "64-lowercase-hex",
  "source": {
    "kind": "llms_txt",
    "uri": "https://example.invalid/llms.txt",
    "content_sha256": "64-lowercase-hex"
  },
  "artifacts": [
    {
      "ecosystem": "npm",
      "name": "@cwl/example",
      "version": "1.2.3",
      "registry_url": "https://registry.npmjs.org",
      "owner": "ContextualWisdomLab",
      "sha256": "64-lowercase-hex",
      "artifact_argument": "@cwl/example@1.2.3"
    }
  ]
}
```

The response is HTTP 200 for both policy allow and policy block:

```json
{
  "request_id": "req-20260828-0001",
  "decision": "block",
  "reason_codes": ["artifact_not_approved"],
  "policy_id": "enterprise-default",
  "policy_revision": "2026-08-28.1",
  "normalized_source_uri": "https://example.invalid/llms.txt",
  "command_sha256": "64-lowercase-hex",
  "artifact_count": 1
}
```

HTTP status communicates transport/auth/service state only:

- `200`: a durable allow/block decision exists
- `400`: malformed or structurally invalid request, durably audited when authentication succeeded
- `401`: missing, duplicate, malformed, or incorrect admin token
- `413`: body limit exceeded
- `503`: audit durability unavailable; execution must not proceed

## Policy contract

The service configuration contains:

- `configuration_version = "1"`
- loopback `bind_address`
- bounded `max_request_body_bytes`
- mandatory `audit_log_path`
- immutable `policy`

The policy contains:

- stable `policy_id` and `policy_revision`
- explicit `allowed_executables`
- reviewed workspace manifest digests
- exact approved artifact identities

Policy validation rejects duplicates, malformed digests, insecure registry URLs, unbounded strings, forbidden executables, wildcard or moving versions (`latest`, `main`, ranges), and entries without review provenance.

## Command restrictions

The following executables are always blocked even if named by policy:

- shells and command interpreters (`sh`, `bash`, `zsh`, `cmd`, `powershell`, `pwsh`)
- direct download clients (`curl`, `wget`, `aria2c`, `ftp`, `scp`)
- package executors (`npx`, `pnpx`, `bunx`)

Language runtimes are blocked when command arguments request inline evaluation (`-c`, `-e`, `--eval`, or `--execute`). Package-manager options that create an alternate trust root, such as `--extra-index-url` and `--trusted-host`, are blocked.

Safe-flag requirements are deterministic:

- `npm`, `pnpm`, `yarn`, `bun`: `--ignore-scripts`
- `pip`, `pip3`, and `uv pip`: `--require-hashes`
- `cargo install`: `--locked`
- `docker pull` and `podman pull`: argument includes `@sha256:<approved digest>`

## Authentication

Both `/v1/policy` and `/v1/admissions` require exactly one `X-Admin-Token`. `/healthz` is unauthenticated and exposes only status, policy identity, and counts. The token is read from a credentials JSON file supplied with `--credentials`; runtime environment variables are not a credential source. Comparison uses a fixed-size constant-time buffer and constant-time length equality.

## Audit contract

Each authenticated admission attempt produces one NDJSON record containing:

- timestamp
- request, actor, and workspace IDs
- operation
- decision and reason codes
- policy identity
- normalized source kind and URI
- source content digest
- command digest, not raw `argv`
- reviewed manifest digest
- artifact coordinates and digests

The file sink serializes writers, appends one bounded JSON line, flushes, and synchronizes data before success. A memory sink is provided for embedding/tests. Audit serialization or I/O errors fail closed.

## Error handling

- Validation returns stable machine-readable reason codes in deterministic order.
- Multiple defects may be returned together so an operator can remediate one request without repeated trial-and-error.
- Error messages never contain the admin token, raw command, query string, URL fragment, or unbounded upstream text.
- Malformed authenticated JSON is identified by a body SHA-256-derived request surrogate and audited without storing the body.

## Verification

Tests must cover:

- the reported attack shape: unowned package from `llms.txt` is blocked
- exact approved artifact and reviewed manifest is allowed
- registry, owner, version, digest, manifest, or argument mismatch blocks
- moving/unpinned versions block
- remote source without HTTPS or source digest blocks
- source query/fragment removed from audit/response
- shell/downloader/package-executor/runtime-eval commands block
- missing package-manager safety flags block
- duplicate artifacts, arguments, and policy entries block
- missing/duplicate/wrong/non-ASCII/oversized tokens return 401
- no token or raw command appears in audit output
- malformed authenticated JSON is audited and returns 400
- audit failure converts any candidate decision to HTTP 503/block
- loopback-only configuration and strict CLI parsing
- property tests for arbitrary input never panic and never allow without a complete exact policy match
- SHA-256 NIST-known vectors

Merge requires exact-head formatting, locked workspace tests, strict Clippy, central security checks, current-head review, zero unresolved actionable threads, and the live independent-approval rule.

## Deployment

The process starts with:

```text
wardnet-agent-artifact-admission \
  --config /etc/wardnet/agent-artifact-admission.json \
  --credentials /run/secrets/wardnet-agent-artifact-admission.json
```

The committed example policy has no approved manifests or artifacts and therefore blocks every install. Operators create policy entries through code review or a separate policy delivery system; there is no mutation API in v0.1.

## Non-goals

- executing package managers or shell commands
- inferring package ownership from website content
- automatically repairing hallucinated package names
- dynamically registering or probing package names
- replacing package registry verification, TUF, Sigstore, SLSA provenance, or sandboxing
- allowing model output to mutate policy
- exposing the service directly to a non-loopback network

## Follow-up boundaries

- integrate the admission call into central OpenCode/Codex/Claude/Hermes execution brokers
- accept signed policy bundles through TUF/Sigstore instead of local files
- emit OCSF/OTLP through Wardnet's SIEM export path
- add a durable PostgreSQL/outbox audit backend
- add sandbox execution receipts and post-install filesystem/network attestation
- add transitive dependency graph verification and SBOM comparison
