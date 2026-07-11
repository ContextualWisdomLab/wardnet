# Agent Instructions

- Keep the project Rust-first for gateway, DNSBL, and high-throughput control-plane code.
- Prefer proven security engines over fake in-house detections. Integrate OWASP CRS/Coraza, Suricata, STIX/TAXII, MISP, or OpenCTI before inventing equivalent engines.
- Do not use Figma Code Connect for this project unless explicitly requested later.
- Keep MVP work narrow: web management, gateway decisions, event/KPI visibility, and DNSBL publishing before broader SIEM/SOAR scope.
- Run `cargo fmt --check` and `cargo test` before claiming code is ready.

<!-- BEGIN cwl-agent-guidance -->
## Agent guidance (CWL governance)

Cross-agent conventions for any agent (Claude, Codex, Cursor, opencode, …) working in this repo.

### Security & review gate

- Every PR runs a central **Security Scan** required gate: `osv-scan` + `dependency-review` (diff-scoped) and `trivy-fs` (repo-wide, CRITICAL/HIGH, fixable). It runs against every PR base, **including stacked PRs**.
- A failing **`trivy-fs` is a REAL finding, not a flake.** Read the job log — it prints each finding's rule id / severity / file — or the run's SARIF results, then **remediate**:
  - Rust dependency CVE → bump the crate (`cargo update -p <crate>`, adjust `Cargo.toml`) and commit the updated `Cargo.lock`.
  - Container/OS finding → fix the base image or package in the `Dockerfile`.
  - k8s/IaC misconfig → fix `deploy/kubernetes/waf-ids-ai-soc.yaml` or `deploy/docker-compose.yml`.
  - Genuine false positive only → add a narrow, commented entry to `.trivyignore` (see the existing `AVD-KSV-0125` note for the expected style). Never broaden it to silence a real vuln.
- Do **not** weaken or disable the gate. A local scan with a stale DB misses findings: run `trivy --download-db-only` first, then scan the **merge ref**, not just the PR head (e.g. `trivy fs --scanners vuln,misconfig --severity CRITICAL,HIGH --ignore-unfixed .`).
- Gating is by the Security Scan **job result**, not the `code_scanning` rule. That org ruleset is intentionally **CodeQL-only** (multiple code-scanning tools can't converge on one PR ref) — do **not** add tools to it.

### Code exploration

- There is no `.codegraph/` index in this repo, so use normal search (grep/ripgrep, `cargo` tooling, editor navigation). If a `.codegraph/` index is added later, prefer CodeGraph (`codegraph explore "<query>"` or the code-review-graph MCP tools) before grep/find — it surfaces callers/callees/impact that text search misses.

### Config & secrets (KV, not env)

- Org rule: do **not** read config/secrets from raw environment variables (`std::env::var` / `os.getenv`) at runtime. Read them from a KV / credential registry. Org Actions secrets (e.g. `OPENAI_API_KEY`) flow **into** the KV via a bootstrap/CI step; runtime reads from the KV — env is only transport into the KV, never the runtime source.
- Reference implementation: xtrmLLMBatchPython's pgcrypto-encrypted Postgres credential registry (`get_credential(name)`). Reuse that pattern (a DB-backed KV is fine) unless a dedicated KV is adopted.
- **Known deviation to migrate:** `src/main.rs` currently reads secrets/config directly via `std::env::var` — auth tokens `ADMIN_TOKEN` / `ADMIN_TOKENS` plus operational config (`BIND_ADDR`, `WAF_IDS_STATE_PATH`, `DNSBL_ORIGIN`, `EVENT_LIMIT`, `RATE_LIMIT`). Move the secret-bearing values (the admin tokens first) behind a `get_credential`-style KV lookup; env may remain only as the bootstrap transport that seeds the KV.

### This repo's role in the ecosystem

- **This repo (`waf-ids-ai-soc`) is the WAF / IDS / AI SOC / software load balancer / APIM for the ecosystem.** It fronts and protects the other components and mediates their traffic.
- The org is an ecosystem around **naruon** (the hub: an email/PIM that DOM-decomposes emails and files into a persisted knowledge graph). Every component is a standalone program that must **also** work as a git submodule, grown separately and together.
- Sibling components: **clearfolio** (document viewer), **pg-erd-cloud** (ERD tool), **contextual-orchestrator** (LLM cost/perf/upstream-LB gateway, beyond LiteLLM), **codec-carver** (STT/omni-modal speech-video codec), **fast-mlsirm** (LLM-as-a-Judge calibration + evaluation-item quality, using aFIPC FIPC + kaefa item-fit), **feelanet-adfs** (passwordless SSO: OIDC/SCIM/ADFS/LDAP/FIDO2/OAuth2.1, eliminate passwords), **newsdom-api** (PDF→DOM sidecar), and **semantic-data-portal** (upper-ontology/catalog/governance plane with its own graph engine).

### Research grounding (attach paper PDFs)

- Org rule: substantive feature/process PRs should find the relevant academic papers and **commit their PDFs into the PR** (e.g. a `docs/papers/` or `references/` dir) with full citations, respecting copyright — attach the PDF only when redistribution is permissible; otherwise cite + link + summarize.
- For this repo's domain, ground changes in the relevant literature — e.g. **load-balancing and anomaly-detection** research (WAF/IDS detection models, adaptive/DDoS-aware load balancing) for detection, routing, and rate-limiting work.
<!-- END cwl-agent-guidance -->

