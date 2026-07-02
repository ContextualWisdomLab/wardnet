# Enterprise Product Architecture FigJam

## Artifact

- FigJam: https://www.figma.com/board/JExziD87eUWKLERECUGhWQ?utm_source=codex&utm_content=edit_in_figjam&oai_id=&request_id=a97d2861-82f8-4d43-9d16-27e07b13b10c&architecture=true
- Title: WAF IDS AI SOC 2B KRW Product Architecture
- Figma Code Connect: not used

## Source Architecture

```mermaid
flowchart LR
  buyer["Enterprise Buyer Lab"] --> console["Web Admin Console"]
  operator["SOC Operator"] --> console
  console --> api["Management API"]
  api --> app["waf-ids-ai-soc App Crate"]
  app --> core["waf-ids-core Domain Crate"]
  core --> scoring["Scoring and Readiness"]
  core --> dnsbl["DNSBL Zone Export"]
  core --> kpis["SOC KPI Snapshot"]
  feed["Threat Feed Import"] --> api
  gateway["API Gateway Traffic"] --> app
  app --> upstream["Configured Upstream"]
  app --> state["Optional JSON State"]
  app --> bundle["Support Bundle"]
  bundle --> buyer
```

## Design Notes

- The visible product should read as an operator console first.
- Architecture proof should emphasize the Rust memory-safety boundary and small reusable core.
- Buyer evidence should connect directly to APIs, docs, deployment assets, tests, and support bundle output.
- Future engine integrations should be presented as adapters, not as hidden hand-rolled WAF/IDS logic.
