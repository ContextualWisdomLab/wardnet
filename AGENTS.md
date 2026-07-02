# Agent Instructions

- Keep the project Rust-first for gateway, DNSBL, and high-throughput control-plane code.
- Prefer proven security engines over fake in-house detections. Integrate OWASP CRS/Coraza, Suricata, STIX/TAXII, MISP, or OpenCTI before inventing equivalent engines.
- Do not use Figma Code Connect for this project unless explicitly requested later.
- Keep MVP work narrow: web management, gateway decisions, event/KPI visibility, and DNSBL publishing before broader SIEM/SOAR scope.
- Run `cargo fmt --check` and `cargo test` before claiming code is ready.
