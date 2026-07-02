# Security Policy

This repository is an early security product MVP. Treat all deployments as test or lab deployments until the production hardening checklist is complete.

## Supported Versions

Only the default branch is supported during initial development.

## Reporting Vulnerabilities

Open a private security advisory in GitHub or contact the repository maintainers through the ContextualWisdomLab organization.

Do not include live customer secrets, packet captures, credentials, or production payloads in public issues.

## Deployment Guardrails

- The service binds to `127.0.0.1:8080` by default.
- Set `ADMIN_TOKEN` before exposing management APIs beyond localhost.
- Use TLS and an upstream identity proxy before remote administration.
- Treat route, threat, DNSBL, license, and threat-feed POST/write APIs as privileged management surfaces.
- Treat AI-generated SOC recommendations as advisory until a human approves enforcement changes.
- Do not enable block mode against production traffic without route-specific rollback and allowlist procedures.
- Do not put `ADMIN_TOKEN`, upstream credentials, or customer payload secrets into support bundles or public issues.
