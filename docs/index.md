---
title: Wardnet
---

# Wardnet

Wardnet is a Rust-first gateway and security-operations control plane for governed traffic policy, threat evidence, DNSBL operations, request enforcement, and operator handoff.

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ContextualWisdomLab/wardnet)

## Start here

Use the [repository README](https://github.com/ContextualWisdomLab/wardnet#readme) for the current product boundary, maturity, local quick start, management APIs, deployment guidance, and verification posture. Wardnet deliberately does not present its current source as a complete hardened WAF, IDS, SIEM, or SOAR.

## Product responsibility

Wardnet owns its gateway and SOC control-plane surface: route policy, current local threat and DNSBL evidence, request scoring and enforcement mode, operational evidence, support handoff, and bounded management APIs. Proven external WAF/IDS engines, SIEM and telemetry destinations, threat-intelligence providers, model routing, identity, TLS, secrets, and deployment topology remain independently authoritative.

## Documentation

- [README](https://github.com/ContextualWisdomLab/wardnet#readme) — product overview, quick start, maturity, security and verification.
- [Architecture](https://github.com/ContextualWisdomLab/wardnet/blob/main/docs/architecture.md) — system boundaries and integration responsibilities.
- [Product and technical gap baseline](https://github.com/ContextualWisdomLab/wardnet/blob/main/docs/product-technical-gap-baseline.md) — current gaps and evidence status when present on protected `main`.
- [Operations](https://github.com/ContextualWisdomLab/wardnet/tree/main/docs/runbooks) — operator and recovery guidance.
- [Releases](https://github.com/ContextualWisdomLab/wardnet/releases) — immutable release evidence when published.
- [Ask DeepWiki](https://deepwiki.com/ContextualWisdomLab/wardnet) — repository-grounded navigation and questions.

## Evidence boundary

A source version, readiness endpoint, passing test, support bundle, or open pull request is not by itself a production deployment, certification, customer adoption, or published release. Repository-facing claims should remain bound to protected source and the applicable immutable release, deployment, and verification evidence.

This file is a GitHub Pages source prerequisite. Its presence does not mean GitHub Pages is published; publication is complete only after repository settings are reconciled, deployment succeeds, and the live HTTPS site is verified.
