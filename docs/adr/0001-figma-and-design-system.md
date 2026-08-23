# ADR 0001 — Figma design-system source and embedded admin console

Status: accepted  
Date: 2026-08-23

## Context

Wardnet ships an operator console as vanilla HTML/CSS/JS embedded in the Rust
binary (`ADMIN_HTML` in `src/lib.rs`, served at `GET /` and `/admin`). Repeating
objects (KPI tiles, cards, tables, badges, buttons, forms, toasts) must stay
token-based. A Node Storybook toolchain cannot be loaded by that console without
a separate static site.

## Decision

- Canonical design-system tokens live in CSS custom properties on `:root`
  (`docs/design-system.md` matches the running `/admin` CSS).
- Figma is the visual mirror, not a runtime dependency. **Figma Code Connect is
  not used** (repo `AGENTS.md`).
- Record file IDs here so operators and agents can open the same files.

## Figma file IDs

| Artifact | File ID | URL |
| --- | --- | --- |
| Design system / console frames | `QTH5UuU0FJv2VyM2xb02Fp` | https://www.figma.com/design/QTH5UuU0FJv2VyM2xb02Fp |
| Enterprise product architecture FigJam | `JExziD87eUWKLERECUGhWQ` | https://www.figma.com/board/JExziD87eUWKLERECUGhWQ |

## Scene and edge-case events

Scene-by-scene and edge-case event definitions for the ten UI-UX areas live in
`docs/ui-ux/storybook-scene-inventory.md`, which opens from disk (`file://`)
without a Node Storybook server. That inventory is the Storybook-equivalent
contract for this embedded-console architecture.

## Consequences

- Token changes must land in `ADMIN_HTML` and `docs/design-system.md` together.
- Do not add a frontend framework to `/admin`; it would break the
  binary-embedded load path used by `scripts/smoke.sh`.
