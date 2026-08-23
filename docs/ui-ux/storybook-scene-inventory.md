# Admin console — scene and edge-case event inventory

**Open this file from disk:** `file://` on
`docs/ui-ux/storybook-scene-inventory.md`. It is the Storybook-equivalent
contract for Wardnet’s **embedded** console (`ADMIN_HTML` in `src/lib.rs`).

A Node Storybook (`storybookjs/storybook`) cannot be hosted inside `/admin`
without a separate static site the binary does not serve. This inventory
defines scenes, edge-case events, and the ten UI-UX areas so operators and
agents can review interaction without a JS toolchain. Tokens remain the source
for repeating objects (`docs/design-system.md`, Figma `QTH5UuU0FJv2VyM2xb02Fp`).

Companion skills used while authoring: Storybook scene thinking, UI-UX Pro Max
checklists, Anti-Slop-UI (no generic dashboard chrome; this console is an
operator instrument panel).

## How to exercise each scene

1. `cargo run` (loopback; optional `ADMIN_TOKEN=dev-secret`).
2. Open `http://127.0.0.1:8080/admin`.
3. Drive the event in the table. Expected result is the operator’s next action,
   not a status narrative.

## Ten UI-UX areas

| Area | Console contract | Edge-case events |
| --- | --- | --- |
| Accessibility | Skip link, wrapping labels, `th scope`, live regions, High Contrast `aria-pressed`, text+colour badges | Keyboard-only create-route; High Contrast + focus ring visible on every control; screen-reader hears KPI refresh (`aria-live=polite`) and toast (`assertive`) |
| Touch & Interaction | Controls `min-height: 44px` (WCAG 2.5.5) | Tap primary save on a 390px-wide viewport; toast auto-dismiss ~4.5s; do not rely on hover |
| Performance | No framework, no extra network for CSS/JS; `Promise.allSettled` per card | One failing `/api/*` card shows `.err` and does not blank the page; large event list capped at 25 with truncation copy |
| Style Selection | Default tokens vs High Contrast (`data-theme=hc`, `localStorage["waf-theme"]`) | Toggle High Contrast, reload, theme persists; never raw hex on a component |
| Layout & Responsive | Card grid `repeat(auto-fit, minmax(340px, 1fr))` | 1280px desktop and 390px mobile: header, KPI strip, and create forms remain usable; no horizontal trap |
| Typography & Color | `--fs-h1/h2/body/cap/metric`; WCAG table in design-system.md | Body `--ink` vs `--sub`; destructive `--fail` always with the word Block/Fail/Stale |
| Animation | None beyond toast dismiss; no decorative motion | Toast appears and leaves without blocking the next write |
| Forms & Feedback | `label.field` + `.field-help` matching server validators; toast `ok`/`bad` | Path without leading `/` → server error in toast; valid route → toast + table refresh; empty collection → `.empty` “No entries.” |
| Navigation Patterns | Single-page console; skip link to `#main`; header token field | Tab order: skip → token → High Contrast → main cards; `/` and `/admin` render the same console |
| Charts & Data | KPI tiles (not charts) + tables + raw `pre` for NDJSON/JSON/zone | KPI `…` while loading then numbers from `/api/kpis`; readiness checklist pass/fail rows; raw DNSBL zone is faithful text, not a redesigned chart |

## Scene catalog (Storybook CSF analogue)

Each scene is `(id, setup, event, expected next action)`.

| Scene ID | Setup | Event | Expected next action |
| --- | --- | --- | --- |
| `kpi.strip.loaded` | Seeded state | Page load | Read route/threat/DNSBL/block counts; if Block is non-zero, open Events |
| `kpi.strip.error` | Stop API | Page load | Card/strip shows error copy; rest of page remains |
| `routes.table.empty` | No routes | Open Routes | “No entries.” then open the create `<details>` |
| `routes.create.ok` | Token set | Submit path `/secure`, upstream `mock://x`, mode Block | Toast success; table shows the row; next: send a gateway request |
| `routes.create.validation` | Token set | Submit path `secure` (no slash) | Toast with server validator text; fix the path |
| `routes.create.unauth` | Empty token, auth required | Submit create | Toast unauthorized; paste `X-Admin-Token` |
| `routes.create.forbidden` | Readonly token | Submit create | HTTP 403 / toast; switch to a write token |
| `threats.import.feed` | Token set | Import a reviewed feed | Toast upsert counts; open Freshness |
| `feeds.freshness.stale` | TTL expired feed | Open Freshness | Stale badge (text+colour); re-import or disable |
| `license.detail` | Seeded license | Open License | Definition list; missing optionals render `—` |
| `readiness.not-ready` | Missing license fields | Open Commercial readiness | Not-ready badge + one evidence string per failed check |
| `events.ndjson.export` | At least one blocked event | Open raw export | Copy NDJSON for SIEM; do not reformat |
| `dnsbl.zone.export` | Seeded DNSBL | Open zone | Copy RFC 5782 zone text to the authoritative DNS publisher |
| `audit.readonly` | Readonly token | Open audit logs | Table of writes; no create controls succeed |
| `theme.high-contrast` | Default theme | Toggle High Contrast | Borders `#000`; reload keeps theme |
| `gateway.block.demo` | Block route `/secure` | `GET /gateway/secure` | Blocked event appears; next: confirm KPI blocked count |

## Storybook (Node) — deferred

If a future pass adds a static `storybook/` package, CSF stories must mount
the same CSS tokens (not a parallel palette) and replay the events above.
Until then this file is the inventory of record. Do not claim `/admin` loads
Storybook.
