# WAF IDS AI SOC — Design System

Canonical reference for the admin console UI. Tokens and components are implemented
as vanilla HTML/CSS/JS embedded in the binary (`ADMIN_HTML` in `src/lib.rs`, served
by `admin_console` at `GET /` and `/admin`). The Figma mirror is file
`QTH5UuU0FJv2VyM2xb02Fp`. No build step, no framework, no runtime dependency — the
console ships inside the Rust binary and talks to the same `/api/*` endpoints as any
other client.

## Design tokens

Tokens are CSS custom properties on `:root`, overridden under `:root[data-theme="hc"]`
for High Contrast. Every colour on a component is a token — no raw hex on elements.

### Colour (with measured WCAG 2.1 contrast on white/surface)

| Token | Default | Role | Contrast vs surface | Verdict |
|-------|---------|------|--------------------:|---------|
| `--brand` | `#14213d` | header, primary action, brand badge | 14.9:1 (white on brand) | AAA |
| `--ink` | `#18202a` | body text | 16.4:1 | AAA |
| `--sub` | `#667085` | secondary text, labels | 4.97:1 | AA |
| `--on-brand` | `#ffffff` | text on brand | 15.97:1 (on brand) | AAA |
| `--pass` | `#1a7f37` | success badge/status | 5.08:1 | AA |
| `--fail` | `#b3261e` | error/critical | 6.54:1 | AA |
| `--warn` | `#9a6700` | warning | 4.87:1 | AA |
| `--border` | `#d9dee7` | dividers, field borders | 1.35:1 | decorative only¹ |
| `--canvas` | `#f7f8fa` | page background | — | — |

¹ Border contrast is below the 3:1 UI-component threshold. Borders here are **not the
sole indicator** of any state or boundary: interactive controls are identified by
their label, value, and a high-contrast (`#4c8dff`, ≈3.6:1 on white) `:focus-visible`
ring — never by border alone. Under High Contrast mode `--border` becomes `#000`
(21:1). Source values match the running server CSS exactly (verified against
`GET /`), so Foundation is source-true.

Contrast figures are computed, not asserted — see `scripts`/the contrast helper used
during build; reproduce with the standard WCAG relative-luminance formula.

### High Contrast mode

Toggle in the header (`aria-pressed`), persisted to `localStorage["waf-theme"]`.
Overrides push every text pair to ≥ 17:1 and borders to `#000`. Because state is
carried by token swaps only, no component markup changes between modes.

### Type & metrics

| Token | Value | Use |
|-------|-------|-----|
| `--fs-h1` | 20px/600 | header title |
| `--fs-h2` | 15px/600 | card title |
| `--fs-body` | 14px | body |
| `--fs-cap` | 12px | labels, table headers, help text |
| `--fs-metric` | 28px/700 | KPI tile value |
| `--radius` | 8px | cards, inputs (6px), badges (pill) |

Controls (`button`, `input`, `select`) are `min-height: 44px` (WCAG 2.5.5 target size).

## Components

Each entry: **anatomy · states · usage · a11y · data**.

### KPI tile (`.tile`)
- **Anatomy** uppercase label (`--sub`) + large metric (`--fs-metric`).
- **States** value / `…` while loading.
- **Usage** the top strip; one tile per headline count. Never put a table in a tile.
- **a11y** strip is `aria-live="polite"` so refreshes are announced.
- **Data** `GET /api/kpis` → `route_count · threat_indicator_count · dnsbl_entry_count · blocked_event_count · monitor_event_count · gateway_mode`.

### Card / section (`section.card`)
- **Anatomy** `<h2>` + body slot. One domain concern per card.
- **Usage** cards flow in a `repeat(auto-fit, minmax(340px,1fr))` grid; order by operator priority (config → threat data → commercial → logs → raw exports).

### Table
- **Anatomy** visually-hidden `<caption>`, `<th scope="col">` headers, `<td>` cells.
- **States** populated / `No entries.` empty state (`.empty`) / `Error: …` (`.err`).
- **Usage** any list of records (routes, threats, dnsbl, feeds, events, audit). Cap long lists (events/audit slice to 25) and say so if truncated.
- **a11y** real `<table>` semantics; headers associate via scope; never a `<div>` grid.

### Badge (`.badge` + variant)
- **Variants** `b-brand` (mode Monitor, edition), `b-pass` (Enabled, Pass, Active, Fresh), `b-fail` (High/Critical severity, Block, Fail, Stale, Expired), `b-warn` (Medium, Evaluation, Not-ready), `b-neutral` (Low, Unlicensed, empty), `mono` (code/values).
- **Rule (critical)** a badge always carries **text + colour**, never colour alone. Severity, route mode, enabled state, license status, feed freshness, and readiness checks all follow this.
- **Usage** helpers: `sevBadge`, `modeBadge`, `stateBadge`, `statusBadge`. Add a new status by extending the helper's map, not by inlining a colour.

### Definition list (`dl.def`)
- **Anatomy** two-column `dt`/`dd`; keys `--sub`, values bold, right-aligned, `word-break`.
- **Usage** single-record detail (License). Missing optional values render `—`, never blank.

### Button
- **Variants** `btn-primary` (brand fill — one primary action per form), `btn-secondary` (bordered, on surface), `btn-ghost` (in the brand header).
- **States** default / `:focus-visible` ring / `aria-pressed` (toggle). 44px min.

### Form field
- **Anatomy** `label.field` wrapping caption + control + optional `.field-help`.
- **Controls** single-line `<input>` (text/password), `<select>`, checkbox (`.check`).
- **Usage** one concern per field. Show validation constraints as help text up front
  (e.g. Path prefix “must start with /”, Upstream “mock:// | http:// | https://”),
  matching server validators so the client never promises what the API rejects.
- **a11y** label wraps control (implicit association); help text visible, not title-only.

### Toast (`.toast`)
- **Variants** `ok` (pass left-border), `bad` (fail left-border). `#toast` is `aria-live="assertive"`.
- **Usage** transient result of a write (route saved / save failed: <server message>). Auto-dismiss ~4.5s. Not for persistent errors — those render inline in the card.

### Empty / error / raw
- **Empty** `.empty` “No entries.” for genuinely empty collections.
- **Error** `.err` inline per card; one failing card never blanks the page (`Promise.allSettled` + per-card `guard`).
- **Raw** `pre.raw` monospace block for exports that *are* code — evidence manifest (JSON), SOC event export (ndjson), DNSBL zone file. Do not “design” a raw export; present it faithfully, scrollable.

### Skip link (`a.skip`)
First tab stop, off-screen until focused, jumps to `#main`.

## Patterns

- **Resource list + create** — Routes: table of records + a `<details>`-collapsed
  create form posting to the resource endpoint, then re-fetch. Reused shape for any
  writable collection (threats, dnsbl share the same POST contract).
- **Detail** — License: definition list of one record.
- **Checklist** — Commercial readiness: a ready/not-ready headline badge + one
  pass/fail row per check with its evidence string.
- **Import** — Threat feed: `POST /api/threat-feeds/import` returns upsert counts;
  surface as a toast + refreshed feeds.
- **Export** — raw blocks for machine-facing artifacts.

## Accessibility checklist (per screen)

- [ ] All text pairs ≥ 4.5:1 (see table); non-text state has a text label too.
- [ ] Every control ≥ 44×44 and reachable by keyboard with a visible focus ring.
- [ ] Tables use `<table>/<th scope>`; forms use wrapping `<label>`.
- [ ] Live regions announce KPI refresh and write results.
- [ ] High Contrast mode usable (borders `#000`, text ≥ 17:1).
- [ ] One card failing to load does not break the page.

## Extending

Add a section: append a `section.card` with an id'd body, write a `loadX()` that
fetches and renders with the helpers above, and register it in `refresh()` via
`guard('bodyId', loadX)`. Add a status colour by extending the relevant badge map —
never inline hex on an element; put it in a token first.

## Known scope / not done

- Client covers all read surfaces plus create/update forms for routes, threat
  indicators, DNSBL entries, and license — every write endpoint the API exposes.
  A single admin-token field in the header authorizes writes (`X-Admin-Token`);
  server validation is surfaced verbatim via toast.
- Single brand; only Default + High Contrast themes (no dark, no density).
- No automated a11y/visual regression test yet; contrast is verified manually.
