# NextFix roadmap

Sequenced so that every step is demoable on its own and the hard, defensible part
(function-level reachability) keeps getting better underneath a stable UI.

## 0.1 — Spike (done 2026-10-09)

Lockfile → OSV/EPSS/KEV → JS call graph → Express entry points → tiers → SSVC decision →
table / JSON / OpenVEX. Demo target exercises every tier. Tests cover tiers and entry points.

## 0.2 — Two dashboards (done 2026-10-09)

`nextfix-server serve` opens a local browser dashboard (same pattern as NetVane), SQLite
history per target, scan-over-scan diff.

- **Executive view:** fix-now / fix-next-cycle with deltas, set-aside rate, unauthenticated
  entry points, trend across scans, decision and reachability breakdowns, what to fix first,
  since-last-scan diff, exposure.
- **Remediation view:** queue by decision, reachability and search; per-finding why, call-path
  diagram, fix command, copy-as-ticket, VEX download.
- Light/dark, phone width, GRCSAC house fonts.

Still open from this phase: one-page PDF export, remediation velocity (needs resolved-date
tracking), KEV/EPSS hot list as its own card.

## 0.3 — Brand, redesign, open-core (done 2026-10-09)

Dashboard rebuilt to the approved prototype (rail, tabs, command center ring, entry points,
component states, evidence & exceptions), brand palette and mark applied, Components /
Evidence / Reports / Apps / Settings pages, Apache-2.0 license with the open-core split.

## 0.4 — Make the evidence wider (done 2026-10-09)

Derived symbols from fix commits with evidence, review (`symbols confirm`) and export;
`nextfix.config.json`; chained Express routes. Validation on the demo: five of six curated
advisories reproduced, 12 of 14 uncurated advisories gained function data.

Still open from this phase:
- Resolve a package's public API across files (entry `main`/`exports` → re-exports), so ESM
  libraries like moment yield `moment.locale` rather than the internal `getLocale`.
- Fastify and Koa entry points; `express.static` and regex paths.
- Container image inventory through a Syft/Grype adapter (external binary, optional).
- A review page in the dashboard for derived entries (today it is the CLI).

## 0.5 — Team edition (separate commercial repo)

- OIDC single sign-on, local accounts fallback.
- Roles: admin, analyst, viewer (executives are viewers).
- Audit log, REST API with tokens, Jira and GitHub Issues export.
- Offline advisory bundles for air-gapped installs.
- The open repo keeps WCAG AA on every page and a stable API the team edition builds on.

## 0.6 — Python and Go

- Python: tree-sitter (wasm) parser, Flask / FastAPI / Django entry points, same tiers.
- Go: wrap `govulncheck` (symbol-level, from the Go vuln DB) and map into tiers.

## 1.0 — Ship

- Single executable per platform (Node SEA or Bun compile) and a Docker image.
- Installer for Windows like NetVane; `winget` + Chocolatey.
- Website `nextfix.grcsac.com` (brand kit in `docs/BRAND.md`); open edition free, team
  edition priced per application count.
- Trademark filing for NEXTFIX in classes 9 and 42 (see `docs/NAME-CHECK.md`), then flip
  the repo public.
