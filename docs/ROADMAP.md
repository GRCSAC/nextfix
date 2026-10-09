# NextFix roadmap

Sequenced so that every step is demoable on its own and the hard, defensible part
(function-level reachability) keeps getting better underneath a stable UI.

## 0.1 — Spike (done 2026-10-09)

Lockfile → OSV/EPSS/KEV → JS call graph → Express entry points → tiers → SSVC decision →
table / JSON / OpenVEX. Demo target exercises every tier. Tests cover tiers and entry points.

## 0.2 — Make the evidence wider

- **Derived symbols:** given an advisory with a fix commit, diff the commit, list the changed
  exported functions, store as `derived` entries. automated, with a human review
  queue. This is what turns `imported-unknown-symbol` into real answers at scale.
- More Express patterns: `router.route('/x').get()`, `app.all`, regex paths, `express.static`.
- Fastify and Koa entry points (same shape, different method names).
- Config file `nextfix.config.json`: auth-guard names, ignored paths, entry-point overrides.
- Container image inventory through a Syft/Grype adapter (external binary, optional).

## 0.3 — Two dashboards (web UI)

Server mode: `nextfix serve` opens a local browser dashboard (same pattern as NetVane),
SQLite history per target, scan-over-scan diff.

- **Executive view:** exposure trend, Act/Attend counts, remediation velocity, the headline
  "scanners found N, M matter", KEV/EPSS hot list, exportable one-page PDF.
- **Remediation view:** queue by decision and score, per-finding path graph, the why, fix
  with major-bump warning, one-click VEX export, copy-as-ticket.
- GRCSAC house fonts and the simple/clean/professional UX bar; mobile-symmetric.

## 0.4 — Enterprise accessibility

- OIDC single sign-on, local accounts fallback.
- Roles: admin, analyst, viewer (executives are viewers).
- Audit log, REST API with tokens, Jira and GitHub Issues export.
- Offline advisory bundles for air-gapped installs.
- WCAG AA on both dashboards.

## 0.5 — Python and Go

- Python: tree-sitter (wasm) parser, Flask / FastAPI / Django entry points, same tiers.
- Go: wrap `govulncheck` (symbol-level, from the Go vuln DB) and map into tiers.

## 1.0 — Ship

- Single executable per platform (Node SEA or Bun compile) and a Docker image.
- Installer for Windows like NetVane; `winget` + Chocolatey.
- Website `nextfix.grcsac.com`, pricing for SMB: free for one app, paid tiers per app count.
- Trademark filing for NEXTFIX in classes 9 and 42 (see `docs/NAME-CHECK.md`).
