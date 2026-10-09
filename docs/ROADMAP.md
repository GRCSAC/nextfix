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

## 0.3 — Make the evidence wider

- **Derived symbols:** given an advisory with a fix commit, diff the commit, list the changed
  exported functions, store as `derived` entries, with a human review queue before they
  count as `confirmed`. This is what turns `imported-unknown-symbol` into real answers at scale.
- More Express patterns: `router.route('/x').get()`, `app.all`, regex paths, `express.static`.
- Fastify and Koa entry points (same shape, different method names).
- Config file `nextfix.config.json`: auth-guard names, ignored paths, entry-point overrides.
- Container image inventory through a Syft/Grype adapter (external binary, optional).

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
