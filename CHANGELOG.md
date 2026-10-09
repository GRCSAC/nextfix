# Changelog

All notable changes to NextFix are recorded here. Version numbers come from the root
`package.json` (single source of truth) and are stamped into every report and VEX document.

## [Unreleased]

## [0.2.0] — 2026-10-09

### Added
- `nextfix-server serve`: local web dashboards on http://127.0.0.1:8790 with scan history in
  SQLite (`~/.nextfix/nextfix.sqlite`), JSON API, and OpenVEX download.
- **Executive view:** fix-now / fix-next-cycle tiles with deltas, "set aside with evidence"
  rate, unauthenticated entry points, actionable-findings trend across scans, decision and
  reachability breakdowns, what-to-fix-first list, since-last-scan diff, exposure card.
- **Remediation view:** queue filtered by decision, reachability and search; per-finding
  detail with the plain-English why, call-path diagram (entry → hops → vulnerable call,
  marking where request data enters), fix command, copy-as-ticket (Markdown), VEX download.
- Light and dark themes from the OS setting; phone-width layout; keyboard-operable queue.
- `scripts/set-version.mjs` keeps every workspace package on the root version.

## [0.1.0] — 2026-10-09

### Added
- End-to-end spike: npm lockfile inventory → OSV advisories → EPSS/KEV enrichment →
  JavaScript call-graph and Express entry-point analysis → four-tier reachability →
  Docker exposure → SSVC-style decision → terminal table, JSON report, OpenVEX export.
- Curated vulnerable-symbol seed for lodash, express, minimist.
- Demo target `samples/express-shop` that exercises every reachability tier.
