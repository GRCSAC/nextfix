# Changelog

All notable changes to NextFix are recorded here. Version numbers come from the root
`package.json` (single source of truth) and are stamped into every report and VEX document.

## [Unreleased]

## [0.3.0] — 2026-10-09

### Added
- Brand: Midnight/Navy surfaces, Electric Blue actions, the gradient N mark and two-tone
  wordmark, tagline "Find › Prioritize › Fix › Prove". Brand kit in `docs/BRAND.md` and
  `docs/brand/` for the website team.
- Dashboard redesign to the approved prototype: left rail (Apps, Settings, Help), top tabs
  (Overview, Findings, Components, Evidence, Reports), application header with status and
  summary; Overview with scan-overview dot matrix, the remediation command center ring,
  entry points without authentication, trend with range picker, where-the-findings-landed
  bar with percentages, component-states ring, what-to-fix-first table, evidence &
  exceptions card, and a "How it works" explainer.
- New pages: Components (every installed package with its state), Evidence (all
  set-asides grouped by reason with the VEX justification), Reports (exports and scan
  history), Apps (add, switch, remove applications), Settings (theme, data locations).
- Reports now include the full component list.
- Apache 2.0 `LICENSE` and `NOTICE`; open-core split documented in the README.

### Changed
- Decision colours: Fix now red, Fix next cycle amber, Set aside blue, Watch cyan, drawn in
  an order validated for colour-vision deficiency.
- Dark theme is the default; Light and Match OS are in Settings.

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
