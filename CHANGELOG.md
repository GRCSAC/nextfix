# Changelog

All notable changes to NextFix are recorded here. Version numbers come from the root
`package.json` (single source of truth) and are stamped into every report and VEX document.

## [Unreleased]

## [0.5.0] — 2026-10-09

### Added
- **Cross-file symbol resolution.** Derived symbols are now carried from the file the fix
  touched up through the package's import graph to its entry file: `package.json` is located
  from the touched file upward, the entry is chosen source-first (`source`, `src/index`,
  `src/<name>`, `module`, `exports`, `main`, …), the import graph is walked breadth-first from
  the entry, and tainted names flow through named and namespace imports, `export … from`
  barrels, `module.exports = require()`, class methods to their class, and module-level
  variables to whatever references them. The result is the package's public names: moment's
  locale path-traversal fix in an internal file now derives to `locale`, `defineLocale`,
  `updateLocale` and the parsers that read locale config; marked's module-level regex fixes
  derive to `marked`, `parse`, `lexer`, …; qs's internal `parseObject` derives to `parse`.
- A call to the package itself (`marked(src)`) matches an export named after the package.
- Evidence records the entry file the symbols were resolved through.

### Fixed
- `var parseKeys = function parseQueryStringKeys()` is known by the variable name callers use.
- Import resolution probes `.js` first and no longer spends the file budget depth-first.

## [0.4.1] — 2026-10-09

First validation against real applications (OWASP Juice Shop, OWASP NodeGoat, Hackathon
Starter; see README "Validation on real applications"). Everything below came out of it.

### Fixed
- Routes whose handlers are `controller.method`, `instance.method`, a factory call such as
  `login()`, or a wrapped factory such as `asyncHandler(handler())` were dropped. They now
  resolve into the controller module, the class, or the factory; handlers NextFix still cannot
  follow are kept as entry points and listed as `unresolvedHandlers`.
- Setup middleware (`session()`, `passport.initialize()`, `passport.session()`, `flash`,
  rate limiters, `lusca`, `helmet`, …) matched the auth-guard pattern and marked every later
  route as authenticated. A non-guard list is checked first, and the guard pattern now looks
  for guard-shaped names (`isLoggedIn`, `requireLogin`, `passport.authenticate`,
  `isAuthorized`, `verifyToken`, …) rather than bare words like `login` or `session`.
- Handlers that do their work inside nested callbacks or returned closures were not followed:
  a function now reaches every function defined inside it.
- `this.method = (req, res) => …` assignments inside constructors are named after the property.
- Module-level fix changes (regex tables, constants) in a single-callable package derive to
  `default`; in multi-export files the failure reason says so.
- Array route paths print as `a | b`; the CLI table shows the unauthenticated path first and
  how many other entry points reach the call.

### Changed
- Entry-point coverage on the three applications went from 23 / 4 / 12 routes to 91 / 21 / 107
  (grep finds 102 / 20 / 109 registrations in the same files).

## [0.4.0] — 2026-10-09

### Added
- **Derived vulnerable symbols.** For every advisory without function-level data, the scan
  follows the advisory's GitHub fix commit, pull request or compare link, diffs it, maps the
  touched lines to the functions that contain them, and resolves those to the file's public
  surface (exports, `module.exports`, `lodash.x = x` and `res.x = function` assignments,
  public callers up to three hops, callbacks passed as arguments, changes inside nested
  callbacks). Results are stored on the machine with the commit as evidence and shown as
  confidence `derived`. On the demo app this reproduces the hand-curated data for five of
  six advisories and adds function data for 12 of the 14 that had none.
- `nextfix symbols derive|list|confirm|forget|export`: inspect derived entries, promote one
  to `confirmed` after review, and export confirmed entries as curated JSON for the repo.
- `GITHUB_TOKEN` is honoured for fix-commit fetches; `--no-derive` turns derivation off.
- `nextfix.config.json`: extra auth-guard patterns, ignored directories, and routes to
  treat as internal.
- Chained Express routes: `app.route('/x').get(h).post(h)`.
- Findings detail shows the function data behind each advisory: the symbols, the fix
  commit it was derived from, and the functions that commit changed.

### Changed
- `derived` entries outrank nothing: curated data wins when both exist for an advisory.

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
