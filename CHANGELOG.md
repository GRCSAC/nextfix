# Changelog

All notable changes to NextFix are recorded here. Version numbers come from the root
`package.json` (single source of truth) and are stamped into every report and VEX document.

## [Unreleased]

## [0.8.2] — 2026-10-10

The experience release: the Overview answers an executive's questions instead of counting
the same findings five ways, the dashboard works on a phone, and reachability is fast
enough for monorepos.

### Added
- **Overview rebuilt, one question per panel.** A posture verdict (Exposed, Attention,
  Contained, Clean) with its sentence and the rule behind it; the evidence funnel from every
  advisory found to the ones reachable without a login with request data and exploitation
  evidence, each step saying what it removed and why, with three ratios (need no action,
  exposed surface, from the image); what changed since the previous scan as a bridge with
  new, resolved and re-decided items named; the work queue (the four decisions, once);
  ageing of open actionable findings against the SLA with median time to resolve; the
  shortest path to green (upgrades ranked by findings closed, with the sentence "N upgrades
  clear everything that needs action"); where an attacker gets in (entry points as tiles
  sized by what they reach); why each decision (reachability × exploitation matrix); the
  trend and the evidence list. "Print summary" produces a one-sheet report.
- **Re-check exploit data.** Re-runs only the decision step with today's EPSS and KEV data,
  without re-scanning, and lists findings that would change; nothing is stored until the
  next scan. The same logic is at `POST /api/targets/:id/redecide`.
- **Finding history.** First seen, last seen and resolved dates per finding across scans,
  with age buckets, SLA breaches, median days to resolve and the last 30 days' flow at
  `GET /api/targets/:id/history`. SLA days (Fix now 7, Fix next cycle 30) and scan retention
  (50 per application) are editable in Settings and at `GET/PUT /api/settings`.
- **Scan progress and cancel.** The banner shows the stage and elapsed time with a Cancel
  button; `GET /api/scan/progress`, `DELETE /api/scan`, and `scanning` in the health
  endpoint. A scan started elsewhere is picked up when the tab regains focus.
- **Phone layout.** Below 760 px the findings queue is a card per finding; below 1100 px the
  detail is a full-height scrollable sheet with focus management; the tab strip shows an
  overflow fade; a skip link.
- Filters live in the URL (`#/findings?decision=Act&tier=reachable&q=lodash`), so reload,
  share and Back keep them. The full finding (advisory text, every reference) is fetched
  when opened; the list payload is lighter and gzip-compressed.
- Export filenames carry the local date and time.

### Changed
- **Reachability is up to 170× faster.** One backwards pass from the vulnerable calls to the
  handlers that can reach them, then a single shared request-data search with parent
  pointers; 3.5 s per advisory became under 30 ms on a 1,500-file project, with identical
  results and shortest paths shown.
- The diff compares tier, decision, fix, request data, KEV, EPSS and entry points, and
  explains each change ("entered KEV", "fix published 4.18.0").
- "Match OS" follows the operating system's theme. Text colours in both themes meet WCAG AA
  (amber, green and cyan darkened for light; button and small red text adjusted for dark).
- Reports written before 0.8 show zeros for tiers they predate. Old-scan rows no longer break
  the reachability filter.
- `summary.advisories` counts distinct advisories.
- Trend axis shows the time of day when several scans share a day; "seven tiers" in How it
  works; the Reports column is "No action needed"; Evidence's first chip is "All evidence".

### Fixed
- Switching applications quickly can no longer show one application's report under another's
  name; a diff failure no longer hides a loaded report; a malformed URL no longer blanks the
  page (an error boundary offers Reload).
- Modal dialogs move focus in, trap Tab, restore focus and close on Escape.
- Settings no longer discards typed integration values on refetch.

## [0.8.1] — 2026-10-10

A hardening release: the local server no longer trusts the network it sits on, the analyzer
no longer reports code as safe for reasons that were wrong, and the command line can gate a
build. Nothing in the report shape changed except new optional fields.

### Security
- **The server refuses requests it did not expect.** State-changing API calls must be
  `application/json` (415 otherwise), must carry no `Origin` other than the server's own
  (403), and must be addressed to a host the server was started for: `localhost`,
  `127.0.0.1`, `[::1]`, the `--host` value, or names given with the new `--allow-host`
  option (421 otherwise). Bodies over 1 MB are refused (413). A web page the user visits can
  no longer scan folders, create tickets or change settings through the dashboard's port.
- **Tracker tokens stay with the host they were entered for.** Integration settings accept
  only their known keys; the GitHub `apiBase` and Jira `baseUrl` must be https (http only
  for loopback) with no credentials, query or fragment; changing the host without re-entering
  the token is refused. Secrets are never returned by any endpoint (now tested).
- **A project's own `nextfix.config.json` is untrusted input.** `image` values that point
  syft at the host (`dir:`, `file:`, archive sources, option-like strings) and `sbom` paths
  outside the project are ignored with a log line; the same values on the command line are
  honoured. Guard patterns are checked for length and nested quantifiers before they are
  compiled, and matched against bounded text. The config's shape is validated with a plain
  error naming the first wrong setting.
- Advisory reference URLs are rendered as links only when they are http or https.

### Fixed (analysis)
- A route whose handler is named like `authController.login` or `auth.register` was taken
  for an auth guard and the route dropped, so vulnerable code behind login and registration
  endpoints was reported unreachable. The last argument of a registration is now always the
  handler, and guard names are tested against the member name, not the receiver.
- `require()` and `import()` inside a function count as imports, so lazily loaded packages
  are no longer reported "installed but never imported".
- `import x from 'pkg/sub'` records the sub-path as the symbol, so sub-path imports match
  function-level data.
- Request data is kept when a parameter is reassigned to itself (`src = src.trim()`) and
  when a callback or closure captures a tainted local.
- Inline middleware that rejects with 401/403 is recognised as a guard for Express and Koa,
  as the decision model already said; a bare `throw` no longer counts as a rejection.
- `./x.js` specifiers resolve to `x.ts` (NodeNext projects); `.jsx`, `.tsx`, `.mts`, `.cts`
  and more index files are tried.
- `this.method()` receivers and `new Pkg()` constructor calls are visible to symbol matching.
- Exploitation evidence is taken across every CVE an advisory covers (KEV on any, highest
  EPSS); the why line names the CVE when it is not the headline one.
- A package found in the image at another version than the lockfile's is no longer analysed
  as if the application ran it.
- Version ordering for Maven, RubyGems, NuGet, Packagist and unknown schemes compares digit
  runs numerically, so `1.10.0` is newer than `1.9.0` and real fixes are no longer rejected.
- npm aliases (`"string-width-cjs": "npm:string-width@4"`) are inventoried under the real
  package name and queried correctly.

### Fixed (robustness)
- A GitHub or network error during symbol derivation skips that advisory instead of aborting
  the scan; an offline scan no longer records "no fix data" failures for seven days.
- Two servers on one database: a `locks` table (schema `user_version` 1) makes scanning
  exclusive across processes (409 while any scan runs), `/api/health` reports the other
  server, and the second one logs a warning at start. Scans time out after `--scan-timeout`
  minutes (default 20) and free the slot.
- Reports written before 0.8 are shown with zeros for the tiers they predate.
- Adding an application no longer inserts it when its first scan cannot start.
- Tracker calls time out after 20 s, retry once on 403/429 honouring `Retry-After`, are
  spaced one second apart in bulk, and record each created issue before continuing so a
  retry never creates a duplicate. Jira issues get clickable links.
- The server logs one sentence and exits 1 on a crash or a busy port instead of dying
  silently; `--port` is validated.
- `nextfix scan` without a folder exits 2; `--why` with a non-number falls back to 3.

### Added
- `nextfix scan … --fail-on Act|Attend|Track*|Track` exits 3 when any finding is decided
  that or worse, for pipeline gates. Exit codes are documented in `--help`.
- A GitHub Actions workflow runs typecheck, tests and the build on Ubuntu and Windows.
- `scripts/set-version.mjs` keeps the README's version line in step.
- Regression fixtures for every analyzer case above.

## [0.8.0] — 2026-10-09

### Added
- **Container image inventory.** `image` in `nextfix.config.json` or `--image <ref>` runs
  syft over the built image and merges its packages with the lockfile: the local `syft`
  binary (or `NEXTFIX_SYFT`) when present, otherwise the pinned `anchore/syft` container
  through Docker, which also covers a local syft that cannot read images (syft on Windows
  currently fails on its own layer-cache paths). A missing or failing image is reported per
  image; the scan continues.
- **SBOM input.** CycloneDX JSON, SPDX JSON and Grype JSON are read with `--sbom <file>` or
  `sbom` in the config; `*.cdx.json`, `*.spdx.json`, `sbom.json` and `bom.json` at the
  project root are picked up without being asked.
- **Distribution ecosystems.** OS packages are queried in OSV as `Debian:<release>`,
  `Ubuntu:<release>[:LTS]`, `Alpine:v<major.minor>`, Wolfi, Chainguard, Red Hat,
  `AlmaLinux:<n>`, `Rocky Linux:<n>`, by source package (binary packages of one source merge
  into one component, listed in the Components page), with dpkg-style version ordering for
  fixed versions. Go modules in binaries go to the Go ecosystem; Maven, RubyGems, crates.io,
  NuGet, Packagist, Hex and Pub are mapped for SBOMs that carry them. Binaries and unknown
  types are listed as `generic` and not queried.
- **`image-only` tier.** A package present only in the image gets no call-path claim; it is
  Attend when in KEV, or when a fix exists and EPSS ≥ 10% or CVSS ≥ 7, otherwise Track\*. Fix
  text and ticket command point at the image (`apt-get` / `apk` / `dnf`, rebuild the base).
  OpenVEX marks it `affected` with the reason.
- Distribution advisories without severity or summary of their own take both from the CVE
  record in OSV; `DEBIAN-CVE-…`-style ids resolve to their CVE for EPSS and KEV.
- Components page: image header (OS, component count, how many are unqueried, which route
  read it), a "Where" column, and "Project lockfiles only" / "In the image" scopes. The
  terminal summary lists each image.

### Changed
- `Ecosystem` is the OSV ecosystem string, no longer limited to `npm` and `PyPI`; reports and
  the Components page show it as is (`Alpine:v3.24`).
- `fixCommand` lives in the engine (`report/ticket.ts`) and the dashboard reuses it.

## [0.7.0] — 2026-10-09

### Added
- **GitHub Issues and Jira Cloud export.** Settings → Integrations takes a repository and
  token (GitHub) or site, email, API token and project key (Jira), with Save-and-test.
  Credentials live only in the local NextFix database and are never returned by the API.
  A finding's detail gains "Create GitHub issue" / "Create Jira issue"; the queue gains
  "… issues for actionable" to create one for every Fix now and Fix next cycle finding that
  has none. Created issues are remembered per finding (no duplicates on retry) and linked
  from the queue and the detail. The issue body is the same Markdown as "Copy as ticket",
  converted to Atlassian Document Format for Jira.
- GitHub Enterprise: an optional API base for the GitHub integration.

### Changed
- The ticket text lives in the engine (`report/ticket.ts`) so the CLI, server and dashboard
  share one format.

## [0.6.0] — 2026-10-09

### Added
- **Python.** Inventory from pinned `requirements*.txt`, `Pipfile.lock`, `poetry.lock` and
  `uv.lock` (PEP 503 names, PEP 440 version ordering for fixes); OSV lookups in the PyPI
  ecosystem; a tree-sitter based module analyzer (WebAssembly grammar, no native build);
  and entry points for **Flask** (`@app.route` / `@bp.get`, blueprints with `url_prefix`,
  `register_blueprint` from `create_app()` factories, `@login_required`-style decorators,
  rejecting `before_request` hooks), **FastAPI** (`APIRouter(prefix, dependencies)`, nested
  `include_router`, `Depends(...)` and `CurrentUser`-style annotated parameters as guards,
  handler parameters as request data) and **Django** (`urlpatterns` with `path`/`re_path`/
  `include`, function views, class-based views per HTTP verb, `LoginRequiredMixin`,
  `@login_required`, `permission_classes`). `request`, `ctx` and every handler parameter are
  request-data roots; the call graph resolves `from pkg import x`, relative imports, barrel
  `__init__` re-exports and `self.method()`.
- **Python symbol derivation.** Fix commits touching `.py` files are analysed with the same
  pipeline: changed functions and methods, the class they belong to, module-level variables,
  and cross-file resolution through the package's `__init__.py` (star imports, `__all__`,
  Python 2 implicit relative imports). PyYAML's constructor fix derives to `load`,
  `full_load`, `FullLoader`, …; requests' proxy fix to `Session`; PyJWT's to `PyJWS` and its
  helpers.
- Curated PyPI seed for PyYAML (CVE-2017-18342, CVE-2020-1747, CVE-2020-14343) and requests
  (CVE-2023-32681).
- Mixed projects (a `package-lock.json` and Python requirements in one folder) are scanned
  as one graph; findings carry their ecosystem and `pip install` fix commands.
- Derivation failures are keyed by a pipeline version, so they are retried after upgrades.

### Fixed
- Broken symlinks and dot-directories no longer abort file discovery.
- Request-data sources name the request expression behind a local variable
  (`request.POST['body']`, not `body`), and a handler's own request-carrying parameter counts
  as a direct source.
- Django class-based views pair each HTTP verb with its own method.

Validated on Flask microblog (35 routes, 25 behind `login_required`; the Act findings are
PyJWT decoding the password-reset token from the URL), OWASP PyGoat (Django,
137 routes, 141 advisories of which 94 got derived function data; the four Act findings are
the insecure-deserialisation lab calling `yaml.load` on an uploaded file and the
misconfiguration lab decoding an attacker-controlled cookie with PyJWT) and the FastAPI
full-stack template (23 routes, 17 behind dependencies).

## [0.5.2] — 2026-10-09

### Added
- **Fastify** entry points: `fastify.get(path, handler)`, route options objects
  (`{ preHandler, onRequest, … , handler }`), `fastify.route({ method, url, handler })`,
  `fastify.register(plugin, { prefix })` for plugin modules, in-file plugin functions, and
  scoped `addHook('onRequest', guard)`. `@fastify/autoload`: every route module under the
  autoload directory is mounted at its folder path (`routes/api/tasks/index.ts` →
  `/api/tasks`) and `autohooks` files guard their folder; a module that registers autoload
  is the root when nothing mounts it (fastify-cli apps).
- **Koa** entry points with `@koa/router`, `koa-router` or any package class named `…Router`:
  `new Router({ prefix })`, `router.prefix()`, named routes, `router.use(guard)`,
  `app.use(router.routes())` and `router.use('/p', sub.routes())` mounts, routers exported by
  name. `ctx` is a request-data root, so `ctx.request.body.x` is traced like `req.body.x`.
- Inline hooks and middleware whose body rejects requests (401/403, `unauthorized`,
  `ctx.throw`) count as guards and are named by file and line.
- Handlers reached through barrel files (`export { default as user } from './user'`) resolve
  to the controller that defines them.
- `export { router }` named exports are recognised; "unprotected"/"public" names never
  count as guards.
- Derivation has a time budget per scan (90 s by default); what is left is picked up next scan.

Validated on the official Fastify demo (15 routes, 13 behind the folder autohook) and a Koa
REST template (7 routes, 6 behind `koa-jwt`), both now in the README table.

## [0.5.1] — 2026-10-09

### Changed
- **Argument-level request-data tracing.** "Request data reaches it" used to mean that `req`
  appeared somewhere in the call chain. Each call site now records which parameters, `req`
  accesses or captured names every argument derives from (through local variables,
  destructuring and call results), the path search carries the set of tainted names from the
  handler's `req` parameter by parameter through every call and into callbacks, and a
  vulnerable call counts as reached by request data only when one of its arguments traces
  back to it. Findings name the source expression (`req.body.template`) and the argument it
  arrives in. A path that carries request data is preferred over one that does not, both for
  the decision and in the dashboard.
- The same package at several lockfile paths is one component (dev only if every copy is dev,
  direct if any copy is), so it is one finding to fix rather than several.

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
