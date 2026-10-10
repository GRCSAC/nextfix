# NextFix decision model

This is the contract between the engine and the person reading the result. Every rule here
is quoted back in a finding's "why" lines; if a rule is not explainable in one sentence it
does not belong in this file.

## 1. Inputs per finding

| Input | Source | Used for |
|---|---|---|
| Component (name, version, dev, direct) | lockfile | tiers `dev-only`, fix text |
| Image components (ecosystem incl. distribution release, source package, binary packages) | syft over the image, or an SBOM file | tier `image-only`, OS-package fix text |
| Advisory (CVSS v3 vector → score, fixed version) | OSV | severity, fix |
| Vulnerable symbols for (advisory, package) | `data/vulnerable-symbols.json` | tiers 2–4 |
| Imports, functions, calls | TypeScript parser over the project | call graph |
| Entry points (method, path, guards) | Express route registrations, mounts, `app.use(guard)` | reachability, authentication |
| Request data | each argument's roots (parameters, `req.*`, captured names, through locals and destructuring); tainted names carried parameter-by-parameter along the path | "user input" |
| Network exposure | Dockerfile `EXPOSE`, compose `ports:`, `app.listen` host | exposure |
| EPSS score, KEV membership | FIRST, CISA | exploitation |

## 2. Reachability tiers (evaluated in order)

1. `dev-only` — component is a devDependency.
2. `unused` — no source file imports the package.
3. `imported-unknown-symbol` — imported, but there is no function-level data for this advisory.
   NextFix refuses to guess; it says so.
4. `imported-not-called` — imported, and none of the advisory's symbols are called anywhere.
5. `called-unreached` — a symbol is called, but no entry-point handler reaches that function
   through the local call graph.
6. `reachable` — at least one entry point reaches a call. The first path found per entry point
   is recorded; an unauthenticated path is preferred for the decision.

Before tier 1: a component found **only in the container image** (not in a lockfile, and for
npm / PyPI not imported by any source file) is `image-only`. NextFix traces no code paths
inside an image, so no claim of "unused" or "not called" is made; the package is simply
present. An image package that the application does import is analysed like any other.

**Confidence** travels with the tier: `confirmed` (curated symbols), `derived` (from the fix
commit, automated), `package-level` (tiers 1–3 and `image-only`).

### How derived symbols are built

1. Candidate fix links from the advisory references: GitHub commit, pull request or compare
   URLs, ranked `FIX`-typed first, then those whose repository name matches the package,
   then commits before PRs. At most three are tried; the first that yields symbols wins.
2. The unified diff is fetched; tests, docs, fixtures, build output and non-source files are
   dropped; at most 12 files are considered.
3. Each touched file is fetched at the post-fix ref and parsed. For every added or deleted
   line, the chain of enclosing functions (innermost first) is walked until one resolves to
   the file's public surface.
4. Public surface of a file: `module.exports = …`, `exports.x = …`, `export …`, and any
   `obj.name = fn` assignment (which is how lodash and Express expose their APIs). A changed
   function that is public contributes itself and its immediate public callers; a changed
   internal function contributes public callers up to three hops away, where passing a
   function as an argument counts as a call.
5. **Across files.** The package's `package.json` is found from the touched file upward and
   an entry file chosen source-first. The import graph is walked breadth-first from the entry
   (at most 200 files for npm, 60 for PyPI). The changed names are then carried toward the entry: a file's
   functions that call or reference them (and the classes those methods belong to), the
   file's public names for those, then each importer's local bindings for those names, with
   `export … from` barrels and `module.exports = require()` passing names through unchanged.
   The entry file's public names that are reached are the package's symbols.
6. If nothing resolves but the file's default export is itself a function, the symbol is
   `default` (the package is one callable).
7. Failures are remembered for seven days so scans do not retry every time; `nextfix symbols
   forget` clears one.

Curated entries always outrank derived ones for the same advisory. `nextfix symbols confirm`
promotes a derived entry after a human looks at the commit; `export` turns confirmed entries
into curated JSON for the repository.

### Go: the call graph and govulncheck together

Go modules get two sources of evidence. The project call graph (tree-sitter) finds entry
points, guards and request data for net/http, Gin, Echo, Chi, Fiber, gorilla/mux and
httprouter, and resolves calls into dependencies by module and exported name. `govulncheck`
supplies the vulnerable symbols per advisory from the Go vulnerability database and its own
verdict, which follows calls *inside* dependencies that the project graph does not see.

| Situation | Tier | Confidence |
|---|---|---|
| graph has entry points and OSV lists symbols | `assessReach` as for any ecosystem | confirmed |
| graph says less than govulncheck (govulncheck `called` but no graph path; `imported` but the graph saw no import) | govulncheck's verdict wins, below | confirmed |
| govulncheck `called` (vulnerable symbol reached from the program's own entry points) | `called-unreached`, call sites from the trace | confirmed |
| govulncheck `imported` only | `imported-not-called` (`imported-unknown-symbol` when the advisory lists no symbols) | confirmed / package-level |
| govulncheck `required` only | `unused` | confirmed |
| advisory unknown to the Go database, or govulncheck missing, failed or offline | `imported-unknown-symbol` for go.mod modules, `unused` for go.sum-only ones | package-level |

The report records which route decided (`goAnalysis`: call-graph, govulncheck or none) and
govulncheck's error when it could not run (a dependency that needs cgo on a machine without
a C compiler is the common case). Known limit: a vulnerable call inside auth middleware is
reached by every route but is modelled as called from a guard, not a handler, so it reports
as called-unreached rather than reachable.

## 3. Exploitation

- `active` — any CVE the advisory covers is in CISA KEV (the why line names it).
- `likely` — the highest EPSS across the advisory's CVEs is ≥ 0.10 (10% probability of
  exploitation in 30 days).
- `none` — otherwise.

An advisory often bundles several CVEs (a GHSA with two aliases, a Debian or Ubuntu notice
with ten); evidence on any of them counts.

## 4. Decision

Modelled on CISA's SSVC deployer tree, with reachability standing in for "automatable" and
exposure standing in for "mission & well-being".

| Tier | Rule | Decision |
|---|---|---|
| dev-only, unused, imported-not-called | vulnerable code not in execute path | **Track** |
| imported-unknown-symbol | exploitation ≠ none **or** CVSS ≥ 7 → Attend, else | **Track\*** |
| image-only | exploitation = active, **or** (a fix exists **and** (exploitation = likely **or** CVSS ≥ 7)) → Attend, else | **Track\*** |
| called-unreached | exploitation = active → Attend, else | **Track\*** |
| reachable, unauthenticated | exploitation ≠ none **or** CVSS ≥ 9 **or** (user input **and** CVSS ≥ 7) → **Act**, else | **Attend** |
| reachable, authenticated | exploitation = active → **Act**, else | **Attend** |

Meanings follow SSVC: **Act** = fix now, out of cycle; **Attend** = fix in the next cycle,
tell the owner; **Track\*** = watch closely, re-check on new exploit data; **Track** = no
action, re-evaluate on change.

"User input" in the reachable rows is read from the path the decision is made on: an
unauthenticated path is preferred over an authenticated one even when only the latter
carries request data. The why lines mention the other path when it exists.

## 5. Score (0–100, ordering only)

```
base      = CVSS × 10 (5.0 × 10 if unknown)
reach     = reachable 1.0 · called-unreached 0.55 · imported-unknown-symbol 0.6
            · image-only 0.5 · imported-not-called 0.2 · unused 0.1 · dev-only 0.05
auth      = reachable & authenticated → × 0.75
local     = network local-only → × 0.5
score     = base × reach × auth × local + EPSS × 20 + (KEV ? 15 : 0) + (user input ? 5 : 0)
```

The score never changes a decision; it orders findings within a decision.

## 6. OpenVEX mapping

| Tier | status | justification / note |
|---|---|---|
| dev-only | `not_affected` | `component_not_present` |
| unused | `not_affected` | `vulnerable_code_not_in_execute_path` |
| imported-not-called | `not_affected` | `vulnerable_code_not_in_execute_path` (confidence stated) |
| called-unreached | `under_investigation` | call sites listed; confirm dead code before closing |
| imported-unknown-symbol | `affected` | no function data; `action_statement` = fix |
| image-only | `affected` | present in the image, no code path traced; `action_statement` = fix |
| reachable | `affected` | path in `status_notes`; `action_statement` = fix |

The image-only rule leans on "a fix exists" because a distribution advisory with no fix
gives the owner nothing to do but watch; KEV overrides that. Distribution advisories often
carry no severity of their own, so the CVE record in OSV supplies CVSS and summary when the
distribution entry lacks them.

## 7. Known limits of the spike (say them out loud)

- Entry points: Express (`app`/`router` methods, `app.route(path)` chains, `express.Router()`
  mounts, `app.use(guard)` ordering), Fastify (route options hooks, `route({…})`,
  `register(plugin, { prefix })`, `addHook` scopes, `@fastify/autoload` folder prefixes and
  `autohooks`), and Koa (`@koa/router`-style routers incl. third-party `…Router` classes,
  prefixes, `router.use(guard)`, `app.use(router.routes())` mounts). Guards are recognised by
  **name** (`isLoggedIn`, `requireAuth`, `passport.authenticate`, `isAuthorized`, `jwt(`, …)
  after a non-guard list (`session()`, `passport.initialize()`, `helmet`, rate limiters, …)
  and an anti-guard list (`unprotected`, `public…`) are excluded, or by **body** for inline
  functions that reject requests (401/403, `unauthorized`, `ctx.throw`). Add project names
  via `nextfix.config.json`. Not covered: NestJS decorators, Hapi, serverless handlers.
- Python entry points: Flask (`@app.route`/`@bp.<verb>`, blueprint `url_prefix`,
  `register_blueprint` incl. inside `create_app()`, decorator guards, rejecting
  `before_request` hooks), FastAPI (`APIRouter(prefix, dependencies)`, nested
  `include_router`, `Depends(...)` and `CurrentUser`-style annotations as guards), Django
  (`urlpatterns`, `include()`, function and class-based views per verb, `LoginRequiredMixin`,
  `@login_required`, `permission_classes`). Every handler parameter is request data.
- Framework-internal code paths are not modelled: an advisory in Django's request parsing or
  a middleware runs on every request without your code calling it, so it shows as
  "imported, not called" unless your code calls the affected function. Treat those as a
  reason to upgrade on the normal cycle, which is what Track says.
- Handlers: inline functions, local functions, `controller.method`, `instance.method` of an
  imported class, factory calls (`login()`) and one level of wrapper (`asyncHandler(fn())`).
  Anything else is kept as an entry point with `unresolvedHandlers`, so the route still counts
  but no path can be traced through it.
- Call graph: intra-file by name, cross-file by export name or by any function of that name
  in the target module, `this.method()`, and containment (a function reaches the callbacks and
  closures defined inside it). No dynamic dispatch, no class hierarchies, no prototype chains.
- Request data: tracked by name. Inside a function, each argument is reduced to the names it
  derives from (parameters, `req`/`request`, captured identifiers), resolving local variables,
  destructuring and call results. Any identifier named `req`, `request` or `ctx` counts as
  request data wherever it appears, including one the application built itself; this
  over-approximates on purpose. Along a path, a callee's parameter is tainted when the
  argument at its position is; a callback or returned closure inherits the tainted names it
  captures. The vulnerable call is "reached by request data" only when one of its own
  arguments traces back. Not tracked: object fields written then read elsewhere, data passed
  through `this`, databases, globals, and sanitisers (a cleaned value still counts as tainted).
- Bundlers and tree-shaking are ignored: "present" means "in the lockfile".
- Container images: what syft reports is what counts; packages are matched to OSV by
  distribution release and source package, so an image whose SBOM carries no `distro`
  qualifier is queried release-less (Debian, Ubuntu) or not at all (Alpine, where OSV only
  has per-release data). Binaries (`pkg:generic`) and package types OSV has no ecosystem for
  are inventoried but never queried, and the Components page counts them. No layer
  attribution yet.
- Cross-file resolution over-approximates on purpose: every public function that can reach the
  changed code counts (moment's `months()` reads locale config, so it is listed with
  `locale`). The decision still depends on whether *your* code calls one of them.
- Built entry files (`lib/*.cjs`, `dist/`) are tried after source entries; a repo whose only
  entry is a build artifact that does not import its sources falls back to per-file symbols.
- Advisories without a GitHub fix link in OSV stay `imported-unknown-symbol`.
