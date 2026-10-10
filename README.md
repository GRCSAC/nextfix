# NextFix

**Scanners find. NextFix decides.**

NextFix looks at an application and tells you which of its vulnerabilities actually matter,
in what order, and why. It does not try to find more issues. Scanners already find
thousands; the job is to work out which ones are **reachable** from
an entry point, **exposed** to an attacker, and **exploited** in the wild, and to hand both
the executive and the engineer a short list with the evidence attached.

Built by GRCSAC for small and medium businesses: self-contained, runs locally or on your
own server, nothing leaves your network.

**Current version:** `v0.6.0` · history in [CHANGELOG.md](CHANGELOG.md)

---

## The dashboards

```bash
npm install
npm run serve        # builds the UI and opens http://127.0.0.1:8790
```

Enter a project folder on the welcome screen. NextFix scans it and keeps the history.

- **Overview** (executives): total findings with a dot per decision, the remediation
  command center ring with Fix now / Fix next cycle / Set aside with evidence / Watch,
  entry points without authentication, the trend across scans, where the findings landed,
  component states, what to fix first, and evidence & exceptions.
- **Findings** (engineers): the queue filtered by decision, reachability and search; each
  finding opens with the plain-English why, the call path from entry point to vulnerable
  function (showing where request data enters), the upgrade command, copy-as-ticket, and
  VEX download.
- **Components**, **Evidence** (every set-aside with its VEX justification), **Reports**
  (exports and scan history), **Apps** and **Settings**.

Dark by default, light and match-OS in Settings; works at phone width.

## The command line

Point it at a Node.js project with a `package-lock.json`, or a Python project with pinned
requirements or a lockfile (or both in one folder):

```bash
node packages/engine/src/cli.ts scan samples/express-shop --json out/report.json --vex out/report.openvex.json
```

```
NextFix 0.1.0 — express-shop 1.0.0
53 components, 20 advisories → 20 findings
Act 1 · Attend 3 · Track* 2 · Track 14
80% of findings need no action right now, with evidence.
Entry points: 4 (3 unauthenticated) · network: published on 3000

DECISION  SCORE  PACKAGE          ADVISORY        REACH                  ENTRY                               FIX
Act       81     lodash@4.17.15   CVE-2021-23337  reachable              POST /preview                       → 4.17.21
Attend    66     express@4.17.1   CVE-2024-29041  reachable              GET /go                             → 4.19.2
Attend    46     lodash@4.17.15   CVE-2020-28500  reachable              POST /admin/users/normalize (auth)  → 4.17.21
Track*    42     lodash@4.17.15   CVE-2020-8203   called, unreached                                          → 4.17.19
Track     10     moment@2.29.1    CVE-2022-24785  not imported                                               → 2.29.2
Track     6      minimist@1.2.5   CVE-2021-44906  dev only                                                   → 1.2.6
```

Every finding carries a plain-English **why**:

```
Act · lodash@4.17.15 · CVE-2021-23337
  - lodash 4.17.15 is affected by CVE-2021-23337: Command Injection in lodash (CVSS 7.2 HIGH).
  - Reachable: POST /preview → <handler> (src/app.js:12) → renderTemplate (src/services/render.js:5)
    → _.template() at src/services/render.js:6.
  - User-controlled request data enters the chain in <handler> (src/app.js:12) and is passed down
    to the vulnerable call.
  - The entry point POST /preview has no auth guard.
  - Service is network-published: Dockerfile: EXPOSE 3000; docker-compose.yml: publishes port 3000.
  - Not in CISA KEV; EPSS 21.33% (percentile 98).
  - Upgrade lodash 4.17.15 → 4.17.21.
```

### The pipeline

1. **Inventory** — every component from `package-lock.json` and/or pinned Python
   dependencies (`requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`), with dev /
   direct / transitive flags.
2. **Advisories** — [OSV](https://osv.dev) for the advisories, [FIRST EPSS](https://www.first.org/epss/)
   for exploit probability, [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
   for confirmed in-the-wild exploitation. Cached locally in SQLite; `--offline` reuses the cache.
3. **Code** — a call graph of your source (TypeScript compiler parser for JavaScript and
   TypeScript, tree-sitter for Python), entry points with their mount prefixes and auth guards
   for Express, Fastify, Koa, Flask, FastAPI and Django, and request data traced argument by
   argument from the handler to the vulnerable call.
4. **Reachability** — one of six evidence-graded tiers per advisory (see below).
5. **Exposure** — Dockerfile `EXPOSE`, compose `ports:`, and whether the app binds to loopback.
6. **Decision** — an SSVC-style call: **Act**, **Attend**, **Track\***, **Track**, plus a 0–100 score
   for ordering and the "why" lines that justify it.
7. **Output** — terminal table, full JSON report, and an **OpenVEX** document whose
   `not_affected` statements carry the standard justification
   `vulnerable_code_not_in_execute_path`, so Dependency-Track and auditors accept them.

### Reachability tiers

| Tier | Meaning | Default decision |
|---|---|---|
| `dev-only` | devDependency, not in the shipped artifact | Track |
| `unused` | installed, but no source file imports it | Track |
| `imported-not-called` | imported, but none of the vulnerable functions are called | Track |
| `imported-unknown-symbol` | imported, and NextFix has no function-level data for this advisory yet | Track\* / Attend |
| `called-unreached` | the vulnerable function is called, but no HTTP entry point leads there | Track\* / Attend |
| `reachable` | an entry point leads to the vulnerable call; graded by auth, user input, exposure, EPSS, KEV | Attend / Act |

Confidence is shown with every tier: `confirmed` (hand-curated function data), `derived`
(extracted from the fix commit), or `package-level` (no function data).
The full rules are in [docs/DECISION-MODEL.md](docs/DECISION-MODEL.md).

### Where the function data comes from

A reachability tier below "imported" needs to know *which functions* of a package carry the
advisory. NextFix has two sources:

1. **Curated** entries in `packages/engine/data/vulnerable-symbols.json`, hand-checked.
2. **Derived** entries, built during the scan for anything not curated: the advisory's fix
   commit on GitHub is diffed, the touched lines are mapped to the functions that contain
   them, and those are resolved to the file's public surface (exports, `obj.name = fn`
   assignments, public callers up to three hops, callbacks passed as arguments). The entry
   is stored on the machine with the commit as evidence and shown as confidence `derived`.

```bash
node packages/engine/src/cli.ts symbols derive GHSA-p6mc-m468-83gw lodash   # try one
node packages/engine/src/cli.ts symbols list                                 # what this machine has derived
node packages/engine/src/cli.ts symbols confirm GHSA-p6mc-m468-83gw lodash  # after you reviewed it
node packages/engine/src/cli.ts symbols export reviewed.json                # confirmed entries as curated JSON
```

Set `GITHUB_TOKEN` to lift GitHub's unauthenticated limit; `--no-derive` skips the step.
Derivation then follows the package's import graph from its entry file, so a fix in an
internal module is reported as the public names that reach it (moment's locale fix as
`moment.locale`, marked's regex fix as `marked`/`parse`). When no entry export reaches the
change, NextFix says so rather than guessing.

### Per-project settings

Optional `nextfix.config.json` in the project root:

```json
{
  "authGuards": ["checkSession", "requireTenant"],
  "ignore": ["scripts", "tools"],
  "internalRoutes": ["GET /healthz", "GET /metrics"]
}
```

`authGuards` are regular expressions added to the built-in guard names (`authGuardsReplace: true`
replaces them). `internalRoutes` are treated as authenticated.

## Run it

Requires Node 24+ (the engine and server run TypeScript directly; only the UI is bundled).

```bash
npm install
npm run serve                # build the dashboards, start the local server, open the browser
npm run scan:sample          # CLI: scans samples/express-shop, writes out/*.json
npm test                     # engine tests (no network)
npm run typecheck            # engine + server + web
```

Scan history lives in `~/.nextfix/nextfix.sqlite`; advisory caches in `~/.nextfix/cache.sqlite`.
`nextfix-server serve --host 0.0.0.0` exposes the dashboards to the LAN (no auth yet; see roadmap).

The demo target `samples/express-shop` is a deliberately old Express app that exercises
every tier. Its `package-lock.json` is committed; do not update its versions.

## Validation on real applications

Measured 2026-10-09 on open-source applications, cloned fresh, scanned with derivation on.
"Routes" is what `grep` finds in the routes files; "found" is NextFix's entry points there.
Times are for a repeat scan with advisories cached; the first scan of a project also derives
symbols from fix commits, which can take a few minutes for a large dependency tree.

| Application | Components | Advisories | Routes / found | Act · Attend · Watch · Set aside | Scan time |
|---|---|---|---|---|---|
| OWASP Juice Shop (Express, TypeScript) | 1,178 | 87 | 109 / 105 | 0 · 10 · 16 · 61 | 5 s |
| OWASP NodeGoat (Express) | 1,091 | 311 | 20 / 19 | 0 · 4 · 5 · 302 | 12 s |
| Hackathon Starter (Express) | 689 | 2 | 102 / 89 | 0 · 0 · 0 · 2 | 1 s |
| Fastify demo (fastify-cli, autoload, TypeScript) | 462 | 0 | 15 / 15 | — | 1 s |
| node-typescript-koa-rest (Koa, koa-jwt) | 877 | 119 | 7 / 7 | 0 · 4 · 2 · 113 | 6 s |
| microblog (Flask, blueprints, flask-login) | 54 | 56 | 35 / 35 | 2 · 8 · 4 · 42 | 1 s |
| OWASP PyGoat (Django, requirements.txt) | 34 | 141 | 137 / 137 | 4 · 16 · 15 · 106 | 2 s |
| full-stack-fastapi-template (FastAPI, uv.lock) | 134 | 0 | 23 / 23 | — | 1 s |

What the first pass got wrong, and what changed because of it, is in the 0.4.1 entry of
[CHANGELOG.md](CHANGELOG.md). What is still open: handlers NextFix cannot follow are listed
per entry point as `unresolvedHandlers` (11 of 107 on Juice Shop, mostly third-party
middleware factories), and request-data tracing follows names, not object fields or
databases, so data stored and read back later is not followed.

Juice Shop needed one line of `nextfix.config.json` to ignore `data/static/codefixes`, a
folder of challenge snippets that re-declare the server's routes without their imports.

## Feature status

| Area | Status |
|---|---|
| npm lockfile inventory (v2/v3) | ✅ |
| OSV + EPSS + KEV with local cache and offline mode | ✅ |
| JavaScript/TypeScript call graph; Express, Fastify (incl. autoload) and Koa entry points, auth guards, mounts | ✅ |
| Python inventory (requirements, Pipfile.lock, poetry.lock, uv.lock) + PyPI advisories | ✅ |
| Python call graph; Flask, FastAPI and Django entry points, guards, blueprints/routers/includes | ✅ |
| Python symbol derivation from fix commits (incl. `__init__` re-exports) | ✅ |
| Request-data tracing, argument by argument along the path | ✅ |
| Reachability tiers + SSVC-style decision + score | ✅ |
| Docker / compose exposure | ✅ |
| OpenVEX + JSON report | ✅ |
| Vulnerable-symbol data | ✅ curated seed (7 advisories) + derived from fix commits |
| Derived symbols from fix commits, with a review and export path | ✅ |
| `nextfix.config.json` (auth guards, ignored dirs, internal routes) | ✅ |
| Go (govulncheck wrapper) | ⬜ |
| Web UI: Overview, Findings, Components, Evidence, Reports, Apps, Settings | ✅ |
| Brand applied (see docs/BRAND.md) | ✅ |
| Server mode: SQLite history, trends, scan diff, JSON API | ✅ |
| SSO (OIDC), RBAC, audit log, API tokens | ⬜ |
| Container image inventory (Syft/Grype adapter) | ⬜ |
| Jira / GitHub Issues export | ⬜ |
| Packaging: single executable + Docker image | ⬜ |

See [docs/ROADMAP.md](docs/ROADMAP.md) for sequencing.

## Parking lot

- Executive one-page PDF export; scheduled re-scans; e-mail or Slack digest.
- Jira / GitHub Issues push (copy-as-ticket covers it manually today).
- NestJS and Hapi entry-point detection.
- Framework objects beyond Express `res` (e.g. Next.js API routes, serverless handlers).
- Import of a CycloneDX SBOM instead of a lockfile.
- Deeper taint (sanitizers, multi-level, object fields).
- Bundler-aware analysis (tree-shaken builds change what is "present").

## License

NextFix is open-core. Everything in this repository, the engine, the CLI, the server and
both dashboards, is licensed under the [Apache License 2.0](LICENSE). Team features
(single sign-on, roles, audit log, API tokens) and the curated vulnerable-symbol feed with
support are offered commercially by GRCSAC LLC and live outside this repository.
"NextFix" and the logo are trademarks of GRCSAC LLC (see [NOTICE](NOTICE)).

Brand assets and the website hand-off are in [docs/BRAND.md](docs/BRAND.md).

> **Authorized use only.** Point NextFix at code you own or are authorized to assess.
