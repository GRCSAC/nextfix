# NextFix™

**Scanners find. NextFix decides.**

NextFix looks at an application and tells you which of its vulnerabilities actually matter,
in what order, and why. It does not try to find more issues. Scanners already find
thousands; the job is to work out which ones are **reachable** from
an entry point, **exposed** to an attacker, and **exploited** in the wild, and to hand both
the executive and the engineer a short list with the evidence attached.

Built by GRCSAC for small and medium businesses: self-contained, runs locally or on your
own server, nothing leaves your network.

**Current version:** `v1.0.1` · history in [CHANGELOG.md](CHANGELOG.md)

---

## The dashboards

```bash
npm install
npm run serve        # builds the UI and opens http://127.0.0.1:8790
```

Enter a project folder on the welcome screen. NextFix scans it and keeps the history.

- **Overview** (executives): one question per panel. A **posture verdict** (Exposed,
  Attention, Contained, Clean) with the sentence and the rule behind it; the **evidence
  funnel** from every advisory found down to the ones that are reachable without a login,
  carry request data and are known or likely exploited, with what each step removed; **what
  changed** since the previous scan as a bridge with the items named; the **work queue** (the
  four decisions, once); the **shortest path to green** (upgrades ranked by what they close,
  with the sentence "N upgrades clear everything that needs action"); **where an attacker
  gets in** (entry points as tiles sized by what they reach); **why each decision** (a
  reachability × exploitation matrix); the trend; and the evidence for auditors. "Print
  summary" turns the page into a one-sheet report.
- **Findings** (engineers): the queue filtered by decision, reachability and search; each
  finding opens with the plain-English why, the call path from entry point to vulnerable
  function (showing where request data enters), the upgrade command, copy-as-ticket, and
  VEX download.
- **Portfolio** (every application on one page: posture, owner, actionable count, exposed
  surface, oldest SLA breach, trend), **Components**, **Evidence** (every set-aside with its
  VEX justification, including exceptions a person approved), **Reports** (exports and scan
  history), **Apps** (owner, scan schedule) and **Settings** (theme, SLA days, GitHub Issues
  and Jira integrations, users and roles, single sign-on, API tokens, digest, audit log).

The first visit on the machine that runs the server creates the administrator; after that
everyone signs in (local account or single sign-on) and sees what their role allows:
viewers read, analysts scan and propose exceptions, admins approve and administer. For a
single-user laptop, `nextfix-server serve --allow-open` keeps the no-sign-in mode on loopback.

Dark by default, light and match-OS in Settings; works at phone width.

## The command line

Point it at a Node.js project (npm, yarn or pnpm lockfile, workspaces included), a Python
project with pinned requirements or a lockfile, a Go module, or any mix in one folder:

```bash
node packages/engine/src/cli.ts scan samples/express-shop --json out/report.json --vex out/report.openvex.json
```

Go modules work the same way (`go.mod` + `go.sum`; install [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
for symbol-level verdicts, NextFix finds it on the PATH or through `NEXTFIX_GOVULNCHECK`).
Add `--image <ref>` to inventory the built container image as well, or `--sbom <file>` to
read a CycloneDX, SPDX or Grype JSON document you already have (see
[Container images](#container-images)). `--sarif <file>` writes SARIF 2.1.0 for GitHub code
scanning; a ready-made workflow with a pull-request comment is in [docs/ci](docs/ci/README.md).

In a pipeline, `--fail-on Act` (or `Attend`) exits with code 3 when any finding is decided
that or worse, so a build can gate on "nothing to fix now" while the JSON report is kept as
an artefact. Exit codes: 0 ok, 1 error, 2 usage, 3 gate failed.

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

1. **Inventory** — every component from `package-lock.json`, `yarn.lock` or `pnpm-lock.yaml` (workspaces included), `go.mod` + `go.sum`, and/or pinned Python
   dependencies (`requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`), with dev /
   direct / transitive flags.
2. **Advisories** — [OSV](https://osv.dev) for the advisories, [FIRST EPSS](https://www.first.org/epss/)
   for exploit probability, [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
   for confirmed in-the-wild exploitation. Cached locally in SQLite; `--offline` reuses the cache.
3. **Code** — a call graph of your source (TypeScript compiler parser for JavaScript and
   TypeScript, tree-sitter for Python and Go), entry points with their mount prefixes and auth
   guards for Express, Fastify, Koa, Flask, FastAPI, Django, net/http, Gin, Echo, Chi, Fiber,
   gorilla/mux and httprouter, and request data traced argument by
   argument from the handler to the vulnerable call.
4. **Reachability** — one of seven evidence-graded tiers per advisory (see below). For Go,
   `govulncheck` adds the Go vulnerability database's symbol data and its own verdict on calls
   made inside dependencies.
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
| `image-only` | present in the container image but not imported by the application (OS package, tooling, a binary) | Track\* / Attend |
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
  "internalRoutes": ["GET /healthz", "GET /metrics"],
  "image": "ghcr.io/example/shop:1.4",
  "sbom": ["build/shop.cdx.json"]
}
```

`authGuards` are regular expressions added to the built-in guard names (`authGuardsReplace: true`
replaces them). `internalRoutes` are treated as authenticated. `image` and `sbom` take one
reference or a list; `syft` names the syft binary when it is not on the PATH (or `"docker"`
to always use the container).

### Container images

The lockfile says what the application depends on; the image says what actually ships
around it: the base distribution's packages, a Node or Python runtime, globally installed
tooling and its dependencies. NextFix inventories the image through
[syft](https://github.com/anchore/syft) and merges the result with the lockfile:

- **Where syft comes from.** A `syft` on the PATH (or `NEXTFIX_SYFT`) is used first. If
  there is none, or it fails, and Docker is available, NextFix runs the pinned
  `anchore/syft` container against the daemon's socket, which reads any image the daemon
  has. With neither, the image is reported as not inventoried and the scan continues.
- **SBOM files** (`*.cdx.json`, `*.spdx.json`, `sbom.json`, `bom.json`) at the project root
  are read without being asked; `--sbom` and `sbom` in the config add others. A Grype
  report is accepted too (only its matched artifacts are known).
- **OS packages** are queried in their distribution's OSV ecosystem (`Debian:12`,
  `Ubuntu:22.04:LTS`, `Alpine:v3.18`, Wolfi, Chainguard, Red Hat, AlmaLinux, Rocky Linux) by
  source package, so `libssl3` and `openssl` become one `openssl` finding, and fixed
  versions are compared the way `dpkg` compares them. Go modules found in binaries are
  queried in the Go ecosystem. Binaries and unknown package types are listed as `generic`
  and not queried; the Components page says how many.
- **Decisions.** A package that is also in the lockfile keeps its code-level tier. A package
  only in the image lands in `image-only`: NextFix makes no call-path claim inside an image,
  so the call rests on exploitation evidence, severity and whether the distribution has
  shipped a fix (Attend when in KEV, or fixable and EPSS ≥ 10% or CVSS ≥ 7; otherwise
  Track\*). The fix text says to rebuild from an updated base image or upgrade the package in
  the Dockerfile, and the ticket carries the `apt-get` / `apk` / `dnf` line.

On the demo image (`docker build -t nextfix-sample:dev samples/express-shop`, Alpine 3.24
base) the image adds 158 components to the lockfile's 53: 18 Alpine packages, the Node
binary, and npm's own bundled dependencies, which produce the `image-only` findings.

## Run it

Requires Node 24+ (the engine and server run TypeScript directly; only the UI is bundled).
Without Node: the single executable and the Docker image are described in
[docs/INSTALL.md](docs/INSTALL.md), with upgrades, backups and reverse-proxy setup.

```bash
npm install
npm run serve                # build the dashboards, start the local server, open the browser
npm run scan:sample          # CLI: scans samples/express-shop, writes out/*.json
npm test                     # engine tests (no network)
npm run typecheck            # engine + server + web
```

Scan history lives in `~/.nextfix/nextfix.sqlite`; advisory caches in `~/.nextfix/cache.sqlite`.
`nextfix serve --host 0.0.0.0` exposes the dashboards to the LAN; accounts, roles and single
sign-on are built in, and the first visit from the server's own machine creates the admin. The server answers only to `localhost`, `127.0.0.1`, the `--host` value and any
`--allow-host <name>` you add, and refuses state-changing requests from other origins, so a
web page cannot drive it. Run one server per database: a second one sees the first in the
header and waits for its scans.

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
| gin-realworld (Gin, go.mod) | 43 | 58 | 27 / 27 | 0 · 0 · 20 · 45 | 9 s |
| go-clean-arch (Echo) | 31 | 61 | 4 / 4 | 0 · 0 · 17 · 51 | 10 s |
| go-test-bench (Gin + Chi + net/http + httprouter) | 53 | 75 | 20 / 20 | 1 · 11 · 11 · 59 | 11 s |
| go-dvwa (net/http + gorilla/mux) | 68 | 55 | 3 / 3 | 0 · 5 · 18 · 39 | 9 s |
| gophish (gorilla/mux; govulncheck needs cgo, fell back to package level) | 47 | 212 | 51 / 51 | 0 · 68 · 114 · 38 | 12 s |
| govwa (httprouter) | — | — | 20 / 20 | — | — |

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
| Go: go.mod/go.sum inventory, govulncheck symbols and verdicts, call graph for net/http, Gin, Echo, Chi, Fiber, gorilla/mux, httprouter | ✅ |
| yarn.lock, pnpm-lock.yaml and workspaces (npm, yarn, pnpm) | ✅ |
| Web UI: Overview, Findings, Components, Evidence, Reports, Apps, Settings | ✅ |
| Brand applied (see docs/BRAND.md) | ✅ |
| Server mode: SQLite history, trends, scan diff with reasons, finding history + SLA ageing, progress and cancel, JSON API | ✅ |
| Executive Overview: posture verdict, evidence funnel, what changed, fix leverage, attack surface, decision matrix, print summary | ✅ |
| Re-check exploit data without re-scanning (KEV/EPSS re-decide) | ✅ |
| Accounts, roles (admin / analyst / viewer), single sign-on (Entra ID, Google, Okta, generic OIDC), API tokens, audit log | ✅ |
| Exceptions with approver and expiry, in the VEX export and the Decide panel | ✅ |
| Portfolio across applications, owner and schedule per application | ✅ |
| Scheduled scans, nightly re-decide, weekly digest (e-mail, Slack, Teams) | ✅ |
| Container image inventory (syft binary or container; CycloneDX / SPDX / Grype input; distro ecosystems) | ✅ |
| Jira / GitHub Issues export (per finding and bulk, links remembered) | ✅ |
| CI gate (`--fail-on`, exit codes) | ✅ |
| SARIF 2.1.0 output, GitHub Actions template with pull-request comment (docs/ci) | ✅ |
| Packaging: single executable per platform, Docker image with syft, signed release pipeline (docs/INSTALL.md) | ✅ |

See [docs/ROADMAP.md](docs/ROADMAP.md) for sequencing.

## Parking lot

- Executive PDF beyond the print summary; scheduled re-scans and nightly re-decide; e-mail,
  Slack or Teams digest; portfolio view across applications; human exceptions with approver
  and expiry; SARIF output.
- NestJS and Hapi entry-point detection.
- Framework objects beyond Express `res` (e.g. Next.js API routes, serverless handlers).
- Image sources beyond the daemon and registries when syft runs in its container (`dir:`,
  archives); layer attribution for image findings (which Dockerfile line brought it in).
- Deeper taint (sanitizers, multi-level, object fields).
- Bundler-aware analysis (tree-shaken builds change what is "present").

## License

Everything in this repository, the engine, the CLI, the server, both dashboards and the
team features (accounts, roles, single sign-on, audit log, API tokens, exceptions, digests),
is licensed under the [Apache License 2.0](LICENSE). Nothing is held back for a separate
edition. GRCSAC LLC may offer support and hosted editions; the software stays free.
"NextFix" and the logo are trademarks of GRCSAC LLC, used as unregistered marks (see
[NOTICE](NOTICE)).

Brand assets and the website hand-off are in [docs/BRAND.md](docs/BRAND.md).

> **Authorized use only.** Point NextFix at code you own or are authorized to assess.
