# NextFix

**Scanners find. NextFix decides.**

NextFix looks at an application and tells you which of its vulnerabilities actually matter,
in what order, and why. It does not try to find more issues. Scanners already find
thousands; the job is to work out which ones are **reachable** from
an entry point, **exposed** to an attacker, and **exploited** in the wild, and to hand both
the executive and the engineer a short list with the evidence attached.

Built by GRCSAC for small and medium businesses: self-contained, runs locally or on your
own server, nothing leaves your network.

**Current version:** `v0.2.0` · history in [CHANGELOG.md](CHANGELOG.md)

---

## Two dashboards, one scan

```bash
npm install
npm run serve        # builds the UI and opens http://127.0.0.1:8790
```

Enter a project folder on the welcome screen. NextFix scans it and keeps the history.

- **Executive:** fix-now and fix-next-cycle counts with change since the last scan, the
  share of findings set aside with evidence, unauthenticated entry points, the trend across
  scans, where the findings landed and why, what to fix first, what changed, and exposure.
- **Remediation:** the queue filtered by decision, reachability and search; each finding
  opens with the plain-English why, the call path from entry point to vulnerable function
  (showing where request data enters), the upgrade command, copy-as-ticket, and VEX download.

Both views follow the OS light/dark setting and work at phone width.

## The command line

Point it at a Node.js project with a `package-lock.json`:

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

1. **Inventory** — every component from `package-lock.json`, with dev / direct / transitive flags.
2. **Advisories** — [OSV](https://osv.dev) for the advisories, [FIRST EPSS](https://www.first.org/epss/)
   for exploit probability, [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
   for confirmed in-the-wild exploitation. Cached locally in SQLite; `--offline` reuses the cache.
3. **Code** — a call graph of your source (TypeScript compiler parser, no type-checking needed),
   Express routes as entry points with their mount prefixes and auth guards, and a one-level
   request-data taint hint.
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
(extracted from the fix commit, coming), or `package-level` (no function data).
The full rules are in [docs/DECISION-MODEL.md](docs/DECISION-MODEL.md).

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

## Feature status

| Area | Status |
|---|---|
| npm lockfile inventory (v2/v3) | ✅ |
| OSV + EPSS + KEV with local cache and offline mode | ✅ |
| JavaScript/TypeScript call graph, Express entry points, auth guards, mounts | ✅ spike |
| Request-data taint hint (one level + chain propagation) | ✅ heuristic |
| Reachability tiers + SSVC-style decision + score | ✅ |
| Docker / compose exposure | ✅ |
| OpenVEX + JSON report | ✅ |
| Vulnerable-symbol data | 🟡 curated seed (7 advisories) |
| Derived symbols from fix commits (automated, human-reviewed) | ⬜ |
| Python (Flask / FastAPI / Django) | ⬜ |
| Go (govulncheck wrapper) | ⬜ |
| Web UI: executive + remediation dashboards | ✅ |
| Server mode: SQLite history, trends, scan diff, JSON API | ✅ |
| SSO (OIDC), RBAC, audit log, API tokens | ⬜ |
| Container image inventory (Syft/Grype adapter) | ⬜ |
| Jira / GitHub Issues export | ⬜ |
| Packaging: single executable + Docker image | ⬜ |

See [docs/ROADMAP.md](docs/ROADMAP.md) for sequencing.

## Parking lot

- Executive one-page PDF export; scheduled re-scans; e-mail or Slack digest.
- Jira / GitHub Issues push (copy-as-ticket covers it manually today).
- Fastify, Koa, NestJS, Hapi entry-point detection.
- Framework objects beyond Express `res` (e.g. Next.js API routes, serverless handlers).
- Import of a CycloneDX SBOM instead of a lockfile.
- Deeper taint (sanitizers, multi-level, object fields).
- Bundler-aware analysis (tree-shaken builds change what is "present").

> **Authorized use only.** Point NextFix at code you own or are authorized to assess.
