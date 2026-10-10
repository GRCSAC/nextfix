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

## 0.3 — Brand, redesign, open-core (done 2026-10-09)

Dashboard rebuilt to the approved prototype (rail, tabs, command center ring, entry points,
component states, evidence & exceptions), brand palette and mark applied, Components /
Evidence / Reports / Apps / Settings pages, Apache-2.0 license with the open-core split.

## 0.4 — Make the evidence wider (done 2026-10-09)

Derived symbols from fix commits with evidence, review (`symbols confirm`) and export;
`nextfix.config.json`; chained Express routes. Validation on the demo: five of six curated
advisories reproduced, 12 of 14 uncurated advisories gained function data.

0.4.1 validated the analyzer on Juice Shop, NodeGoat and Hackathon Starter and fixed what
that found (see CHANGELOG). Coverage per routes file is now 87–96% of the registrations.

Both follow-ups landed in 0.5.1: argument-level request-data tracing, and duplicate lockfile
entries merged into one component.

## 0.5 — Cross-file symbol resolution (done 2026-10-09)

Derived symbols follow the package's import graph from its entry file, so internal fixes
report as public names (moment `locale`, marked `parse`, qs `parse`). Entry chosen
source-first; barrels, `module.exports = require()`, classes and module-level variables are
followed. Validated live on moment, marked, qs, lodash, express, send, minimist.
- Fastify and Koa entry points; `express.static` and regex paths.
- Container image inventory through a Syft/Grype adapter (external binary, optional).
- A review page in the dashboard for derived entries (today it is the CLI).

0.5.2 added Fastify (with autoload) and Koa entry points, validated on the official Fastify
demo and a Koa REST template. Order agreed for what follows: Python, then the team edition,
then Go.

## 0.6 — Python (done 2026-10-09)

Flask, FastAPI and Django entry points on a tree-sitter analyzer, PyPI inventory and
advisories, Python symbol derivation through package `__init__` files. Validated on Flask
microblog, OWASP PyGoat and the FastAPI full-stack template. **This is the release the
repository goes public with** (later moved to after the 1.0 feature list).

Known open: Django/DRF `permission_classes` as class attributes, Flask-RESTful / Flask-RESTX
resource classes, Starlette-only apps, Tornado; method calls on framework objects
(`request.get_host()`) cannot be matched to derived symbols.

## Before going public (decided 2026-10-09)

The repository opens once the five remaining feature-table items are done, in this order:

1. Jira and GitHub Issues export (0.7) — done 2026-10-09
2. Container image inventory through a Syft adapter (0.8) — done 2026-10-09
   - 0.8.1 hardening (server origin/host/content-type defences, tracker-host allowlist,
     analyzer false-safe fixes, CI gate, CI workflow) — done 2026-10-10 after a full review
   - 0.8.2 experience release (Overview rebuilt around verdict / funnel / what changed /
     fix leverage / attack surface / matrix / ageing, re-check exploit data, finding history
     and SLA, phone layout, progress and cancel, contrast and theme fixes, reachability
     performance) — done 2026-10-10
3. Go via govulncheck, SARIF and CI mode (0.9) — done 2026-10-10
4. Team features: local accounts, roles, audit log, API tokens, OIDC, exceptions, portfolio, schedules and digest (0.10) — done 2026-10-10
5. Packaging: single executable per platform, Docker image, Windows installer (1.0)

Decided 2026-10-10: the name is used as an unregistered mark (NextFix™); a use-based filing
may follow after launch. The prepared application stays in `docs/TRADEMARK.md`.

## 0.8 — Container images (done 2026-10-09)

`image` in `nextfix.config.json` or `--image` on the CLI inventories the built image through
syft (local binary, or the pinned `anchore/syft` container when Docker is present); SBOM files
(CycloneDX, SPDX, Grype JSON) are read directly, and any `*.cdx.json` / `*.spdx.json` at the
project root is picked up. OS packages are queried in their distribution's OSV ecosystem
(`Debian:12`, `Alpine:v3.18`, `Ubuntu:22.04:LTS`, Wolfi, Chainguard, Red Hat, AlmaLinux,
Rocky) by source package, with dpkg-style version ordering for fixes. A package that exists
only in the image lands in the `image-only` tier: watched, or scheduled when exploited or
fixable and severe. Go modules found in binaries are queried too.

Known open: no call-path claim is made inside an image; the container route reads daemon
images only (not `dir:` or archive sources); Grype itself is not needed because OSV answers
for every supported distribution.

## 0.10 — Team features (done 2026-10-10, open, in this repo)

- Local accounts with hashed passwords and cookie sessions; first-run admin setup.
- OIDC single sign-on: generic authorization-code flow with PKCE and discovery, presets for
  Microsoft Entra ID, Google and Okta; validated end to end against Entra ID first.
- Roles: admin, analyst, viewer (executives are viewers). Audit log. Scoped API tokens.
- Human exceptions (accept risk, false positive, mitigated elsewhere) with reason, approver,
  expiry and review date, exported into the VEX and shown in the "decide" panel.
- Portfolio view across applications; owner per application.
- Scheduled scans, nightly re-decide, and a digest by email, Slack and Teams (Teams first).
- Offline advisory bundles for air-gapped installs.
- WCAG AA on every page and a stable API.

## 0.9 — Go and pipeline mode (done 2026-10-10)

go.mod/go.sum inventory with replace and exclude; govulncheck as an optional binary for
symbol data and verdicts; a tree-sitter Go call graph with entry points and guards for
net/http, Gin, Echo, Chi, Fiber, gorilla/mux and httprouter, validated on six real Go
applications (every registered route found). SARIF 2.1.0 output, a GitHub Actions template
with a pull-request comment, yarn.lock and pnpm-lock.yaml with workspaces.

Known open: `go.work` workspaces, local-directory `replace` targets, gRPC and other
fasthttp routers; govulncheck needs a C compiler for cgo dependencies.

## Going public

Decision 2026-10-09 (revised the same day): NextFix is offered to the community rather than
sold, under Apache-2.0 with nothing held back. The repository goes **public with the Python
release (0.6)**, once two ecosystems make it clearly more than a demo. The public day is a
launch, not a flip:
- Launch prep done ahead of time: `SECURITY.md` (private disclosure path), `CONTRIBUTING.md`
  with a Developer Certificate of Origin, issue and pull-request templates, a code of conduct.
- The name used as NextFix™ with dated first-use evidence kept from launch day; a use-based
  registration can follow when it is worth the fee.
- History reviewed once more: no attribution trailers, no internal paths, no secrets.
- A launch post (LinkedIn, the Exposure Management community) with the validation table.

Should selling support or a hosted edition ever become interesting, the Apache-2.0 license
does not prevent it and nothing shipped free is taken back; the "team edition" phase below
simply becomes features in the open repo.

## 1.0 — Ship

- Single executable per platform (Node single-executable application) and a Docker image
  on GitHub's container registry, signed with cosign.
- Installer for Windows like NetVane, Authenticode-signed through Microsoft Trusted Signing
  (CN=GRCSAC, the same account and fail-closed release script as NetVane); `winget` +
  Chocolatey.
- One release workflow: build matrix, tests, NextFix scanning itself with `--fail-on Act`,
  assets attached, notes from the changelog.
- Website `nextfix.grcsac.com` (brand kit in `docs/BRAND.md`); open edition free, team
  edition priced per application count.
- Launch-day evidence of first use of the NextFix™ mark saved (see `docs/TRADEMARK.md`),
  then flip the repo public.
