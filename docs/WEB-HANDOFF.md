# Website hand-off for nextfix.grcsac.com (1.0)

Everything the web team needs to update the site for the 1.0 release, in one place. The
site lives in its own repository; this file is the source of truth for facts, copy and
assets. Brand rules are in `BRAND.md`; screenshots are in `site/`.

## 1. The product in one breath

**NextFix™** · *Scanners find. NextFix decides.*

NextFix looks at an application and tells you which of its vulnerabilities actually matter,
in what order, and why. It does not try to find more issues. Scanners already find
thousands; the job is to work out which ones are **reachable** from an entry point,
**exposed** to an attacker, and **exploited** in the wild, and to hand both the executive
and the engineer a short list with the evidence attached.

Free and open source (Apache 2.0). Built by GRCSAC LLC for small and medium businesses.
Runs on your machine or your server; nothing leaves your network except advisory lookups.

Write **NextFix™** at the first mention on each page, plain "NextFix" afterwards. Never ®.
In the footer: "NextFix and the NextFix logo are trademarks of GRCSAC LLC."

## 2. Headline facts (all verifiable in the repository)

- Decides, does not scan: reads the lockfile and the source, builds a call graph, finds the
  HTTP entry points and their auth guards, and traces request data to the vulnerable call.
- Four decisions, one per finding, each with a plain-English "why": **Fix now**, **Fix next
  cycle**, **Watch**, **Set aside with evidence**. Set-asides go into an OpenVEX document
  auditors and Dependency-Track accept.
- Languages: JavaScript and TypeScript (Express, Fastify, Koa), Python (Flask, FastAPI,
  Django), Go (net/http, Gin, Echo, Chi, Fiber, gorilla/mux, httprouter), plus container
  images (OS packages of Debian, Ubuntu, Alpine, Wolfi, Chainguard, Red Hat, AlmaLinux,
  Rocky) and any CycloneDX or SPDX SBOM.
- Lockfiles: npm, yarn, pnpm (workspaces included), pip requirements, Pipfile.lock,
  poetry.lock, uv.lock, go.mod/go.sum.
- Data sources: OSV for advisories, FIRST EPSS for exploit probability, CISA KEV for
  confirmed exploitation. All cached locally; works offline from the cache.
- Executive dashboard: posture verdict, evidence funnel, what changed, shortest path to
  green, where an attacker gets in, SLA ageing, a printable one-page summary.
- Team edition is the same free download: accounts and roles, single sign-on (Microsoft
  Entra ID, Google, Okta), exceptions with approver and expiry, portfolio across
  applications, scheduled scans, nightly exploit-data re-check, weekly digest by e-mail,
  Slack or Teams, API tokens, audit log.
- Pipelines: `--fail-on Act` exit code, SARIF for GitHub code scanning, a ready-made
  GitHub Actions workflow with a pull-request comment.
- Since 1.1, exposure is observed, not inferred: access logs (nginx, Apache, AWS ALB, Caddy,
  Cloudflare, Traefik, pino) are counted per route over the last 30 days, so the dashboards say
  which open routes the internet is actually calling and which nobody has called; infrastructure
  files (Terraform, CloudFormation, Kubernetes, compose, fly.io, Vercel, Netlify) say whether the
  internet reaches the service at all; the Map page draws every application, what it calls and
  what calls it, with a one-click blast radius; and each scan reports what changed on the attack
  surface (new open routes, guards removed, new exposure, new public traffic). Nothing is
  installed and the logs never leave the machine.
- No telemetry, no account with us, no phone-home. Outbound hosts: osv.dev, api.first.org,
  cisa.gov, github.com (fix commits), and only the trackers or identity provider you configure.

## 3. Numbers the site may quote (measured 2026-10-10, see README "Validation")

| Application | Findings | Need action | Set aside or watched, with evidence |
|---|---|---|---|
| OWASP Juice Shop (Express, TypeScript) | 87 | 10 | 77 (89%) |
| OWASP NodeGoat (Express) | 311 | 4 | 307 (99%) |
| Flask microblog | 56 | 10 | 46 (82%) |
| OWASP PyGoat (Django) | 141 | 20 | 121 (86%) |
| Demo app (`samples/express-shop`) | 20 | 4 | 16 (80%) |

Entry-point coverage on real applications: every registered route found on six Go
applications; 87–100% on the Node and Python ones (the README table has each).

Safe generalisation for copy: "On real applications, four out of five findings a scanner
reports need no action right now, and NextFix says why for each one."

## 4. Downloads (replace placeholders with the current version)

Release page: `https://github.com/GRCSAC/nextfix/releases/latest`

| Platform | File | Notes |
|---|---|---|
| Windows | `NextFix-Setup-<v>.exe` | per-user installer, signed by GRCSAC, adds `nextfix` to the PATH, Start Menu entry "NextFix dashboards" |
| Windows (portable) | `nextfix-<v>-win32-x64.exe` | single signed executable |
| macOS Apple silicon | `nextfix-<v>-darwin-arm64` | `chmod +x`, then run |
| macOS Intel | `nextfix-<v>-darwin-x64` | |
| Linux x64 | `nextfix-<v>-linux-x64` | |
| Linux arm64 | `nextfix-<v>-linux-arm64` | |
| Docker | `ghcr.io/grcsac/nextfix:<v>` | signed with cosign; SBOM attached to the release |
| Checksums | `SHA256SUMS` | every file above |

Package managers (after each release is approved there):

```
winget install GRCSAC.NextFix
choco install nextfix
```

Docker one-liner for the download page:

```
docker run -d --name nextfix -p 8790:8790 -v nextfix-data:/data -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/grcsac/nextfix:<v>
docker exec -it nextfix nextfix user add admin --role admin
```

First run on a laptop: run `nextfix serve`, the browser opens, the first visit creates the
administrator. Full install, upgrade and backup notes: `INSTALL.md`.

## 5. Pages and copy

**Home.** Hero: the tagline, one sentence from section 1, the download button (Windows
installer detected by platform, "all downloads" link), and the evidence-funnel screenshot
(`site/overview-dark.png`). Three panels under it: *Reachable* (call path from a route to the
vulnerable call), *Exposed* (open routes, published ports), *Exploited* (KEV, EPSS). Then
the validation sentence from section 3 and the four-decision strip.

**How it works.** The pipeline (inventory → advisories → code → reachability → exposure →
decision → outputs) in the README's words; the seven reachability tiers table; the decision
table from `DECISION-MODEL.md` section 4. Link to the full decision model.

**For leadership.** The Overview, panel by panel, with `site/overview-full-dark.png`:
posture verdict, evidence funnel, what changed, work queue, ageing against SLA, shortest
path to green, where an attacker gets in, why each decision. One line each. "Print summary"
gives a one-sheet. Portfolio screenshot `site/portfolio-dark.png` for teams with several
applications.

**For engineers.** Findings screenshot `site/findings-dark.png`: the why, the call path with
"request data enters here", the fix command, copy as ticket, GitHub and Jira issues, VEX.
Pipeline section: `--fail-on`, SARIF, the workflow in `docs/ci/`.

**Download.** Section 4 verbatim, plus a "verify" box with the checksum command.

**Privacy.** Section 2's last bullet, expanded: what is read (lockfiles, source, SBOMs),
what is sent (package names and versions to OSV, CVE ids to FIRST, nothing else), where
data lives (`~/.nextfix`), and that the dashboards run on the user's own machine.

**Support and security.** Issues on GitHub; security reports to nextfix@grcsac.com
(`SECURITY.md` promises an acknowledgement within three working days).

## 6. Assets

- `brand/logo.svg` (the N mark; usable on light and dark), `brand/brand-sheet.png`.
- `site/overview-dark.png`, `site/overview-light.png` (1440 px, top of the Overview),
  `site/overview-full-dark.png` (the whole page), `site/portfolio-dark.png`,
  `site/findings-dark.png`, `site/evidence-light.png`. All taken from real scans of the demo
  app, Flask microblog and OWASP PyGoat at 1.0.0; no mock data.
- Colours and type: `BRAND.md`. The site keeps the house system font stacks.

## 7. Do not say

- Not "scanner", "vulnerability scanner" or "finds vulnerabilities": NextFix decides about
  what scanners find.
- No pricing, tiers, "enterprise edition" or "contact sales": everything is free and in the
  one repository.
- No claims of "zero false positives" or "guaranteed": the honest claim is "every set-aside
  carries evidence an auditor can check".
- No ® and no "patented".
