# Launch post (LinkedIn, the Exposure Management community)

Use as written or trim; the numbers are from the README's validation table.

---

**NextFix™ 1.0 is out, and it is free.**

Scanners find. NextFix decides.

Every vulnerability scanner hands you a list of hundreds of findings. The real work is
deciding which ones matter: which are reachable from an entry point, which are exposed to an
attacker, and which are being exploited right now. That is the work NextFix does.

Point it at a Node.js, Python or Go application (or its container image) and it builds a
call graph, finds the HTTP routes and their auth guards, traces request data to the
vulnerable call, and gives each finding one of four decisions with a plain-English reason:
Fix now, Fix next cycle, Watch, or Set aside with evidence. The set-asides go into an OpenVEX
document your auditors can check.

On real applications, four out of five findings a scanner reports need no action right now,
and NextFix says why for each one:

- OWASP Juice Shop: 87 findings, 10 need action
- OWASP NodeGoat: 311 findings, 4 need action
- OWASP PyGoat: 141 findings, 20 need action

For leadership there is one page that answers "are we OK, what changed, what is being done,
what do I decide". For engineers, the call path from the route to the vulnerable function,
the upgrade command, and one-click GitHub or Jira tickets. For pipelines, `--fail-on` and
SARIF. For teams, accounts, single sign-on, exceptions with an approver and an expiry, and a
weekly digest.

It runs on your machine or your server. Nothing leaves your network except advisory lookups.
Apache 2.0, everything in one repository, nothing held back.

Windows installer, macOS, Linux and Docker: https://github.com/GRCSAC/nextfix/releases
How it decides: https://github.com/GRCSAC/nextfix/blob/main/docs/DECISION-MODEL.md
Site: https://nextfix.grcsac.com

Built by GRCSAC LLC. If you try it on your own application, tell us what it got wrong; that
is the most useful thing you can send.

---

Suggested image: `docs/site/overview-dark.png` (the evidence funnel). Hashtags, if any:
#ExposureManagement #AppSec #VulnerabilityManagement #OpenSource #SBOM #VEX
