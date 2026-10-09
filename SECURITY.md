# Security policy

NextFix reads source code and lockfiles on the machine it runs on. It makes outbound requests
only to osv.dev, api.first.org (EPSS), cisa.gov (KEV) and, for symbol derivation, github.com
and raw.githubusercontent.com. It never sends source code anywhere.

## Reporting a vulnerability

Please do not open a public issue for a security problem in NextFix itself.

Email **nextfix@grcsac.com** with:
- what you found and how to reproduce it,
- the NextFix version (`nextfix --version`) and your platform,
- whether you believe it is being exploited.

You will get an acknowledgement within three working days. Fixes ship as a patch release with
a note in `CHANGELOG.md`; you will be credited unless you ask not to be.

## Scope

In scope: the engine, CLI, local server and dashboards in this repository, including anything
that could make NextFix read files outside the scanned project, execute code from the scanned
project, or leak scan results.

Out of scope: vulnerabilities in the applications NextFix scans (that is what it is for), and
advisory data quality from upstream sources (report those to OSV, FIRST or CISA; open a normal
issue here if NextFix misreads the data).

## Supported versions

The latest minor release receives security fixes.
