# Security policy

NextFix reads source code, lockfiles and SBOM files on the machine it runs on. It makes
outbound requests only to osv.dev, api.first.org (EPSS), cisa.gov (KEV), github.com and
raw.githubusercontent.com for symbol derivation, and the issue trackers you configure
yourself. It never sends source code anywhere; a created ticket contains the finding's
reasoning, file paths and line numbers. Tracker credentials are stored unencrypted in the
local NextFix database.

When a container image is configured, NextFix runs the `syft` binary found on the PATH (or
named by `NEXTFIX_SYFT`), or, failing that, the pinned `anchore/syft` container through your
Docker CLI with the daemon socket mounted. Either may pull the image from its registry. Image
references are validated before they are passed to a process, and nothing else from the
scanned project is executed.

A scanned project's own `nextfix.config.json` is treated as untrusted input: `image` values
that name a host path (`dir:`, `file:`, archive sources) and `sbom` paths outside the project
folder are ignored with a log line, and guard patterns are length- and shape-checked before
they are compiled. The same values given on your own command line (`--image`, `--sbom`) are
honoured as written.

The local server accepts state-changing requests only as `application/json`, only from its
own origin, and only for host names it was started with (`localhost`, `127.0.0.1`, the
`--host` value and any `--allow-host`), so a web page you visit cannot drive it. Tracker
base URLs are restricted to https and the token must be re-entered whenever the tracker host
changes, so a stored token is never sent anywhere but the host it was entered for.

Accounts: until the first administrator is created the server answers loopback connections
only; after that every API call needs a session cookie (HttpOnly, SameSite=Lax, Secure over
https) or an API token. Passwords are stored as scrypt hashes with a per-user salt, sessions
and API tokens as SHA-256 hashes, and five failed logins lock a username for fifteen minutes.
Single sign-on uses OpenID Connect with PKCE; ID tokens are verified against the provider's
published keys. Every sign-in, settings change, scan, ticket and exception is written to the
audit log without secrets. `--allow-open` turns authentication off for single-user use and is
accepted only on loopback.

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
