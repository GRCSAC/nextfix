# NextFix in CI

`nextfix.yml` in this folder is a GitHub Actions workflow you can copy into
`.github/workflows/` of any repository NextFix can scan (a Node project with
`package-lock.json`, `yarn.lock` or `pnpm-lock.yaml`, a Python project with pinned
requirements or a lockfile, or both). It does four things on every push to `main`, every
pull request and once a week:

1. **Scans** with `nextfix scan . --json nextfix.json --sarif nextfix.sarif --fail-on Act`.
   The job fails when anything is decided **Act** ("fix now"). Change the gate to
   `--fail-on Attend` to also fail on "fix next cycle", or drop `--fail-on` to report only.
2. **Uploads the SARIF** to GitHub code scanning (`github/codeql-action/upload-sarif@v3`,
   category `nextfix`), so findings appear under *Security → Code scanning* and as
   annotations on pull requests. The upload runs even when the gate fails.
3. **Keeps the JSON report** (and the SARIF) as a workflow artifact for 90 days.
4. **Comments on the pull request** with the verdict, the four decision counts, the
   shortest path to green and the top three upgrades, linking to the code scanning tab and
   the run. The comment is updated in place on later pushes; it carries a hidden
   `<!-- nextfix-pr-comment -->` marker so the script finds its own comment.

## Installing NextFix in the job

While the repository is private the workflow clones a pinned tag and runs the CLI from the
clone:

```yaml
- name: Install NextFix
  run: |
    git clone --quiet --depth 1 --branch "$NEXTFIX_VERSION" \
      "https://x-access-token:${NEXTFIX_TOKEN}@github.com/GRCSAC/nextfix.git" "$RUNNER_TEMP/nextfix"
    npm ci --prefix "$RUNNER_TEMP/nextfix" --omit=dev --ignore-scripts --no-audit --no-fund
    echo "NEXTFIX=$RUNNER_TEMP/nextfix" >> "$GITHUB_ENV"
  env:
    NEXTFIX_TOKEN: ${{ secrets.NEXTFIX_TOKEN }}
```

`NEXTFIX_TOKEN` is a fine-grained personal access token with *Contents: read* on
`GRCSAC/nextfix`, stored as a repository or organisation secret. Once the repository is
public, remove `x-access-token:${NEXTFIX_TOKEN}@` from the URL and the secret. Once the npm
package is published, the commented variant in the workflow replaces the clone:

```yaml
- name: Install NextFix
  run: npm install --global "nextfix@${NEXTFIX_VERSION#v}"
```

and the scan step becomes `nextfix scan …`; the comment step then runs the script from the
installed package: `node "$(npm root -g)/nextfix/scripts/pr-comment.mjs" nextfix.json`.

Pin `NEXTFIX_VERSION` to a release tag and bump it deliberately; decisions should not change
under a pull request because the tool moved.

## Permissions

The workflow asks for the least `GITHUB_TOKEN` can do the job with:

| Permission | Why |
|---|---|
| `contents: read` | `actions/checkout` |
| `security-events: write` | `upload-sarif` writes code scanning alerts |
| `pull-requests: write` | the PR comment (`POST`/`PATCH /repos/{owner}/{repo}/issues/…/comments`) |

Pull requests from forks get a read-only `GITHUB_TOKEN`; the scan and the SARIF upload still
run, the comment step fails and is the only thing that does. If that noise matters, add
`&& github.event.pull_request.head.repo.full_name == github.repository` to the comment
step's `if`.

`GITHUB_TOKEN` is also passed to the scan itself. It is optional: NextFix uses it only to
raise GitHub's API rate limit when it derives vulnerable functions from fix commits
(`--no-derive` turns that off).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; nothing at or above `--fail-on` |
| 1 | Error (no lockfile, advisory feed unreachable without `--offline`, …) |
| 2 | Usage error (bad flag, unknown decision in `--fail-on`) |
| 3 | At least one finding decided `--fail-on` or worse; the reports were still written |

The SARIF, artifact and comment steps use `if: always() && hashFiles(...) != ''`, so a gate
failure (3) still uploads everything and an error (1), which writes no files, skips them.

## What lands in code scanning

The SARIF has one run (tool `NextFix`), one **rule per advisory** (id = the advisory id,
name = its CVE, short description = the advisory summary, full description = NextFix's first
"why" line, help URI = the first reference, `security-severity` = the CVSS score) and one
**result per finding**. Levels follow the decision:

| Decision | SARIF level | GitHub |
|---|---|---|
| Act | `error` | alert, PR annotation |
| Attend | `warning` | alert, PR annotation |
| Track* | `note` | alert |
| Track | `none` | recorded, not raised as an alert |

Every result points at the file that pins the component (`package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`, a requirements file, or the `Dockerfile` for image-only components) and,
for reachable findings, carries the entry point and the vulnerable call as related
locations. Result properties hold the decision, score, tier, confidence, fixed version and
the fix command; `partialFingerprints["nextfix/finding"]` is NextFix's stable finding id, so
alerts survive line shifts in the lockfile.

Code scanning rejects a SARIF with more than 25,000 results or rules per run, or larger
than 10 MB gzipped; a NextFix run is far below both.

## Running the same command locally

```bash
node packages/engine/src/cli.ts scan . --json nextfix.json --sarif nextfix.sarif --fail-on Act
echo "exit $?"
```

Add `--offline` to reuse the advisory cache in `~/.nextfix/cache.sqlite` without network.
To preview the pull-request comment without posting it:

```bash
node scripts/pr-comment.mjs nextfix.json --dry-run
```

Open `nextfix.sarif` in the VS Code *SARIF Viewer* extension, or upload it by hand with
`gh api` if you want to see it in code scanning before wiring the workflow:

```bash
gzip -c nextfix.sarif | base64 -w0 > sarif.b64
gh api repos/OWNER/REPO/code-scanning/sarifs -f commit_sha="$(git rev-parse HEAD)" \
  -f ref="refs/heads/$(git branch --show-current)" -f sarif=@sarif.b64 -f tool_name=NextFix
```
