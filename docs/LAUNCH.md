# Launch checklist (going public)

The repository opens on the owner's word after 1.0. Each line names who does it.

## Before the flip

- [x] 1.0 released 2026-10-10: executables for Windows, macOS and Linux, the Docker image on GHCR
      signed with cosign, the Windows installer Authenticode-signed (owner's machine), CI
      green on Ubuntu and Windows.
- [x] `node packages/engine/src/cli.ts scan . --fail-on Act` passes on the repository itself
      (the release workflow runs it; a failure blocks the release).
- [x] History reviewed once more (rewritten 2026-10-10): no attribution trailers, no internal paths, no secrets
      (`git log --format=%B | grep -iE "co-authored|generated"` is empty; `out/` and editor
      folders are ignored; the scrub grep in docs/CONVENTIONS.md returns nothing).
- [x] README version line matches the tag (`scripts/set-version.mjs` keeps it so).
- [x] SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue and pull-request templates
      present (they are).
- [x] Dependabot enabled for npm and GitHub Actions (`.github/dependabot.yml`), CODEOWNERS
      naming the owner, branch protection on `main` requiring CI (free on public
      repositories; owner's click).
- [x] Website updated 2026-10-10: NextFix™ at first mention, download links to the release
      assets, the Docker one-liner, package-manager commands, privacy hosts, support address.
      (Separate repository; direct-upload Pages deploy.)
- [x] First-use evidence for the trademark saved the same day (repository, release and
      website captures, outside the repository; see docs/TRADEMARK.md). The launch post is
      added to the folder when it goes out.

## The flip (done 2026-10-10)

1. Visibility public, Discussions on, main protected behind CI, topics and homepage set.
2. Container image public; winget pull request and Chocolatey package in their moderation queues.
3. Remaining: publish the launch post (LinkedIn, the Exposure Management community) with the
   validation table and the evidence funnel screenshot.

## The first week

- Watch issues daily; the templates ask for the NextFix version and the platform.
- Security reports arrive at nextfix@grcsac.com (SECURITY.md); acknowledge within three
  working days.
- Re-run the validation targets on the released executables, not the source tree.
