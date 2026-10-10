# Launch checklist (going public)

The repository opens on the owner's word after 1.0. Each line names who does it.

## Before the flip

- [ ] 1.0 released: executables for Windows, macOS and Linux, the Docker image on GHCR
      signed with cosign, the Windows installer Authenticode-signed (owner's machine), CI
      green on Ubuntu and Windows.
- [ ] `node packages/engine/src/cli.ts scan . --fail-on Act` passes on the repository itself
      (the release workflow runs it; a failure blocks the release).
- [ ] History reviewed once more: no attribution trailers, no internal paths, no secrets
      (`git log --format=%B | grep -iE "co-authored|generated"` is empty; `out/` and editor
      folders are ignored; the scrub grep in docs/CONVENTIONS.md returns nothing).
- [ ] README version line matches the tag (`scripts/set-version.mjs` keeps it so).
- [ ] SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue and pull-request templates
      present (they are).
- [ ] Dependabot enabled for npm and GitHub Actions (`.github/dependabot.yml`), CODEOWNERS
      naming the owner, branch protection on `main` requiring CI (free on public
      repositories; owner's click).
- [ ] Website updated: NextFix™ at first mention, download links to the release assets, the
      Docker one-liner, screenshots of the current Overview and Portfolio, the validation
      table. (Separate repository; direct-upload Pages deploy.)
- [ ] First-use evidence for the trademark saved the same day: the release page, the website
      capture, the launch post (see docs/TRADEMARK.md).

## The flip (owner)

1. GitHub → repository Settings → Danger zone → Change visibility → Public.
2. Enable Discussions; pin the "How it works" and "Validation" issues or discussions.
3. Publish the launch post (LinkedIn, the Exposure Management community) with the
   validation table and the evidence funnel screenshot.

## The first week

- Watch issues daily; the templates ask for the NextFix version and the platform.
- Security reports arrive at nextfix@grcsac.com (SECURITY.md); acknowledge within three
  working days.
- Re-run the validation targets on the released executables, not the source tree.
