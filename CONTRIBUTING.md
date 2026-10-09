# Contributing to NextFix

Thanks for considering it. The parts that grow with more hands are exactly the parts worth
contributing to.

## Where help matters most

1. **Vulnerable-symbol data.** Run `nextfix symbols list`, read the fix commit for an entry
   you know, confirm it (`nextfix symbols confirm <advisory> <package>`), export it
   (`nextfix symbols export reviewed.json`) and open a pull request that merges the JSON into
   `packages/engine/data/vulnerable-symbols.json`. Every entry needs a reference.
2. **Framework coverage.** New entry-point shapes (NestJS, Hapi, serverless handlers), guard
   names NextFix misses, or an app where the entry-point count is wrong. A failing fixture
   under `packages/engine/test-fixtures/` with the expected routes is the ideal issue.
3. **Real-world results.** Scanned your own application? What NextFix got wrong is the most
   useful thing you can tell us: an entry point it missed, a guard it misread, a call it
   claimed was reachable but is not.

## Ground rules

- Node 24+. `npm install`, then `npm test` and `npm run typecheck` must pass.
- The engine runs TypeScript directly: erasable syntax only (no `enum`, `namespace` or
  parameter properties), local imports with the `.ts` extension.
- Decision rules live in `packages/engine/src/decide/ssvc.ts` and are documented in
  `docs/DECISION-MODEL.md`; change both together. Every rule must be explainable in one
  "why" sentence that a finding can print.
- Never invent symbol data. `imported-unknown-symbol` is the honest fallback.
- Keep every new behaviour covered by a test, ideally a fixture app.
- Commit messages are plain; no trailers.

## Developer Certificate of Origin

By contributing you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the contribution or have the right to submit it under the Apache License 2.0.
Sign each commit with `git commit -s` (adds `Signed-off-by: Your Name <email>`). No separate
contributor agreement is needed.

## Reporting bugs

Use the issue templates. For anything security-related, see `SECURITY.md` instead.
