# NextFix — repo conventions

- **What it is:** reachability- and exposure-aware vulnerability prioritization for SMBs.
  "Scanners find. NextFix decides." Read `README.md` then `docs/DECISION-MODEL.md`.
- **Runtime:** Node 24+, TypeScript run directly via type stripping. Only erasable syntax:
  no `enum`, no `namespace`, no parameter properties. Imports of local files use the `.ts`
  extension. `tsc -p packages/engine/tsconfig.json` must stay clean.
- **Layout:** `packages/engine` (analysis + CLI), `packages/server` (SQLite history, JSON API,
  serves the built UI), `packages/web` (Vite + React dashboards), `samples/express-shop`
  (demo target, versions pinned on purpose, lockfile committed), `docs/`.
- **Version:** single source is the root `package.json`; `toolVersion()` stamps every report
  and VEX document. Bump with `node scripts/set-version.mjs X.Y.Z` (syncs the workspaces),
  add a `CHANGELOG.md` entry, tag `vX.Y.Z` on release.
- **Commits:** plain messages, no attribution or co-author trailers of any kind.
- **Every build:** update `README.md` feature status + parking lot and `CHANGELOG.md`
  before committing.
- **Verify:** `npm test` (no network) and `npm run scan:sample` (network, or `--offline`).
- **Decision rules** live in `src/decide/ssvc.ts` and are documented in
  `docs/DECISION-MODEL.md`; change both together. Every rule must be explainable in one
  "why" sentence.
- **Data hygiene:** vulnerable-symbol entries in `packages/engine/data/vulnerable-symbols.json`
  need a source and a reference. Never invent symbols; `imported-unknown-symbol` is the
  honest fallback.
- **UX (when the UI lands):** simple, clean, professional, end-user first, mobile-symmetric;
  GRCSAC house fonts (system stacks, no webfonts); WCAG AA.
