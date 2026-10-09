# NextFix decision model

This is the contract between the engine and the person reading the result. Every rule here
is quoted back in a finding's "why" lines; if a rule is not explainable in one sentence it
does not belong in this file.

## 1. Inputs per finding

| Input | Source | Used for |
|---|---|---|
| Component (name, version, dev, direct) | lockfile | tiers `dev-only`, fix text |
| Advisory (CVSS v3 vector → score, fixed version) | OSV | severity, fix |
| Vulnerable symbols for (advisory, package) | `data/vulnerable-symbols.json` | tiers 2–4 |
| Imports, functions, calls | TypeScript parser over the project | call graph |
| Entry points (method, path, guards) | Express route registrations, mounts, `app.use(guard)` | reachability, authentication |
| Request-data hint | arguments mention `req.*`, or a local assigned from `req.*`; propagated along the path | "user input" |
| Network exposure | Dockerfile `EXPOSE`, compose `ports:`, `app.listen` host | exposure |
| EPSS score, KEV membership | FIRST, CISA | exploitation |

## 2. Reachability tiers (evaluated in order)

1. `dev-only` — component is a devDependency.
2. `unused` — no source file imports the package.
3. `imported-unknown-symbol` — imported, but there is no function-level data for this advisory.
   NextFix refuses to guess; it says so.
4. `imported-not-called` — imported, and none of the advisory's symbols are called anywhere.
5. `called-unreached` — a symbol is called, but no entry-point handler reaches that function
   through the local call graph.
6. `reachable` — at least one entry point reaches a call. The first path found per entry point
   is recorded; an unauthenticated path is preferred for the decision.

**Confidence** travels with the tier: `confirmed` (curated symbols), `derived` (from the fix
commit, automated), `package-level` (tiers 1–3).

### How derived symbols are built

1. Candidate fix links from the advisory references: GitHub commit, pull request or compare
   URLs, ranked `FIX`-typed first, then those whose repository name matches the package,
   then commits before PRs. At most three are tried; the first that yields symbols wins.
2. The unified diff is fetched; tests, docs, fixtures, build output and non-source files are
   dropped; at most 12 files are considered.
3. Each touched file is fetched at the post-fix ref and parsed. For every added or deleted
   line, the chain of enclosing functions (innermost first) is walked until one resolves to
   the file's public surface.
4. Public surface of a file: `module.exports = …`, `exports.x = …`, `export …`, and any
   `obj.name = fn` assignment (which is how lodash and Express expose their APIs). A changed
   function that is public contributes itself and its immediate public callers; a changed
   internal function contributes public callers up to three hops away, where passing a
   function as an argument counts as a call.
5. If nothing resolves but the file's default export is itself a function, the symbol is
   `default` (the package is one callable).
6. Failures are remembered for seven days so scans do not retry every time; `nextfix symbols
   forget` clears one.

Curated entries always outrank derived ones for the same advisory. `nextfix symbols confirm`
promotes a derived entry after a human looks at the commit; `export` turns confirmed entries
into curated JSON for the repository.

## 3. Exploitation

- `active` — CVE is in CISA KEV.
- `likely` — EPSS ≥ 0.10 (10% probability of exploitation in 30 days).
- `none` — otherwise.

## 4. Decision

Modelled on CISA's SSVC deployer tree, with reachability standing in for "automatable" and
exposure standing in for "mission & well-being".

| Tier | Rule | Decision |
|---|---|---|
| dev-only, unused, imported-not-called | vulnerable code not in execute path | **Track** |
| imported-unknown-symbol | exploitation ≠ none **or** CVSS ≥ 7 → Attend, else | **Track\*** |
| called-unreached | exploitation = active → Attend, else | **Track\*** |
| reachable, unauthenticated | exploitation ≠ none **or** CVSS ≥ 9 **or** (user input **and** CVSS ≥ 7) → **Act**, else | **Attend** |
| reachable, authenticated | exploitation = active → **Act**, else | **Attend** |

Meanings follow SSVC: **Act** = fix now, out of cycle; **Attend** = fix in the next cycle,
tell the owner; **Track\*** = watch closely, re-check on new exploit data; **Track** = no
action, re-evaluate on change.

## 5. Score (0–100, ordering only)

```
base      = CVSS × 10 (5.0 × 10 if unknown)
reach     = reachable 1.0 · called-unreached 0.55 · imported-unknown-symbol 0.6
            · imported-not-called 0.2 · unused 0.1 · dev-only 0.05
auth      = reachable & authenticated → × 0.75
local     = network local-only → × 0.5
score     = base × reach × auth × local + EPSS × 20 + (KEV ? 15 : 0) + (user input ? 5 : 0)
```

The score never changes a decision; it orders findings within a decision.

## 6. OpenVEX mapping

| Tier | status | justification / note |
|---|---|---|
| dev-only | `not_affected` | `component_not_present` |
| unused | `not_affected` | `vulnerable_code_not_in_execute_path` |
| imported-not-called | `not_affected` | `vulnerable_code_not_in_execute_path` (confidence stated) |
| called-unreached | `under_investigation` | call sites listed; confirm dead code before closing |
| imported-unknown-symbol | `affected` | no function data; `action_statement` = fix |
| reachable | `affected` | path in `status_notes`; `action_statement` = fix |

## 7. Known limits of the spike (say them out loud)

- Entry points: Express only (`app`/`router` `.get/.post/…/.use`, `app.route(path)` chains,
  `express.Router()` mounts, `app.use(guard)` ordering). Guards are recognised by **name**
  (`isLoggedIn`, `requireAuth`, `passport.authenticate`, `isAuthorized`, `verifyToken`, …)
  after a non-guard list (`session()`, `passport.initialize()`, `helmet`, rate limiters, …)
  is excluded, not by behaviour. Add project names via `nextfix.config.json`.
- Handlers: inline functions, local functions, `controller.method`, `instance.method` of an
  imported class, factory calls (`login()`) and one level of wrapper (`asyncHandler(fn())`).
  Anything else is kept as an entry point with `unresolvedHandlers`, so the route still counts
  but no path can be traced through it.
- Call graph: intra-file by name, cross-file by export name or by any function of that name
  in the target module, `this.method()`, and containment (a function reaches the callbacks and
  closures defined inside it). No dynamic dispatch, no class hierarchies, no prototype chains.
- Taint: any `req.*` in a call's arguments, or in a local assigned from one, propagated along
  the found path. It is a hint: on Juice Shop it flags the challenge-notification chain because
  `req` enters the handler, not because request data reaches the sanitizer.
- Bundlers and tree-shaking are ignored: "present" means "in the lockfile".
- Derived symbols are resolved within the file the fix touched. Packages that assemble their
  public API elsewhere (many ESM libraries) can yield internal names; those entries are
  still useful for call matching only when the user code imports that internal path.
- Advisories without a GitHub fix link in OSV stay `imported-unknown-symbol`.
