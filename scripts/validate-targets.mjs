// Scans the cloned validation targets and prints entry-point and decision counts.
// Targets live in a sibling folder `../nextfix-targets` (or $NEXTFIX_TARGETS), cloned with
// `git clone --depth 1`; see README "Validation on real applications".
// Usage: node scripts/validate-targets.mjs [--offline] [--routes] [name ...]
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const TARGETS_DIR = process.env.NEXTFIX_TARGETS ?? resolve(import.meta.dirname, '..', '..', 'nextfix-targets');
const args = process.argv.slice(2);
const offline = args.includes('--offline');
const names = args.filter((a) => !a.startsWith('--'));
const all = ['juice-shop', 'NodeGoat', 'hackathon-starter', 'demo', 'node-typescript-koa-rest', 'microblog', 'pygoat', 'full-stack-fastapi-template'];

for (const name of names.length ? names : all) {
  const dir = `${TARGETS_DIR}/${name}`;
  if (!existsSync(dir)) {
    console.log(`${name}: not cloned`);
    continue;
  }
  const out = `out/${name}.json`;
  const t0 = Date.now();
  try {
    execFileSync('node', ['packages/engine/src/cli.ts', 'scan', dir, '--json', out, '--why', '0', '--quiet', ...(offline ? ['--offline'] : [])], { stdio: ['ignore', 'ignore', 'pipe'] });
  } catch (e) {
    console.log(`${name}: scan failed: ${String(e.stderr ?? e.message).trim().split('\n').pop()}`);
    continue;
  }
  const r = JSON.parse(readFileSync(out, 'utf8'));
  const s = r.summary;
  const eps = r.entryPoints;
  console.log(`== ${name} (${Math.round((Date.now() - t0) / 1000)}s): entry points ${eps.length}, unauth ${eps.filter((e) => !e.authenticated).length}, unresolved ${eps.filter((e) => e.unresolvedHandlers).length}, unmounted ${eps.filter((e) => !e.mounted).length} | Act ${s.byDecision.Act} Attend ${s.byDecision.Attend} Track* ${s.byDecision['Track*']} Track ${s.byDecision.Track} | reachable ${s.byTier.reachable}`);
  if (args.includes('--routes')) for (const e of eps.slice(0, 40)) console.log(`   ${e.method.padEnd(6)} ${e.path.padEnd(36)} ${e.authenticated ? 'auth [' + e.guards.join(',').slice(0, 50) + ']' : 'noauth'}${e.unresolvedHandlers ? ' ?' + e.unresolvedHandlers.join(',') : ''}${e.mounted ? '' : ' (unmounted)'}`);
}
