// Prints every reachable finding of a report with its traced request-data source.
// Usage: node scripts/summarize-report.mjs out/<name>.json
import { readFileSync } from 'node:fs';

const file = process.argv[2];
const r = JSON.parse(readFileSync(file, 'utf8'));
const s = r.summary;
console.log(`== ${r.target.name ?? r.target.dir}: components ${s.components} | Act ${s.byDecision.Act} Attend ${s.byDecision.Attend} Track* ${s.byDecision['Track*']} Track ${s.byDecision.Track} | reachable ${s.byTier.reachable}`);
for (const f of r.findings.filter((f) => f.reach.tier === 'reachable')) {
  const p = f.reach.paths.find((p) => !p.entry.authenticated && p.userInput) ?? f.reach.paths.find((p) => !p.entry.authenticated) ?? f.reach.paths.find((p) => p.userInput) ?? f.reach.paths[0];
  const bits = [
    f.decision.padEnd(7),
    `${f.component.name}@${f.component.version}`.padEnd(24),
    (f.advisory.cve ?? f.advisory.id).padEnd(16),
    `${p.entry.method} ${p.entry.path.slice(0, 32)}`.padEnd(38),
    p.entry.authenticated ? 'auth  ' : 'noauth',
    `input=${p.userInput}`,
    p.inputSource ? `src=${p.inputSource}` : '',
    p.taintedArgument ? `arg${p.taintedArgument.index + 1}=${p.taintedArgument.text}` : '',
    `(${f.reach.paths.length} paths, ${f.reach.paths.filter((x) => x.userInput).length} with data)`,
  ];
  console.log('  ' + bits.join(' '));
}
