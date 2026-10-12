#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { scan } from './scan.ts';
import { renderSummary, renderTable, renderWhy } from './report/table.ts';
import { toOpenVex } from './report/vex.ts';
import { toSarif } from './report/sarif.ts';
import { toolVersion } from './version.ts';
import { Cache } from './vulns/cache.ts';
import { DerivedStore } from './symbols/store.ts';
import { deriveSymbols } from './symbols/derive.ts';
import { USER_AGENT } from './version.ts';
import type { Advisory, Decision } from './types.ts';

const HELP = `NextFix ${toolVersion()} — tells you what to fix next, and why.

Usage:
  nextfix scan <dir> [--image <ref>] [--sbom <file>] [--access-log <file>] [--json <file>] [--vex <file>] [--sarif <file>] [--fail-on D] [--offline] [--no-derive] [--why N] [--quiet]
  nextfix symbols derive <advisory-id> <package> [--pypi] [--force]   Derive vulnerable functions from the fix commit
  nextfix symbols list                                        Show derived entries on this machine
  nextfix symbols confirm <advisory-id> <package>             Promote a derived entry after review
  nextfix symbols forget <advisory-id> <package>              Drop a derived entry (and retry next scan)
  nextfix symbols export [<file>]                             Write confirmed entries as curated JSON
  nextfix --version

Options:
  --image <ref>   Also inventory this container image with syft (repeatable; or "image" in nextfix.config.json).
  --sbom <file>   Also read this CycloneDX / SPDX / Grype JSON (repeatable; *.cdx.json and *.spdx.json at the root are read anyway).
  --access-log <file>  Count requests from this access log or folder of logs (repeatable; or "accessLogs" in
                  nextfix.config.json). nginx/Apache combined, AWS ALB and JSON lines are read; the last 30 days
                  (--traffic-days N) are counted per route, and routes nobody called are said so.
  --json <file>   Write the full report as JSON.
  --vex <file>    Write an OpenVEX document (one statement per finding).
  --sarif <file>  Write SARIF 2.1.0 for GitHub code scanning and other SARIF viewers (one rule per advisory,
                  one result per finding; Act → error, Attend → warning, Track* → note, Track → none).
  --offline       Use only cached data (~/.nextfix/cache.sqlite).
  --no-derive     Do not fetch fix commits for advisories without function data.
  --why N         Print the full "why" for the top N actionable findings (default 3).
  --fail-on D     Exit with code 3 when any finding is decided D or worse (Act, Attend, Track*, Track); for CI gates.
  --quiet         No progress output.

Exit codes: 0 ok · 1 error · 2 usage · 3 findings at or above --fail-on.
In CI: nextfix scan . --json nextfix.json --sarif nextfix.sarif --fail-on Act (see docs/ci/README.md for the GitHub Actions workflow).

Set GITHUB_TOKEN to raise GitHub's unauthenticated rate limit when deriving symbols.
Set NEXTFIX_SYFT to the syft binary when it is not on the PATH.
`;

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'string' },
      vex: { type: 'string' },
      sarif: { type: 'string' },
      image: { type: 'string', multiple: true },
      sbom: { type: 'string', multiple: true },
      'access-log': { type: 'string', multiple: true },
      'traffic-days': { type: 'string' },
      offline: { type: 'boolean', default: false },
      'no-derive': { type: 'boolean', default: false },
      force: { type: 'boolean', default: false },
      pypi: { type: 'boolean', default: false },
      why: { type: 'string', default: '3' },
      'fail-on': { type: 'string' },
      quiet: { type: 'boolean', default: false },
      version: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  if (values.version) {
    console.log(toolVersion());
    return;
  }
  const [cmd, ...rest] = positionals;
  const log = values.quiet ? undefined : (m: string) => console.error(`· ${m}`);

  if (cmd === 'symbols') return symbolsCommand(rest, { force: values.force, offline: values.offline, pypi: values.pypi, log });

  const dir = rest[0];
  if (values.help || cmd !== 'scan' || !dir) {
    console.log(HELP);
    // Asking for help is fine; anything else that lands here is a usage error.
    process.exitCode = values.help ? 0 : 2;
    return;
  }
  const failOn = values['fail-on'] as Decision | undefined;
  if (failOn !== undefined && !DECISION_ORDER.includes(failOn)) {
    console.error(`nextfix: --fail-on must be one of ${DECISION_ORDER.join(', ')}`);
    process.exitCode = 2;
    return;
  }

  const trafficDays = values['traffic-days'] !== undefined ? parseInt(values['traffic-days'], 10) : undefined;
  if (trafficDays !== undefined && !(Number.isInteger(trafficDays) && trafficDays >= 1 && trafficDays <= 365)) {
    console.error('nextfix: --traffic-days must be a whole number of days from 1 to 365');
    process.exitCode = 2;
    return;
  }
  const report = await scan(dir, { offline: values.offline, derive: !values['no-derive'], images: values.image, sboms: values.sbom, accessLogs: values['access-log'], trafficWindowDays: trafficDays, log });

  if (values.json) writeOut(values.json, JSON.stringify(report, null, 2));
  if (values.vex) writeOut(values.vex, JSON.stringify(toOpenVex(report), null, 2));
  if (values.sarif) writeOut(values.sarif, JSON.stringify(toSarif(report), null, 2));

  console.log(renderSummary(report));
  console.log('');
  console.log(renderTable(report));
  const parsedWhy = parseInt(values.why ?? '3', 10);
  const n = Number.isNaN(parsedWhy) ? 3 : parsedWhy;
  if (n > 0) console.log(renderWhy(report, n));
  if (values.json) console.log(`\nJSON report: ${resolve(values.json)}`);
  if (values.vex) console.log(`OpenVEX:     ${resolve(values.vex)}`);
  if (values.sarif) console.log(`SARIF:       ${resolve(values.sarif)}`);
  if (failOn) {
    const threshold = DECISION_ORDER.indexOf(failOn);
    const hits = report.findings.filter((f) => DECISION_ORDER.indexOf(f.decision) <= threshold);
    if (hits.length) {
      console.log(`\n${hits.length} finding(s) decided ${failOn} or worse; failing as requested (--fail-on ${failOn}).`);
      process.exitCode = 3;
    }
  }
}

const DECISION_ORDER: Decision[] = ['Act', 'Attend', 'Track*', 'Track'];

async function symbolsCommand(args: string[], opts: { force: boolean; offline: boolean; pypi: boolean; log?: (m: string) => void }) {
  const [sub, id, pkg] = args;
  const cache = new Cache();
  const store = new DerivedStore(cache);
  try {
    if (sub === 'list') {
      const all = store.all();
      if (!all.length) return console.log('No derived entries yet. Run a scan, or `nextfix symbols derive <advisory> <package>`.');
      for (const e of all) {
        console.log(`${e.confidence === 'confirmed' ? '✔' : '·'} ${e.ids[0]}  ${e.package}  →  ${e.symbols.join(', ')}${e.reviewed ? '  (reviewed)' : ''}`);
        if (e.evidence) console.log(`    from ${e.evidence.commits[0]}  changed: ${e.evidence.changedFunctions.join(', ')}`);
      }
      return;
    }
    if (sub === 'derive' && id && pkg) {
      const adv = await fetchAdvisory(id);
      const out = await deriveSymbols(adv, pkg, { cache, offline: opts.offline, store, force: opts.force, log: opts.log, typedReferences: adv.typedReferences, token: process.env.GITHUB_TOKEN, ecosystem: opts.pypi ? 'PyPI' : 'npm' });
      if (out.entry) {
        console.log(`${adv.id} ${pkg} → ${out.entry.symbols.join(', ')}${out.cached ? '  (cached)' : ''}`);
        if (out.entry.evidence) {
          console.log(`  commit:  ${out.entry.evidence.commits.join(', ')}`);
          console.log(`  files:   ${out.entry.evidence.files.join(', ')}`);
          console.log(`  changed: ${out.entry.evidence.changedFunctions.join(', ')}`);
          if (out.entry.evidence.entry) console.log(`  entry:   ${out.entry.evidence.entry}`);
          console.log(`  via:     ${Object.entries(out.entry.evidence.resolvedVia).map(([s, v]) => `${s}←${v}`).join(', ')}`);
        }
      } else {
        console.log(`${adv.id} ${pkg}: nothing derived — ${out.reason}`);
        process.exitCode = 1;
      }
      return;
    }
    if (sub === 'confirm' && id && pkg) {
      const e = store.get(id, pkg) ?? store.all().find((x) => x.ids.includes(id) && x.package === pkg);
      if (!e) throw new Error(`No derived entry for ${id} ${pkg}`);
      e.confidence = 'confirmed';
      e.reviewed = true;
      store.put(e);
      console.log(`Confirmed ${e.ids[0]} ${pkg} → ${e.symbols.join(', ')}`);
      return;
    }
    if (sub === 'forget' && id && pkg) {
      const e = store.get(id, pkg) ?? store.all().find((x) => x.ids.includes(id) && x.package === pkg);
      if (e) store.remove(e.ids[0]!, pkg);
      store.clearFailed(id, pkg);
      console.log(`Forgot ${id} ${pkg}`);
      return;
    }
    if (sub === 'export') {
      const entries = store.all().filter((e) => e.confidence === 'confirmed').map((e) => ({ ...e, source: 'curated' as const, note: e.note ? `${e.note} (reviewed from derived)` : 'Reviewed from a derived entry.' }));
      const text = JSON.stringify({ $schema: 'nextfix/vulnerable-symbols/v1', entries }, null, 2);
      if (id) {
        writeOut(id, text);
        console.log(`Wrote ${entries.length} confirmed entries to ${resolve(id)}`);
      } else console.log(text);
      return;
    }
    console.log(HELP);
    process.exitCode = 2;
  } finally {
    cache.close();
  }
}

async function fetchAdvisory(id: string): Promise<Advisory> {
  const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { headers: { 'user-agent': USER_AGENT } });
  if (!res.ok) throw new Error(`OSV ${res.status} for ${id}`);
  const v = (await res.json()) as { id: string; aliases?: string[]; summary?: string; details?: string; references?: { type?: string; url: string }[] };
  return {
    id: v.id,
    aliases: v.aliases ?? [],
    cve: [v.id, ...(v.aliases ?? [])].find((a) => a.startsWith('CVE-')),
    summary: v.summary ?? '',
    details: v.details ?? '',
    references: (v.references ?? []).map((r) => r.url),
    typedReferences: v.references ?? [],
  };
}

function writeOut(file: string, text: string) {
  mkdirSync(dirname(resolve(file)), { recursive: true });
  writeFileSync(file, text + '\n');
}

main().catch((err: unknown) => {
  console.error(`nextfix: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
