#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { scan } from './scan.ts';
import { renderSummary, renderTable, renderWhy } from './report/table.ts';
import { toOpenVex } from './report/vex.ts';
import { toolVersion } from './version.ts';
import { Cache } from './vulns/cache.ts';
import { DerivedStore } from './symbols/store.ts';
import { deriveSymbols } from './symbols/derive.ts';
import { USER_AGENT } from './version.ts';
import type { Advisory } from './types.ts';

const HELP = `NextFix ${toolVersion()} — tells you what to fix next, and why.

Usage:
  nextfix scan <dir> [--json <file>] [--vex <file>] [--offline] [--no-derive] [--why N] [--quiet]
  nextfix symbols derive <advisory-id> <package> [--force]   Derive vulnerable functions from the fix commit
  nextfix symbols list                                        Show derived entries on this machine
  nextfix symbols confirm <advisory-id> <package>             Promote a derived entry after review
  nextfix symbols forget <advisory-id> <package>              Drop a derived entry (and retry next scan)
  nextfix symbols export [<file>]                             Write confirmed entries as curated JSON
  nextfix --version

Options:
  --json <file>   Write the full report as JSON.
  --vex <file>    Write an OpenVEX document (one statement per finding).
  --offline       Use only cached data (~/.nextfix/cache.sqlite).
  --no-derive     Do not fetch fix commits for advisories without function data.
  --why N         Print the full "why" for the top N actionable findings (default 3).
  --quiet         No progress output.

Set GITHUB_TOKEN to raise GitHub's unauthenticated rate limit when deriving symbols.
`;

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'string' },
      vex: { type: 'string' },
      offline: { type: 'boolean', default: false },
      'no-derive': { type: 'boolean', default: false },
      force: { type: 'boolean', default: false },
      why: { type: 'string', default: '3' },
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

  if (cmd === 'symbols') return symbolsCommand(rest, { force: values.force, offline: values.offline, log });

  const dir = rest[0];
  if (values.help || cmd !== 'scan' || !dir) {
    console.log(HELP);
    process.exitCode = cmd && cmd !== 'scan' ? 2 : 0;
    return;
  }

  const report = await scan(dir, { offline: values.offline, derive: !values['no-derive'], log });

  if (values.json) writeOut(values.json, JSON.stringify(report, null, 2));
  if (values.vex) writeOut(values.vex, JSON.stringify(toOpenVex(report), null, 2));

  console.log(renderSummary(report));
  console.log('');
  console.log(renderTable(report));
  const n = parseInt(values.why ?? '3', 10);
  if (n > 0) console.log(renderWhy(report, n));
  if (values.json) console.log(`\nJSON report: ${resolve(values.json)}`);
  if (values.vex) console.log(`OpenVEX:     ${resolve(values.vex)}`);
}

async function symbolsCommand(args: string[], opts: { force: boolean; offline: boolean; log?: (m: string) => void }) {
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
      const out = await deriveSymbols(adv, pkg, { cache, offline: opts.offline, store, force: opts.force, log: opts.log, typedReferences: adv.typedReferences, token: process.env.GITHUB_TOKEN });
      if (out.entry) {
        console.log(`${adv.id} ${pkg} → ${out.entry.symbols.join(', ')}${out.cached ? '  (cached)' : ''}`);
        if (out.entry.evidence) {
          console.log(`  commit:  ${out.entry.evidence.commits.join(', ')}`);
          console.log(`  files:   ${out.entry.evidence.files.join(', ')}`);
          console.log(`  changed: ${out.entry.evidence.changedFunctions.join(', ')}`);
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
