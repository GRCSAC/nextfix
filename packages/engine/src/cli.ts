#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { scan } from './scan.ts';
import { renderSummary, renderTable, renderWhy } from './report/table.ts';
import { toOpenVex } from './report/vex.ts';
import { toolVersion } from './version.ts';

const HELP = `NextFix ${toolVersion()} — tells you what to fix next, and why.

Usage:
  nextfix scan <dir> [--json <file>] [--vex <file>] [--offline] [--why N] [--quiet]
  nextfix --version

Options:
  --json <file>   Write the full report as JSON.
  --vex <file>    Write an OpenVEX document (one statement per finding).
  --offline       Use only cached advisory data (~/.nextfix/cache.sqlite).
  --why N         Print the full "why" for the top N actionable findings (default 3).
  --quiet         No progress output.
`;

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'string' },
      vex: { type: 'string' },
      offline: { type: 'boolean', default: false },
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
  const [cmd, dir] = positionals;
  if (values.help || cmd !== 'scan' || !dir) {
    console.log(HELP);
    process.exitCode = cmd && cmd !== 'scan' ? 2 : 0;
    return;
  }

  const log = values.quiet ? undefined : (m: string) => console.error(`· ${m}`);
  const report = await scan(dir, { offline: values.offline, log });

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

function writeOut(file: string, text: string) {
  mkdirSync(dirname(resolve(file)), { recursive: true });
  writeFileSync(file, text + '\n');
}

main().catch((err: unknown) => {
  console.error(`nextfix: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
