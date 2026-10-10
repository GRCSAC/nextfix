// Prints the CHANGELOG.md section for one version, for the GitHub release body.
//   node packaging/release-notes.mjs 1.0.0 > notes.md
// Exits 1 when CHANGELOG.md has no "## [1.0.0]" heading: a release without notes is a mistake.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const version = (process.argv[2] ?? '').replace(/^v/, '');
if (!version) {
  console.error('usage: node packaging/release-notes.mjs <version>');
  process.exit(2);
}
const changelog = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'CHANGELOG.md'), 'utf8');
const lines = changelog.split(/\r?\n/);
const start = lines.findIndex((l) => /^## \[/.test(l) && l.includes(`[${version}]`));
if (start === -1) {
  console.error(`CHANGELOG.md has no "## [${version}]" section`);
  process.exit(1);
}
let end = lines.findIndex((l, i) => i > start && /^## /.test(l));
if (end === -1) end = lines.length;
const body = lines.slice(start + 1, end).join('\n').trim();
if (!body) {
  console.error(`the "## [${version}]" section of CHANGELOG.md is empty`);
  process.exit(1);
}
process.stdout.write(body + '\n');
