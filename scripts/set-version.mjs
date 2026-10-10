// Syncs every workspace package.json version to the root package.json (the single source).
// Usage: node scripts/set-version.mjs            -> sync only
//        node scripts/set-version.mjs 0.3.0      -> set root, then sync
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');
const rootPkgPath = join(root, 'package.json');
const rootPkg = JSON.parse(readFileSync(rootPkgPath, 'utf8'));
const wanted = process.argv[2];
if (wanted) {
  if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(wanted)) throw new Error(`Not a semver version: ${wanted}`);
  rootPkg.version = wanted;
  writeFileSync(rootPkgPath, JSON.stringify(rootPkg, null, 2) + '\n');
}
const version = rootPkg.version;
let changed = 0;
for (const name of readdirSync(join(root, 'packages'))) {
  const p = join(root, 'packages', name, 'package.json');
  if (!existsSync(p)) continue;
  const pkg = JSON.parse(readFileSync(p, 'utf8'));
  if (pkg.version !== version) {
    pkg.version = version;
    writeFileSync(p, JSON.stringify(pkg, null, 2) + '\n');
    changed++;
  }
}
// The README names the current version in prose; keep it in step.
const readmePath = join(root, 'README.md');
if (existsSync(readmePath)) {
  const readme = readFileSync(readmePath, 'utf8');
  const updated = readme.replace(/\*\*Current version:\*\* `v[^`]+`/, `**Current version:** \`v${version}\``);
  if (updated !== readme) {
    writeFileSync(readmePath, updated);
    changed++;
  }
}
console.log(`version ${version}: ${changed} file(s) updated`);
