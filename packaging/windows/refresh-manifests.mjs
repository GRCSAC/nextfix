// Fills the winget and Chocolatey manifests from the staged, signed Windows installer.
//
//   node packaging/windows/refresh-manifests.mjs            # write the manifests
//   node packaging/windows/refresh-manifests.mjs --check    # verify they match the staged installer
//
// Both channels pin a SHA256 against an immutable per-version URL, and nothing in the build
// reads those files, so a stale digest fails the install for everyone, publicly, on someone
// else's infrastructure. The values are therefore copied from one source rather than retyped:
// the version from the root package.json, the hash from dist-bin/NextFix-Setup-<version>.exe
// (after signing; release.ps1 orders this), the product code from the AppId pinned in
// nextfix.iss, and the download URL from the GitHub release layout.
//
// Templates live in manifests/templates/ with __VERSION__, __URL__, __SHA256__, __DATE__,
// __YEAR__ and __PRODUCT_CODE__ placeholders. Output:
//   manifests/winget/g/GRCSAC/NextFix/<version>/*.yaml   the folder to submit to winget-pkgs
//   manifests/chocolatey/                                 the folder `choco pack` runs in
// Submission steps are in docs/INSTALL-WINDOWS.md.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

const here = import.meta.dirname;
const root = join(here, '..', '..');
const check = process.argv.includes('--check');

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const version = String(pkg.version);
if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version)) throw new Error(`package.json version '${version}' is not semver`);

const installer = join(root, 'dist-bin', `NextFix-Setup-${version}.exe`);
if (!existsSync(installer)) {
  console.error(`missing ${relative(root, installer)}: run packaging\\windows\\release.ps1 -Build first`);
  process.exit(1);
}
const sha256 = createHash('sha256').update(readFileSync(installer)).digest('hex').toUpperCase();
const url = `https://github.com/GRCSAC/nextfix/releases/download/v${version}/NextFix-Setup-${version}.exe`;

const iss = readFileSync(join(here, 'nextfix.iss'), 'utf8');
const guid = iss.match(/^#define AppGuid "([0-9A-Fa-f-]{36})"/m)?.[1];
if (!guid) throw new Error('could not read AppGuid from nextfix.iss');
const productCode = `{${guid}}_is1`;

const today = new Date().toISOString().slice(0, 10);
const year = today.slice(0, 4);

const templates = join(here, 'manifests', 'templates');
const wingetOut = join(here, 'manifests', 'winget', 'g', 'GRCSAC', 'NextFix', version);
const chocoOut = join(here, 'manifests', 'chocolatey');

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

function fill(text, date) {
  return text
    .replaceAll('__VERSION__', version)
    .replaceAll('__URL__', url)
    .replaceAll('__SHA256__', sha256)
    .replaceAll('__PRODUCT_CODE__', productCode)
    .replaceAll('__YEAR__', year)
    .replaceAll('__DATE__', date);
}

// Each output file with the text it should contain. The ReleaseDate of an already-written
// manifest is kept on --check so a re-check on a later day does not report drift.
const plan = [];
for (const src of walk(join(templates, 'winget'))) {
  plan.push({ src, dst: join(wingetOut, relative(join(templates, 'winget'), src)) });
}
for (const src of walk(join(templates, 'chocolatey'))) {
  plan.push({ src, dst: join(chocoOut, relative(join(templates, 'chocolatey'), src)) });
}
// Apache-2.0: the licence travels with the package.
plan.push({ src: join(root, 'LICENSE'), dst: join(chocoOut, 'tools', 'LICENSE.txt'), verbatim: true });

let problems = 0;
for (const { src, dst, verbatim } of plan) {
  const raw = readFileSync(src, 'utf8');
  const rel = relative(root, dst).replaceAll('\\', '/');
  if (check) {
    if (!existsSync(dst)) {
      console.log(`  [FAIL] ${rel} missing`);
      problems++;
      continue;
    }
    const current = readFileSync(dst, 'utf8');
    const date = current.match(/^ReleaseDate: (\d{4}-\d{2}-\d{2})$/m)?.[1] ?? today;
    const expected = verbatim ? raw : fill(raw, date);
    if (current !== expected) {
      console.log(`  [FAIL] ${rel} does not match the staged installer (version, URL or SHA256 stale)`);
      problems++;
    } else {
      console.log(`  [PASS] ${rel}`);
    }
    continue;
  }
  mkdirSync(dirname(dst), { recursive: true });
  writeFileSync(dst, verbatim ? raw : fill(raw, today));
  console.log(`  wrote ${rel}`);
}

if (check) {
  if (problems) {
    console.log(`manifests: ${problems} problem(s); run node packaging/windows/refresh-manifests.mjs`);
    process.exit(1);
  }
  console.log(`manifests describe v${version} with SHA256 ${sha256}`);
} else {
  console.log(`\nrefreshed to v${version}\n  sha256 ${sha256}\n  url    ${url}\n  winget ${relative(root, wingetOut)}\n  choco  ${relative(root, chocoOut)}`);
}
