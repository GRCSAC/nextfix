// Builds NextFix as one program: an esbuild bundle of packaging/entry.ts with its assets
// beside it (dist-bundle/, what the Docker image runs), then a Node single-executable
// application with the assets embedded (dist-bin/<platform>-<arch>/nextfix[.exe]).
//
//   node packaging/build-sea.mjs                 bundle + executable for this machine
//   node packaging/build-sea.mjs --bundle-only   bundle only (Docker build stage)
//   node packaging/build-sea.mjs --node <file>   use this Node binary as the base (defaults to the running one)
//
// The dashboard must be built first (`npm run build`); this script runs it when dist/ is
// missing. The executable is not signed here: on Windows the installer's signing script
// (packaging/windows) signs it; on macOS it gets an ad-hoc signature so it runs locally.
import { build } from 'esbuild';
import { inject } from 'postject';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const args = process.argv.slice(2);
const bundleOnly = args.includes('--bundle-only');
const nodeBinary = args.includes('--node') ? resolve(args[args.indexOf('--node') + 1]) : process.execPath;
const bundleDir = join(root, 'dist-bundle');
const binDir = join(root, 'dist-bin');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

function run(file, cmdArgs, opts = {}) {
  return execFileSync(file, cmdArgs, { stdio: 'inherit', cwd: root, ...opts });
}

function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

function mb(bytes) {
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** Every file under dir, as repo-relative forward-slash paths. */
function walk(dir, base = dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p, base));
    else out.push(relative(base, p).split(sep).join('/'));
  }
  return out;
}

// 1. The dashboard.
const webDist = join(root, 'packages', 'web', 'dist');
if (!existsSync(join(webDist, 'index.html'))) {
  console.log('· building the dashboard (npm run build)');
  run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'build'], { shell: process.platform === 'win32' });
}

// 2. The bundle. One CommonJS file: the server (which includes the engine) and the engine
//    CLI, TypeScript stripped, every dependency inlined, Node built-ins left as require().
rmSync(bundleDir, { recursive: true, force: true });
mkdirSync(bundleDir, { recursive: true });
const bundleFile = join(bundleDir, 'nextfix.cjs');
await build({
  entryPoints: [join(root, 'packaging', 'entry.ts')],
  outfile: bundleFile,
  bundle: true,
  platform: 'node',
  target: 'node24',
  format: 'cjs',
  // web-tree-sitter's ESM build resolves its wasm through import.meta.url at load time; the CJS build does not.
  alias: { 'web-tree-sitter': join(root, 'node_modules', 'web-tree-sitter', 'web-tree-sitter.cjs') },
  // import.meta.url has no meaning in CommonJS; assets.ts reads it to find assets/ beside the bundle.
  define: { 'import.meta.url': '__nextfix_import_meta_url' },
  banner: { js: "const __nextfix_import_meta_url = require('node:url').pathToFileURL(__filename).href;" },
  logLevel: 'warning',
});

// 3. The assets, beside the bundle. The keys are what packages/engine/src/assets.ts asks for.
const assets = {
  'vulnerable-symbols.json': join(root, 'packages', 'engine', 'data', 'vulnerable-symbols.json'),
  'tree-sitter.wasm': require.resolve('web-tree-sitter/web-tree-sitter.wasm'),
  'tree-sitter-python.wasm': require.resolve('tree-sitter-python/tree-sitter-python.wasm'),
  'tree-sitter-go.wasm': require.resolve('tree-sitter-go/tree-sitter-go.wasm'),
};
for (const rel of walk(webDist)) assets[`web/${rel}`] = join(webDist, rel);
const assetDir = join(bundleDir, 'assets');
for (const [key, src] of Object.entries(assets)) {
  const dest = join(assetDir, ...key.split('/'));
  mkdirSync(dirname(dest), { recursive: true });
  copyFileSync(src, dest);
}
// Only the version is needed from package.json; the executable does not carry the repo's scripts.
writeFileSync(join(assetDir, 'package.json'), JSON.stringify({ name: pkg.name, version: pkg.version }, null, 2) + '\n');
assets['package.json'] = join(assetDir, 'package.json');
console.log(`· bundle ${relative(root, bundleFile)} ${mb(statSync(bundleFile).size)}, ${Object.keys(assets).length} assets`);
if (bundleOnly) process.exit(0);

// 4. The executable.
const target = `${process.platform}-${process.arch}`;
const exeName = process.platform === 'win32' ? 'nextfix.exe' : 'nextfix';
const outDir = join(binDir, target);
const exe = join(outDir, exeName);
mkdirSync(outDir, { recursive: true });
const seaConfig = {
  ...JSON.parse(readFileSync(join(root, 'packaging', 'sea-config.json'), 'utf8')),
  main: bundleFile,
  output: join(binDir, 'sea-prep.blob'),
  assets,
};
writeFileSync(join(binDir, 'sea-config.json'), JSON.stringify(seaConfig, null, 2) + '\n');
run(process.execPath, ['--experimental-sea-config', join(binDir, 'sea-config.json')]);

copyFileSync(nodeBinary, exe);
if (process.platform === 'darwin') run('codesign', ['--remove-signature', exe]);
// Windows: the copied node.exe carries the Node.js project's signature, which stops matching
// once the blob is injected; the installer's signing step replaces it. Nothing to do here.
await inject(exe, 'NODE_SEA_BLOB', readFileSync(seaConfig.output), {
  sentinelFuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
  machoSegmentName: process.platform === 'darwin' ? 'NODE_SEA' : undefined,
});
if (process.platform === 'darwin') run('codesign', ['--sign', '-', exe]);
if (process.platform !== 'win32') chmodSync(exe, 0o755);
rmSync(seaConfig.output, { force: true });

// 5. Prove it runs and record its checksum.
const reported = execFileSync(exe, ['--version'], { encoding: 'utf8' }).trim();
if (reported !== pkg.version) throw new Error(`the executable reports version ${reported}, package.json says ${pkg.version}`);
const sum = sha256(exe);
writeFileSync(`${exe}.sha256`, `${sum}  ${exeName}\n`);
console.log(`· ${relative(root, exe)} ${mb(statSync(exe).size)} (NextFix ${reported}, unsigned)`);
console.log(`  sha256 ${sum}`);
