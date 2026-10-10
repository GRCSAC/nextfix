import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import sea from 'node:sea';

/**
 * Files NextFix needs at run time besides its own code: the root package.json (the version),
 * the curated vulnerable-symbol database, the three tree-sitter WebAssembly modules and the
 * built dashboard (`web/index.html`, `web/assets/...`).
 *
 * They are found in one of three places, checked in this order:
 *   1. the single executable's embedded assets (`node:sea`), when running as one;
 *   2. an `assets/` folder next to the program, which is how the esbuild bundle ships
 *      (`packaging/build-sea.mjs` writes it; the Docker image runs from it);
 *   3. the repository, when running from source.
 * `packaging/build-sea.mjs` is the one list of what gets embedded; keep it in step with
 * `sourcePath()` below.
 */

/** True when this process is a Node single-executable application. */
export function isSea(): boolean {
  return sea.isSea();
}

let diskDir: string | undefined | null = null;

/** The folder holding assets on disk (bundle layout), or undefined when running from source or as an executable. */
function bundleAssetDir(): string | undefined {
  if (diskDir !== null) return diskDir;
  diskDir = undefined;
  if (isSea()) return undefined;
  const fromEnv = process.env.NEXTFIX_ASSET_DIR;
  if (fromEnv) diskDir = fromEnv;
  else if (import.meta.url) {
    const beside = join(dirname(fileURLToPath(import.meta.url)), 'assets');
    if (existsSync(join(beside, 'package.json'))) diskDir = beside;
  }
  return diskDir;
}

/** Where an asset lives in the source tree. */
function sourcePath(name: string): string {
  if (!import.meta.url) throw new Error(`NextFix cannot find its asset "${name}": no assets/ folder next to the program and NEXTFIX_ASSET_DIR is not set`);
  const here = dirname(fileURLToPath(import.meta.url));
  if (name === 'package.json') return join(here, '..', '..', '..', 'package.json');
  if (name === 'vulnerable-symbols.json') return join(here, '..', 'data', 'vulnerable-symbols.json');
  if (name === 'web' || name.startsWith('web/')) return join(here, '..', '..', 'web', 'dist', ...name.slice(4).split('/'));
  const require = createRequire(import.meta.url);
  if (name === 'tree-sitter.wasm') return require.resolve('web-tree-sitter/web-tree-sitter.wasm');
  if (name === 'tree-sitter-python.wasm') return require.resolve('tree-sitter-python/tree-sitter-python.wasm');
  if (name === 'tree-sitter-go.wasm') return require.resolve('tree-sitter-go/tree-sitter-go.wasm');
  throw new Error(`unknown asset "${name}"`);
}

/**
 * The on-disk path of an asset (or of the `web` folder). Only valid when assets are on disk;
 * inside the executable there is no path, so callers that can run there use `readAsset()`.
 */
export function assetPath(name: string): string {
  if (isSea()) throw new Error(`asset "${name}" is embedded in the executable and has no path`);
  const dir = bundleAssetDir();
  return dir ? join(dir, ...name.split('/')) : sourcePath(name);
}

/** Whether an asset exists. */
export function hasAsset(name: string): boolean {
  if (isSea()) return seaKeys().has(name);
  try {
    return existsSync(assetPath(name));
  } catch {
    return false;
  }
}

/** The bytes of an asset, from the executable or from disk. */
export function readAsset(name: string): Buffer {
  if (isSea()) {
    if (!seaKeys().has(name)) throw new Error(`asset "${name}" is not embedded in this executable`);
    return Buffer.from(sea.getAsset(name));
  }
  return readFileSync(assetPath(name));
}

let keys: Set<string> | undefined;
function seaKeys(): Set<string> {
  return (keys ??= new Set(sea.getAssetKeys()));
}
