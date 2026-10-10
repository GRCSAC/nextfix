import { execFile } from 'node:child_process';
import { accessSync, constants, existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { delimiter, isAbsolute, join, resolve } from 'node:path';
import type { Component, Ecosystem, ImageInventory } from '../types.ts';
import { osvQueryable } from '../vulns/ecosystems.ts';
import { normalizePyName, purlForPy } from './python.ts';

export interface ContainerOptions {
  /** Image references to inventory with syft (`ghcr.io/org/app:1.2`, `docker:…`, `oci-archive:…`). */
  images?: string[];
  /** SBOM files to read directly: CycloneDX JSON, SPDX JSON, or a Grype report. Relative to the project. */
  sboms?: string[];
  /** Explicit syft binary; otherwise `NEXTFIX_SYFT`, then the PATH. */
  syftPath?: string;
  /** PATH to search (tests); defaults to the process environment. */
  pathEnv?: string;
  /** Kill syft after this long (default 15 minutes). */
  timeoutMs?: number;
  log?: (msg: string) => void;
}

export interface ContainerInventory {
  components: Component[];
  images: ImageInventory[];
}

/** SBOM files NextFix picks up from the project root without being told. */
export const SBOM_FILE_RE = /(\.(cdx|spdx)\.json|^(sbom|bom)\.json)$/i;

export function detectSbomFiles(rootDir: string): string[] {
  try {
    return readdirSync(rootDir)
      .filter((n) => SBOM_FILE_RE.test(n))
      .sort();
  } catch {
    return [];
  }
}

/** Finds an executable on the PATH the way a shell would (PATHEXT on Windows). */
export function findOnPath(name: string, pathEnv = process.env.PATH ?? '', pathExt = process.env.PATHEXT): string | undefined {
  // Windows only runs files with a PATHEXT extension; an extensionless `syft` there is a shell script.
  const win = process.platform === 'win32';
  const pathExts = (pathExt ?? '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  const exts = win ? (pathExts.some((e) => name.toLowerCase().endsWith(e.toLowerCase())) ? [''] : pathExts) : [''];
  for (const dir of pathEnv.split(delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const file = join(dir, name + ext);
      try {
        const st = statSync(file);
        if (!st.isFile()) continue;
        if (process.platform !== 'win32') accessSync(file, constants.X_OK);
        return file;
      } catch {
        // not here
      }
    }
  }
  return undefined;
}

/** The syft container used when no local binary can do the job; pinned so results are reproducible. */
export const SYFT_IMAGE = 'anchore/syft:v1.52.0';

export function findSyft(opts: Pick<ContainerOptions, 'syftPath' | 'pathEnv'> = {}): string | undefined {
  const explicit = opts.syftPath ?? process.env.NEXTFIX_SYFT;
  if (explicit === 'docker') return undefined;
  if (explicit) return existsSync(explicit) ? explicit : findOnPath(explicit, opts.pathEnv);
  return findOnPath('syft', opts.pathEnv);
}

export function findDocker(pathEnv?: string): string | undefined {
  return findOnPath('docker', pathEnv);
}

/** Arguments that run syft inside its official container against the local daemon's images. */
export function dockerSyftArgs(ref: string, image = process.env.NEXTFIX_SYFT_IMAGE || SYFT_IMAGE): string[] {
  return ['run', '--rm', '-v', '/var/run/docker.sock:/var/run/docker.sock', image, ref, '-o', 'cyclonedx-json', '-q'];
}

const SAFE_REF = /^[^\s"'`$&|;<>(){}]+$/;

/** Runs syft through Docker (`docker run anchore/syft …`) and returns its CycloneDX JSON. */
export function runSyftInDocker(docker: string, ref: string, opts: { timeoutMs?: number } = {}): Promise<string> {
  if (!SAFE_REF.test(ref)) return Promise.reject(new Error(`Image reference "${ref}" contains characters NextFix will not pass to a shell.`));
  return new Promise((res, rej) => {
    execFile(docker, dockerSyftArgs(ref), { shell: /\.(cmd|bat)$/i.test(docker), maxBuffer: 512 * 1024 * 1024, timeout: opts.timeoutMs ?? 15 * 60_000, windowsHide: true }, (error, stdout, stderr) => {
      if (error) rej(new Error(`syft (in Docker) failed for ${ref}: ${lastLines(`${String(stderr).trim()}\n${error.message}`)}`));
      else res(String(stdout));
    });
  });
}

/** Runs syft on an image reference and returns its CycloneDX JSON. */
export function runSyft(syft: string, ref: string, opts: { timeoutMs?: number } = {}): Promise<string> {
  if (!SAFE_REF.test(ref)) return Promise.reject(new Error(`Image reference "${ref}" contains characters NextFix will not pass to a shell.`));
  // A .cmd/.bat wrapper (how some package managers install tools on Windows) needs a shell; a real binary does not.
  const shell = /\.(cmd|bat)$/i.test(syft);
  const run = (args: string[]) =>
    new Promise<{ ok: boolean; out: string; err: string }>((res) => {
      execFile(syft, args, { shell, maxBuffer: 512 * 1024 * 1024, timeout: opts.timeoutMs ?? 15 * 60_000, windowsHide: true }, (error, stdout, stderr) => {
        const detail = String(stderr).trim() || (error ? `exit code ${(error as { code?: unknown }).code ?? '?'} with no error output (run \`${syft} scan ${ref}\` by hand to see why)` : '');
        res({ ok: !error, out: String(stdout), err: detail });
      });
    });
  return run(['scan', ref, '-o', 'cyclonedx-json', '-q']).then(async (r) => {
    // syft before 0.90 has no `scan` subcommand.
    if (!r.ok && /unknown command|unknown shorthand|invalid argument "scan"/i.test(r.err)) r = await run([ref, '-o', 'cyclonedx-json', '-q']);
    if (!r.ok) throw new Error(`syft failed for ${ref}: ${lastLines(r.err)}`);
    return r.out;
  });
}

function lastLines(text: string, n = 3): string {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(-n)
    .join(' · ');
}

/** Inventories container images (via syft) and SBOM files into components, one entry per image. */
export async function readContainerInventory(rootDir: string, opts: ContainerOptions): Promise<ContainerInventory> {
  const log = opts.log ?? (() => {});
  const components: Component[] = [];
  const images: ImageInventory[] = [];
  const seen = new Map<string, Component>();

  const absorb = (parsed: ParsedSbom, ref: string, source: ImageInventory['source']) => {
    let n = 0;
    let unqueried = 0;
    for (const c of parsed.components) {
      c.image = ref;
      const key = componentKey(c);
      const existing = seen.get(key);
      if (existing) {
        if (c.path && existing.path !== c.path) existing.paths = [...new Set([...(existing.paths ?? [existing.path]), c.path])];
        continue;
      }
      seen.set(key, c);
      components.push(c);
      n++;
      if (!osvQueryable(c.ecosystem)) unqueried++;
    }
    images.push({ ref, source, os: parsed.os, components: n, unqueried });
    log(`Image: ${ref}: ${n} components${parsed.os ? ` (${parsed.os})` : ''}${unqueried ? `, ${unqueried} in ecosystems OSV has no data for` : ''}`);
  };

  for (const file of opts.sboms ?? []) {
    const abs = isAbsolute(file) ? file : resolve(rootDir, file);
    try {
      const parsed = parseSbom(readFileSync(abs, 'utf8'));
      absorb(parsed, file, parsed.format);
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      images.push({ ref: file, source: 'cyclonedx', components: 0, unqueried: 0, error });
      log(`Image: ${file}: ${error}`);
    }
  }

  const refs = opts.images ?? [];
  if (refs.length) {
    const syft = findSyft(opts);
    const docker = findDocker(opts.pathEnv);
    if (!syft && !docker) {
      const error = 'neither syft (https://github.com/anchore/syft#installation) nor Docker is available; the image was not inventoried';
      for (const ref of refs) images.push({ ref, source: 'syft', components: 0, unqueried: 0, error });
      log(`Image: ${error}`);
    } else {
      for (const ref of refs) {
        try {
          let text: string | undefined;
          let firstError: string | undefined;
          if (syft) {
            log(`Image: reading ${ref} with ${syft}`);
            try {
              text = await runSyft(syft, ref, { timeoutMs: opts.timeoutMs });
            } catch (err) {
              firstError = err instanceof Error ? err.message : String(err);
              if (!docker) throw err;
              log(`Image: ${firstError}; retrying through ${SYFT_IMAGE}`);
            }
          }
          if (text === undefined && docker) {
            // No usable local binary: the official syft container reads the daemon's images on every platform.
            if (!syft) log(`Image: reading ${ref} with ${SYFT_IMAGE} through Docker (no local syft)`);
            text = await runSyftInDocker(docker, ref, { timeoutMs: opts.timeoutMs });
          }
          absorb(parseSbom(text ?? ''), ref, 'syft');
        } catch (err) {
          const error = err instanceof Error ? err.message : String(err);
          images.push({ ref, source: 'syft', components: 0, unqueried: 0, error });
          log(`Image: ${error}`);
        }
      }
    }
  }

  components.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return { components, images };
}

export function componentKey(c: Pick<Component, 'ecosystem' | 'name' | 'version'>): string {
  return `${c.ecosystem}|${c.name}|${c.version}`;
}

// ---------------------------------------------------------------------------------------------
// SBOM parsing

export interface ParsedSbom {
  format: 'cyclonedx' | 'spdx' | 'grype';
  os?: string;
  components: Component[];
}

interface CdxComponent {
  type?: string;
  name?: string;
  version?: string;
  purl?: string;
  properties?: { name: string; value: string }[];
}

interface SpdxPackage {
  name?: string;
  versionInfo?: string;
  primaryPackagePurpose?: string;
  externalRefs?: { referenceCategory?: string; referenceType?: string; referenceLocator?: string }[];
}

interface GrypeMatch {
  artifact?: { name?: string; version?: string; type?: string; purl?: string; locations?: { path?: string }[] };
}

/** Parses a CycloneDX JSON, SPDX JSON or Grype JSON document into components. */
export function parseSbom(text: string): ParsedSbom {
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new Error('not valid JSON (NextFix reads CycloneDX JSON, SPDX JSON and Grype JSON)');
  }
  if (doc.bomFormat === 'CycloneDX') return parseCycloneDx(doc);
  if (typeof doc.spdxVersion === 'string') return parseSpdx(doc);
  if (Array.isArray(doc.matches) && doc.source) return parseGrype(doc);
  throw new Error('not a CycloneDX, SPDX or Grype JSON document');
}

function parseCycloneDx(doc: Record<string, unknown>): ParsedSbom {
  const list = (doc.components as CdxComponent[] | undefined) ?? [];
  const components: Component[] = [];
  let os: string | undefined;
  const distros = new Set<string>();
  for (const c of list) {
    if (c.type === 'operating-system') {
      os = [c.name, c.version].filter(Boolean).join(' ') || os;
      continue;
    }
    const props = new Map((c.properties ?? []).map((p) => [p.name, p.value]));
    const type = props.get('syft:package:type') ?? c.type;
    const location = props.get('syft:location:0:path');
    const mapped = mapPackage({ purl: c.purl, name: c.name, version: c.version, type, location });
    if (!mapped) continue;
    if (mapped.distro) distros.add(mapped.distro);
    components.push(mapped.component);
  }
  return { format: 'cyclonedx', os: os ?? osFromDistros(distros), components };
}

function parseSpdx(doc: Record<string, unknown>): ParsedSbom {
  const list = (doc.packages as SpdxPackage[] | undefined) ?? [];
  const components: Component[] = [];
  let os: string | undefined;
  const distros = new Set<string>();
  for (const p of list) {
    if (p.primaryPackagePurpose === 'OPERATING-SYSTEM') {
      os = [p.name, p.versionInfo].filter(Boolean).join(' ') || os;
      continue;
    }
    const purl = p.externalRefs?.find((r) => r.referenceType === 'purl')?.referenceLocator;
    const mapped = mapPackage({ purl, name: p.name, version: p.versionInfo });
    if (!mapped) continue;
    if (mapped.distro) distros.add(mapped.distro);
    components.push(mapped.component);
  }
  return { format: 'spdx', os: os ?? osFromDistros(distros), components };
}

function parseGrype(doc: Record<string, unknown>): ParsedSbom {
  const matches = doc.matches as GrypeMatch[];
  const distro = doc.distro as { name?: string; version?: string } | undefined;
  const components: Component[] = [];
  const seen = new Set<string>();
  for (const m of matches) {
    const a = m.artifact;
    if (!a) continue;
    const mapped = mapPackage({ purl: a.purl, name: a.name, version: a.version, type: a.type, location: a.locations?.[0]?.path });
    if (!mapped) continue;
    const key = componentKey(mapped.component);
    if (seen.has(key)) continue;
    seen.add(key);
    components.push(mapped.component);
  }
  const os = distro?.name ? [distro.name, distro.version].filter(Boolean).join(' ') : undefined;
  return { format: 'grype', os, components };
}

function osFromDistros(distros: Set<string>): string | undefined {
  const first = [...distros][0];
  return first ? first.replace('-', ' ') : undefined;
}

// ---------------------------------------------------------------------------------------------
// Package URL → component

interface Purl {
  type: string;
  namespace: string;
  name: string;
  version?: string;
  qualifiers: Record<string, string>;
}

export function parsePurl(purl: string): Purl | undefined {
  const m = /^pkg:([^/]+)\/(.+)$/.exec(purl.trim());
  if (!m) return undefined;
  let rest = m[2]!;
  const hash = rest.indexOf('#');
  if (hash >= 0) rest = rest.slice(0, hash);
  const qualifiers: Record<string, string> = {};
  const q = rest.indexOf('?');
  if (q >= 0) {
    for (const kv of rest.slice(q + 1).split('&')) {
      const eq = kv.indexOf('=');
      if (eq <= 0) continue;
      qualifiers[safeDecode(kv.slice(0, eq)).toLowerCase()] = safeDecode(kv.slice(eq + 1));
    }
    rest = rest.slice(0, q);
  }
  let version: string | undefined;
  const at = rest.lastIndexOf('@');
  if (at > 0) {
    version = safeDecode(rest.slice(at + 1));
    rest = rest.slice(0, at);
  }
  const parts = rest.split('/').map(safeDecode);
  const name = parts.pop() ?? '';
  return { type: m[1]!.toLowerCase(), namespace: parts.join('/'), name, version, qualifiers };
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

interface RawPackage {
  purl?: string;
  name?: string;
  version?: string;
  type?: string;
  location?: string;
}

/** Maps one SBOM package to a component in the OSV ecosystem that answers for it. */
export function mapPackage(raw: RawPackage): { component: Component; distro?: string } | undefined {
  const p = raw.purl ? parsePurl(raw.purl) : undefined;
  const version = p?.version ?? raw.version;
  const rawName = p?.name ?? raw.name;
  if (!rawName || !version) return undefined;
  const type = p?.type ?? raw.type ?? 'generic';
  const q = p?.qualifiers ?? {};
  const distro = q.distro;
  let ecosystem: Ecosystem = 'generic';
  let name = rawName;
  let purl = raw.purl ?? `pkg:generic/${encodeURIComponent(rawName)}@${encodeURIComponent(version)}`;
  let path = raw.location ?? rawName;
  let ver = version;

  switch (type) {
    case 'npm':
      name = p?.namespace ? `${p.namespace}/${p.name}` : rawName;
      ecosystem = 'npm';
      purl = `pkg:npm/${name.startsWith('@') ? '%40' + name.slice(1) : name}@${version}`;
      break;
    case 'pypi':
    case 'python':
      name = normalizePyName(rawName);
      ecosystem = 'PyPI';
      purl = purlForPy(name, version);
      break;
    case 'golang':
    case 'go-module':
      name = p?.namespace ? `${p.namespace}/${p.name}` : rawName;
      ecosystem = 'Go';
      ver = version.startsWith('v') || name === 'stdlib' ? version : `v${version}`;
      purl = `pkg:golang/${name}@${ver}`;
      break;
    case 'maven':
      name = p?.namespace ? `${p.namespace}:${p.name}` : rawName;
      ecosystem = 'Maven';
      break;
    case 'gem':
      ecosystem = 'RubyGems';
      break;
    case 'cargo':
      ecosystem = 'crates.io';
      break;
    case 'nuget':
      ecosystem = 'NuGet';
      break;
    case 'composer':
      name = p?.namespace ? `${p.namespace}/${p.name}` : rawName;
      ecosystem = 'Packagist';
      break;
    case 'hex':
      ecosystem = 'Hex';
      break;
    case 'pub':
      ecosystem = 'Pub';
      break;
    case 'deb': {
      // OSV keys Debian and Ubuntu advisories by source package; syft names the binary package.
      name = sourceName(q.upstream) ?? rawName;
      path = rawName;
      const [id, rel] = splitDistro(distro, p?.namespace);
      if (id === 'ubuntu') ecosystem = rel ? (`Ubuntu:${rel}${isUbuntuLts(rel) ? ':LTS' : ''}` as Ecosystem) : 'Ubuntu';
      else ecosystem = rel ? (`Debian:${rel.split('.')[0]}` as Ecosystem) : 'Debian';
      break;
    }
    case 'apk': {
      name = sourceName(q.upstream) ?? rawName;
      path = rawName;
      const [id, rel] = splitDistro(distro, p?.namespace);
      if (id === 'wolfi') ecosystem = 'Wolfi';
      else if (id === 'chainguard') ecosystem = 'Chainguard';
      else if (rel) {
        const [maj, min] = rel.split('.');
        ecosystem = `Alpine:v${maj}.${min ?? '0'}` as Ecosystem;
      } else ecosystem = 'Alpine';
      break;
    }
    case 'rpm': {
      name = sourceName(q.upstream?.replace(/-[^-]+-[^-]+\.src\.rpm$/, '')) ?? rawName;
      path = rawName;
      if (q.epoch && !version.includes(':')) ver = `${q.epoch}:${version}`;
      const [id, rel] = splitDistro(distro, p?.namespace);
      if (id === 'rhel' || id === 'redhat') ecosystem = 'Red Hat';
      else if (id === 'almalinux') ecosystem = rel ? (`AlmaLinux:${rel.split('.')[0]}` as Ecosystem) : 'generic';
      else if (id === 'rocky' || id === 'rockylinux') ecosystem = rel ? (`Rocky Linux:${rel.split('.')[0]}` as Ecosystem) : 'generic';
      else ecosystem = 'generic';
      break;
    }
    default:
      ecosystem = 'generic';
  }

  return {
    component: { ecosystem, name, version: ver, purl, dev: false, optional: false, direct: false, path, origin: 'image', packageType: type },
    distro,
  };
}

function sourceName(upstream: string | undefined): string | undefined {
  if (!upstream) return undefined;
  const n = upstream.split('@')[0]?.trim();
  return n || undefined;
}

/** `debian-12` → ['debian', '12']; falls back to the purl namespace for the id. */
function splitDistro(distro: string | undefined, namespace: string | undefined): [string | undefined, string | undefined] {
  if (distro) {
    const m = /^([a-z][a-z0-9_]*)[-_]?(.*)$/i.exec(distro);
    if (m) return [m[1]!.toLowerCase(), m[2] || undefined];
  }
  return [namespace?.toLowerCase() || undefined, undefined];
}

function isUbuntuLts(rel: string): boolean {
  const m = /^(\d+)\.(\d+)$/.exec(rel);
  return !!m && parseInt(m[1]!, 10) % 2 === 0 && m[2] === '04';
}
