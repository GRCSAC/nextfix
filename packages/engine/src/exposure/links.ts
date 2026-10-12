import { basename } from 'node:path';
import { parseAllDocuments } from 'yaml';
import type { ServiceIdentity, ServiceLink, ServiceLinks } from '../types.ts';
import { isComposeFile, isConfigFile, isEnvFile, isManifestCandidate, readText, walkProject, type ProjectFile } from './files.ts';

/*
 * Service links: the other services this application talks to, read from what is already in
 * the repository: compose files (depends_on, service names in environment values), Kubernetes
 * manifests (container environment), .env files and configuration files (any URL or *_HOST
 * value). Also the names this application answers to, so another application's link can be
 * matched to it on the portfolio map. Nothing is resolved over the network.
 */

export interface LinkOptions {
  ignore?: string[];
  /** The package or module name, added to the identity. */
  projectName?: string;
  /** Container image references from the config or command line; their last path segment names the service. */
  images?: string[];
  log?: (msg: string) => void;
}

const MAX_LINKS = 60;
const PLACEHOLDER_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]', 'example.com', 'example.org', 'example.net', 'host.docker.internal', 'xxx', 'changeme']);
const INTERNAL_SUFFIX = /\.(local|internal|svc|cluster\.local|localhost|test|lan|home|corp|intranet|private)$/i;
const URL_RE = /\b(?:https?|wss?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?|nats|kafka|grpc|ldaps?|smtps?):\/\/(?:[^@\s"'<>\/]*@)?(\[[0-9a-f:.]+\]|[a-z0-9._-]+)(?::(\d{1,5}))?/gi;
const HOST_KEY_RE = /^(?:[A-Z0-9_]*_)?(?:HOST|HOSTNAME|SERVER|ENDPOINT|ADDR|ADDRESS)$/;

/** Keys whose value names this application itself rather than something it calls. */
const SELF_KEY_RE = /^(?:PUBLIC_URL|BASE_URL|APP_URL|SITE_URL|HOST|HOSTNAME|DOMAIN|SERVER_NAME|VIRTUAL_HOST|APP_HOST|PUBLIC_HOST|CANONICAL_URL|FRONTEND_URL|WEB_URL|ROOT_URL)$/i;

function isIp(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[');
}

/** A host with a public-looking domain is external (a SaaS or a partner); bare names and internal suffixes are services of ours. */
export function isExternalHost(host: string): boolean {
  const h = host.toLowerCase();
  if (isIp(h)) return false;
  if (!h.includes('.')) return false;
  if (INTERNAL_SUFFIX.test(h)) return false;
  return true;
}

function usableHost(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const h = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!h || h.length > 253) return undefined;
  if (PLACEHOLDER_HOSTS.has(h)) return undefined;
  if (h.includes('$') || h.includes('{') || h.includes('%') || h.includes('<')) return undefined;
  if (!/^[a-z0-9[]/.test(h)) return undefined;
  if (isIp(h) && /^(127\.|0\.|169\.254\.)/.test(h)) return undefined;
  return h;
}

interface Collector {
  links: Map<string, ServiceLink>;
  names: Set<string>;
  hosts: Set<string>;
}

function addLink(c: Collector, host: string | undefined, port: number | undefined, kind: string, evidence: string): void {
  const h = usableHost(host);
  if (!h || c.names.has(h) || c.hosts.has(h)) return;
  const validPort = port && port > 0 && port < 65536 ? port : undefined;
  const existing = c.links.get(h);
  if (existing) {
    // The first mention keeps the evidence; a later one may add the port.
    if (existing.port === undefined && validPort !== undefined) existing.port = validPort;
    return;
  }
  if (c.links.size >= MAX_LINKS) return;
  c.links.set(h, { host: h, port: validPort, kind, evidence, external: isExternalHost(h) });
}

function addName(c: Collector, name: string | undefined): void {
  const h = usableHost(name);
  if (h) {
    c.names.add(h);
    c.links.delete(h);
  }
}

function addHost(c: Collector, host: string | undefined): void {
  const h = usableHost(host);
  if (h) {
    c.hosts.add(h);
    c.links.delete(h);
  }
}

/** Every URL in a blob of text, as host + port. */
export function urlsIn(text: string): { host: string; port?: number }[] {
  const out: { host: string; port?: number }[] = [];
  for (const m of text.matchAll(URL_RE)) out.push({ host: m[1]!, port: m[2] ? Number(m[2]) : undefined });
  return out;
}

function scanValue(c: Collector, key: string | undefined, value: unknown, kind: string, where: string): void {
  if (typeof value !== 'string') return;
  const v = value.trim();
  if (!v || v.startsWith('#')) return;
  const k = key ?? '';
  if (SELF_KEY_RE.test(k)) {
    const u = urlsIn(v)[0];
    addHost(c, u ? u.host : v);
    return;
  }
  const urls = urlsIn(v);
  if (urls.length) {
    for (const u of urls.slice(0, 5)) addLink(c, u.host, u.port, kind, `${where}: ${k ? `${k}=` : ''}${v.length > 80 ? v.slice(0, 77) + '…' : v}`);
    return;
  }
  if (k && HOST_KEY_RE.test(k.toUpperCase()) && /^[a-z0-9.-]+(:\d+)?$/i.test(v)) {
    const [host, port] = v.split(':');
    addLink(c, host, port ? Number(port) : undefined, kind, `${where}: ${k}=${v}`);
  }
}

function envLines(text: string): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.*)$/.exec(line);
    if (!m) continue;
    out.push({ key: m[1]!, value: m[2]!.replace(/^(['"])(.*)\1\s*(#.*)?$/, '$2').replace(/\s+#.*$/, '') });
  }
  return out;
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

/** The compose service that is this application: it builds from the project, or its image matches a known image. */
function selfComposeService(services: Record<string, unknown>, imageNames: Set<string>): string | undefined {
  for (const [name, def] of Object.entries(services)) {
    const d = asRecord(def);
    if (!d) continue;
    const build = d.build;
    const ctx = typeof build === 'string' ? build : asRecord(build)?.context;
    if (typeof ctx === 'string' && /^\.?\/?$|^\.\/?$/.test(ctx.trim())) return name;
    if (typeof d.image === 'string' && imageNames.has(imageTail(d.image))) return name;
  }
  // One service only: that is us.
  const names = Object.keys(services);
  if (names.length === 1) return names[0];
  for (const [name, def] of Object.entries(services)) if (asRecord(def)?.build !== undefined) return name;
  return undefined;
}

/** `ghcr.io/acme/shop-api:1.4` → `shop-api`. */
export function imageTail(ref: string): string {
  const noTag = ref.split('@')[0]!.replace(/:[\w.-]+$/, '');
  return (noTag.split('/').pop() ?? noTag).toLowerCase();
}

function readCompose(c: Collector, f: ProjectFile, text: string, imageNames: Set<string>): void {
  let doc: unknown;
  try {
    doc = parseAllDocuments(text)[0]?.toJS();
  } catch {
    return;
  }
  const services = asRecord(asRecord(doc)?.services);
  if (!services) return;
  const self = selfComposeService(services, imageNames);
  if (!self) return;
  addName(c, self);
  const me = asRecord(services[self]);
  if (!me) return;
  const otherServices = new Set(Object.keys(services).filter((n) => n !== self).map((n) => n.toLowerCase()));
  const dep = me.depends_on;
  const deps = Array.isArray(dep) ? dep : asRecord(dep) ? Object.keys(asRecord(dep)!) : [];
  for (const d of deps) if (typeof d === 'string') addLink(c, d, undefined, 'compose', `${f.rel}: services.${self}.depends_on ${d}`);
  for (const l of Array.isArray(me.links) ? me.links : []) if (typeof l === 'string') addLink(c, l.split(':')[0], undefined, 'compose', `${f.rel}: services.${self}.links ${l}`);
  const env = me.environment;
  const entries: [string | undefined, unknown][] = Array.isArray(env) ? env.map((e) => (typeof e === 'string' ? [e.split('=')[0], e.slice(e.indexOf('=') + 1)] : [undefined, undefined])) : Object.entries(asRecord(env) ?? {});
  for (const [k, v] of entries) {
    scanValue(c, k, typeof v === 'number' ? String(v) : v, 'compose', `${f.rel}: services.${self}.environment`);
    // A bare value that names another compose service is a link even without a scheme.
    if (typeof v === 'string' && otherServices.has(v.trim().toLowerCase())) addLink(c, v.trim(), undefined, 'compose', `${f.rel}: services.${self}.environment ${k}=${v}`);
  }
}

function readManifest(c: Collector, f: ProjectFile, text: string): void {
  let docs: unknown[];
  try {
    docs = parseAllDocuments(text).map((d) => d.toJS());
  } catch {
    return;
  }
  for (const doc of docs) {
    const d = asRecord(doc);
    if (!d || typeof d.kind !== 'string' || typeof d.apiVersion !== 'string') continue;
    const kind = d.kind;
    const meta = asRecord(d.metadata);
    const name = typeof meta?.name === 'string' ? meta.name : undefined;
    const spec = asRecord(d.spec);
    if (kind === 'Service' || kind === 'Deployment' || kind === 'StatefulSet' || kind === 'DaemonSet' || kind === 'Rollout') addName(c, name);
    if (kind === 'Ingress') {
      for (const rule of Array.isArray(spec?.rules) ? spec!.rules : []) addHost(c, asRecord(rule)?.host as string | undefined);
      for (const tls of Array.isArray(spec?.tls) ? spec!.tls : []) for (const h of Array.isArray(asRecord(tls)?.hosts) ? (asRecord(tls)!.hosts as unknown[]) : []) addHost(c, h as string);
    }
    if (kind === 'HTTPRoute' || kind === 'VirtualService' || kind === 'Gateway') {
      const hosts = (spec?.hostnames ?? spec?.hosts) as unknown;
      for (const h of Array.isArray(hosts) ? hosts : []) addHost(c, h as string);
    }
    // Container environment on workloads.
    const tpl = asRecord(asRecord(spec?.template)?.spec) ?? (kind === 'Pod' ? spec : undefined);
    const containers = [...(Array.isArray(tpl?.containers) ? tpl!.containers : []), ...(Array.isArray(tpl?.initContainers) ? tpl!.initContainers : [])];
    for (const cont of containers) {
      const cr = asRecord(cont);
      for (const e of Array.isArray(cr?.env) ? cr!.env : []) {
        const er = asRecord(e);
        if (er && typeof er.name === 'string') scanValue(c, er.name, er.value, 'kubernetes', `${f.rel}: ${kind} ${name ?? ''} env`.replace(/\s+env$/, ' env'));
      }
    }
    if (kind === 'ConfigMap') for (const [k, v] of Object.entries(asRecord(d.data) ?? {})) scanValue(c, k, v, 'kubernetes', `${f.rel}: ConfigMap ${name ?? ''}`.trim());
  }
}

function readEnv(c: Collector, f: ProjectFile, text: string): void {
  for (const { key, value } of envLines(text)) scanValue(c, key, value, 'env', f.rel);
}

function readConfig(c: Collector, f: ProjectFile, text: string): void {
  // Server names of a reverse proxy in the repo name this application.
  if (f.ext === 'conf' || f.name.endsWith('.conf')) for (const m of text.matchAll(/^\s*server_name\s+([^;]+);/gm)) for (const h of m[1]!.split(/\s+/)) if (h && h !== '_') addHost(c, h);
  if (/\.(json|ya?ml|toml|ini|cfg|conf|properties)$/i.test(f.name)) {
    // Key = value and key: value lines first, so the key can name a self URL; then any URL in the file.
    for (const line of text.split(/\r?\n/)) {
      const m = /^\s*"?([A-Za-z_][\w.-]*)"?\s*[:=]\s*"?([^"\s,]+)"?/.exec(line);
      if (m && SELF_KEY_RE.test(m[1]!)) scanValue(c, m[1], m[2], 'config', f.rel);
    }
    for (const u of urlsIn(text).slice(0, 40)) addLink(c, u.host, u.port, 'config', `${f.rel}: ${u.host}${u.port ? `:${u.port}` : ''}`);
  }
}

/** Discover the services this application calls and the names it is known by. */
export function discoverLinks(rootDir: string, opts: LinkOptions = {}): ServiceLinks {
  const c: Collector = { links: new Map(), names: new Set(), hosts: new Set() };
  const imageNames = new Set((opts.images ?? []).map(imageTail));
  addName(c, opts.projectName);
  addName(c, basename(rootDir));
  for (const img of imageNames) addName(c, img);
  const files = walkProject(rootDir, { ignore: opts.ignore });
  for (const f of files) {
    const text = isComposeFile(f) || isManifestCandidate(f) || isEnvFile(f) || isConfigFile(f) ? readText(f) : undefined;
    if (text === undefined) continue;
    try {
      if (isComposeFile(f)) readCompose(c, f, text, imageNames);
      else if (isManifestCandidate(f)) readManifest(c, f, text);
      else if (isEnvFile(f)) readEnv(c, f, text);
      else if (isConfigFile(f)) readConfig(c, f, text);
    } catch (err) {
      opts.log?.(`Links: ${f.rel}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  const identity: ServiceIdentity = { names: [...c.names].sort(), hosts: [...c.hosts].sort() };
  const outbound = [...c.links.values()].sort((a, b) => Number(a.external) - Number(b.external) || a.host.localeCompare(b.host));
  return { identity, outbound };
}
