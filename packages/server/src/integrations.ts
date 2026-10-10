import { USER_AGENT } from '../../engine/src/version.ts';

export type IntegrationKind = 'github' | 'jira';

export interface GitHubConfig {
  /** owner/name */
  repo: string;
  token: string;
  labels?: string[];
  /** GitHub Enterprise or a test double; defaults to https://api.github.com */
  apiBase?: string;
}

export interface JiraConfig {
  /** https://your-site.atlassian.net */
  baseUrl: string;
  email: string;
  apiToken: string;
  projectKey: string;
  issueType?: string;
}

export interface CreatedTicket {
  key: string;
  url: string;
}

export class IntegrationError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Every tracker call gives up after this long. */
export const TRACKER_TIMEOUT_MS = 20_000;
/** Longest Retry-After the client is willing to honour; anything longer is reported instead. */
const RETRY_AFTER_MAX_MS = 30_000;
const GITHUB_DEFAULT_BASE = 'https://api.github.com';

// ---------------- configuration ----------------

const KNOWN_KEYS: Record<IntegrationKind, string[]> = {
  github: ['repo', 'token', 'labels', 'apiBase'],
  jira: ['baseUrl', 'email', 'apiToken', 'projectKey', 'issueType'],
};
const SECRET_KEY: Record<IntegrationKind, 'token' | 'apiToken'> = { github: 'token', jira: 'apiToken' };
const URL_KEY: Record<IntegrationKind, 'apiBase' | 'baseUrl'> = { github: 'apiBase', jira: 'baseUrl' };
const URL_LABEL: Record<IntegrationKind, string> = { github: 'GitHub API address', jira: 'Jira site URL' };

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '[::1]' || /^127\.\d+\.\d+\.\d+$/.test(hostname);
}

/** A tracker address must be a plain https origin (http is fine for loopback only), without credentials, query or fragment. */
export function validateTrackerUrl(value: string, label: string): string {
  const text = value.trim();
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new IntegrationError(400, `${label} must be a full URL such as https://example.com`);
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) throw new IntegrationError(400, `${label} must use https`);
  if (url.username || url.password) throw new IntegrationError(400, `${label} must not contain a username or password`);
  if (url.search || text.includes('?')) throw new IntegrationError(400, `${label} must not contain a query string`);
  if (url.hash || text.includes('#')) throw new IntegrationError(400, `${label} must not contain a fragment`);
  return text.replace(/\/+$/, '');
}

function hostOf(url: string | undefined, fallback: string): string {
  try {
    return new URL(url || fallback).host.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * Merge a settings request into the stored configuration: unknown keys are dropped, addresses are
 * validated, a blank secret keeps the stored one, and moving the address to another host requires
 * the secret to be entered again so a stored token can never be redirected elsewhere.
 */
export function mergeIntegrationConfig(kind: IntegrationKind, existing: Record<string, unknown> | undefined, body: Record<string, unknown>): Record<string, unknown> {
  const prior = existing ?? {};
  const merged: Record<string, unknown> = {};
  for (const key of KNOWN_KEYS[kind]) if (prior[key] !== undefined) merged[key] = prior[key];

  const secretKey = SECRET_KEY[kind];
  const urlKey = URL_KEY[kind];
  const secretGiven = typeof body[secretKey] === 'string' && (body[secretKey] as string).trim() !== '';

  for (const key of KNOWN_KEYS[kind]) {
    if (!(key in body)) continue;
    const v = body[key];
    if (key === 'labels') {
      const list = typeof v === 'string' ? v.split(',') : Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
      merged.labels = list.map((s) => s.trim()).filter(Boolean);
      continue;
    }
    if (typeof v !== 'string') continue;
    const text = v.trim();
    if (key === secretKey) {
      if (text) merged[key] = text;
      continue;
    }
    if (key === urlKey) {
      if (text) merged[key] = validateTrackerUrl(text, URL_LABEL[kind]);
      else delete merged[key];
      continue;
    }
    if (text) merged[key] = text;
    else delete merged[key];
  }

  const fallback = kind === 'github' ? GITHUB_DEFAULT_BASE : '';
  const hostChanged = hostOf(prior[urlKey] as string | undefined, fallback) !== hostOf(merged[urlKey] as string | undefined, fallback);
  if (hostChanged && typeof prior[secretKey] === 'string' && prior[secretKey] && !secretGiven) throw new IntegrationError(400, 'Enter the token again when changing the server address');

  if (kind === 'github' && !merged.repo) throw new IntegrationError(400, 'Enter the repository as owner/name');
  if (kind === 'jira' && !merged.baseUrl) throw new IntegrationError(400, 'Enter the Jira site URL');
  return merged;
}

// ---------------- HTTP ----------------

function retryAfterMs(res: Response): number | undefined {
  const raw = res.headers.get('retry-after');
  if (!raw) return undefined;
  const seconds = Number(raw);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const at = Date.parse(raw);
  return Number.isNaN(at) ? undefined : Math.max(0, at - Date.now());
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** fetch with a hard timeout and one retry when the tracker asks us to wait (403/429 with Retry-After). */
async function trackerFetch(service: string, url: string, init: RequestInit, retried = false): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(url, { ...init, signal: AbortSignal.timeout(TRACKER_TIMEOUT_MS) });
  } catch (err) {
    const e = err as { name?: string; cause?: { code?: string; message?: string } };
    if (e.name === 'TimeoutError' || e.name === 'AbortError') throw new IntegrationError(504, `${service} did not answer within ${TRACKER_TIMEOUT_MS / 1000} s`);
    throw new IntegrationError(502, `${service}: ${e.cause?.code ?? e.cause?.message ?? (err instanceof Error ? err.message : String(err))}`);
  }
  if ((res.status === 403 || res.status === 429) && !retried) {
    const wait = retryAfterMs(res);
    if (wait !== undefined && wait <= RETRY_AFTER_MAX_MS) {
      await res.body?.cancel().catch(() => {});
      await sleep(wait);
      return trackerFetch(service, url, init, true);
    }
    if (wait !== undefined) throw new IntegrationError(res.status, `${service} asked to wait ${Math.ceil(wait / 1000)} s before the next request; try again later`);
  }
  return res;
}

async function readError(res: Response): Promise<string> {
  const text = await res.text().catch(() => '');
  try {
    const j = JSON.parse(text) as { message?: string; errorMessages?: string[]; errors?: Record<string, string> };
    return j.message ?? j.errorMessages?.join('; ') ?? (j.errors ? Object.entries(j.errors).map(([k, v]) => `${k}: ${v}`).join('; ') : text.slice(0, 300));
  } catch {
    return text.slice(0, 300);
  }
}

// ---------------- GitHub ----------------

const ghBase = (cfg: GitHubConfig) => (cfg.apiBase ?? GITHUB_DEFAULT_BASE).replace(/\/+$/, '');
const ghHeaders = (token: string) => ({ authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': USER_AGENT, 'content-type': 'application/json' });

export async function githubTest(cfg: GitHubConfig): Promise<string> {
  const res = await trackerFetch('GitHub', `${ghBase(cfg)}/repos/${cfg.repo}`, { headers: ghHeaders(cfg.token) });
  if (!res.ok) throw new IntegrationError(res.status, `GitHub: ${await readError(res)}`);
  const j = (await res.json()) as { full_name: string; permissions?: { push?: boolean } };
  if (j.permissions && j.permissions.push === false) throw new IntegrationError(403, `GitHub: the token cannot write to ${j.full_name}`);
  return `Connected to ${j.full_name}`;
}

export async function githubCreateIssue(cfg: GitHubConfig, title: string, body: string): Promise<CreatedTicket> {
  const res = await trackerFetch('GitHub', `${ghBase(cfg)}/repos/${cfg.repo}/issues`, { method: 'POST', headers: ghHeaders(cfg.token), body: JSON.stringify({ title, body, labels: cfg.labels ?? [] }) });
  if (!res.ok) throw new IntegrationError(res.status, `GitHub: ${await readError(res)}`);
  const j = (await res.json()) as { number: number; html_url: string };
  return { key: `#${j.number}`, url: j.html_url };
}

// ---------------- Jira Cloud ----------------

const jiraHeaders = (cfg: JiraConfig) => ({ authorization: `Basic ${Buffer.from(`${cfg.email}:${cfg.apiToken}`).toString('base64')}`, accept: 'application/json', 'content-type': 'application/json', 'user-agent': USER_AGENT });
const jiraBase = (cfg: JiraConfig) => cfg.baseUrl.replace(/\/+$/, '');

export async function jiraTest(cfg: JiraConfig): Promise<string> {
  const res = await trackerFetch('Jira', `${jiraBase(cfg)}/rest/api/3/project/${encodeURIComponent(cfg.projectKey)}`, { headers: jiraHeaders(cfg) });
  if (!res.ok) throw new IntegrationError(res.status, `Jira: ${await readError(res)}`);
  const j = (await res.json()) as { name: string; key: string };
  return `Connected to project ${j.key} (${j.name})`;
}

export async function jiraCreateIssue(cfg: JiraConfig, title: string, markdown: string): Promise<CreatedTicket> {
  const body = {
    fields: {
      project: { key: cfg.projectKey },
      summary: title.slice(0, 250),
      issuetype: { name: cfg.issueType || 'Task' },
      description: markdownToAdf(markdown),
    },
  };
  const res = await trackerFetch('Jira', `${jiraBase(cfg)}/rest/api/3/issue`, { method: 'POST', headers: jiraHeaders(cfg), body: JSON.stringify(body) });
  if (!res.ok) throw new IntegrationError(res.status, `Jira: ${await readError(res)}`);
  const j = (await res.json()) as { key: string };
  return { key: j.key, url: `${jiraBase(cfg)}/browse/${j.key}` };
}

/** Atlassian Document Format from the subset of Markdown the ticket body uses. */
export function markdownToAdf(md: string): unknown {
  const content: unknown[] = [];
  const lines = md.split('\n');
  let i = 0;
  const inline = (text: string) => {
    // **bold**, `code` and bare http(s) links
    const nodes: unknown[] = [];
    const re = /(\*\*([^*]+)\*\*|`([^`]+)`|(https?:\/\/[^\s<>"'`]+))/g;
    let last = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      let end = m.index + m[0].length;
      if (m.index > last) nodes.push({ type: 'text', text: text.slice(last, m.index) });
      if (m[2]) nodes.push({ type: 'text', text: m[2], marks: [{ type: 'strong' }] });
      else if (m[3]) nodes.push({ type: 'text', text: m[3], marks: [{ type: 'code' }] });
      else if (m[4]) {
        // Trailing punctuation belongs to the sentence, not the link.
        let href = m[4];
        const unbalanced = (s: string) => s.split(')').length > s.split('(').length;
        while (/[.,;:!?\]]$/.test(href) || (href.endsWith(')') && unbalanced(href))) href = href.slice(0, -1);
        end = m.index + href.length;
        re.lastIndex = end;
        nodes.push({ type: 'text', text: href, marks: [{ type: 'link', attrs: { href } }] });
      }
      last = end;
    }
    if (last < text.length) nodes.push({ type: 'text', text: text.slice(last) });
    return nodes.length ? nodes : [{ type: 'text', text: ' ' }];
  };
  while (i < lines.length) {
    const line = lines[i]!;
    if (!line.trim()) {
      i++;
      continue;
    }
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h) {
      content.push({ type: 'heading', attrs: { level: h[1]!.length }, content: inline(h[2]!.trim()) });
      i++;
      continue;
    }
    if (line.startsWith('```')) {
      const code: string[] = [];
      i++;
      while (i < lines.length && !lines[i]!.startsWith('```')) code.push(lines[i++]!);
      i++;
      content.push({ type: 'codeBlock', attrs: {}, content: [{ type: 'text', text: code.join('\n') || ' ' }] });
      continue;
    }
    if (/^- /.test(line)) {
      const items: unknown[] = [];
      while (i < lines.length && /^- /.test(lines[i]!)) items.push({ type: 'listItem', content: [{ type: 'paragraph', content: inline(lines[i++]!.slice(2)) }] });
      content.push({ type: 'bulletList', content: items });
      continue;
    }
    // paragraph: consecutive non-empty, non-special lines; trailing double-space means a hard break
    const para: unknown[] = [];
    while (i < lines.length && lines[i]!.trim() && !/^(#{1,3}\s|- |```)/.test(lines[i]!)) {
      const t = lines[i]!.replace(/\s{2,}$/, '');
      para.push(...inline(t.replace(/^_(.*)_$/, '$1')));
      i++;
      if (i < lines.length && lines[i]!.trim() && !/^(#{1,3}\s|- |```)/.test(lines[i]!)) para.push({ type: 'hardBreak' });
    }
    content.push({ type: 'paragraph', content: para });
  }
  return { type: 'doc', version: 1, content: content.length ? content : [{ type: 'paragraph', content: [{ type: 'text', text: ' ' }] }] };
}
