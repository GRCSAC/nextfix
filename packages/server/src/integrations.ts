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

const ghBase = (cfg: GitHubConfig) => (cfg.apiBase ?? 'https://api.github.com').replace(/\/+$/, '');
const ghHeaders = (token: string) => ({ authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': USER_AGENT, 'content-type': 'application/json' });

export async function githubTest(cfg: GitHubConfig): Promise<string> {
  const res = await fetch(`${ghBase(cfg)}/repos/${cfg.repo}`, { headers: ghHeaders(cfg.token) });
  if (!res.ok) throw new IntegrationError(res.status, `GitHub: ${await readError(res)}`);
  const j = (await res.json()) as { full_name: string; permissions?: { push?: boolean } };
  if (j.permissions && j.permissions.push === false) throw new IntegrationError(403, `GitHub: the token cannot write to ${j.full_name}`);
  return `Connected to ${j.full_name}`;
}

export async function githubCreateIssue(cfg: GitHubConfig, title: string, body: string): Promise<CreatedTicket> {
  const res = await fetch(`${ghBase(cfg)}/repos/${cfg.repo}/issues`, { method: 'POST', headers: ghHeaders(cfg.token), body: JSON.stringify({ title, body, labels: cfg.labels ?? [] }) });
  if (!res.ok) throw new IntegrationError(res.status, `GitHub: ${await readError(res)}`);
  const j = (await res.json()) as { number: number; html_url: string };
  return { key: `#${j.number}`, url: j.html_url };
}

// ---------------- Jira Cloud ----------------

const jiraHeaders = (cfg: JiraConfig) => ({ authorization: `Basic ${Buffer.from(`${cfg.email}:${cfg.apiToken}`).toString('base64')}`, accept: 'application/json', 'content-type': 'application/json', 'user-agent': USER_AGENT });
const jiraBase = (cfg: JiraConfig) => cfg.baseUrl.replace(/\/+$/, '');

export async function jiraTest(cfg: JiraConfig): Promise<string> {
  const res = await fetch(`${jiraBase(cfg)}/rest/api/3/project/${encodeURIComponent(cfg.projectKey)}`, { headers: jiraHeaders(cfg) });
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
  const res = await fetch(`${jiraBase(cfg)}/rest/api/3/issue`, { method: 'POST', headers: jiraHeaders(cfg), body: JSON.stringify(body) });
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
    // **bold** and `code`
    const nodes: unknown[] = [];
    const re = /(\*\*([^*]+)\*\*|`([^`]+)`)/g;
    let last = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      if (m.index > last) nodes.push({ type: 'text', text: text.slice(last, m.index) });
      if (m[2]) nodes.push({ type: 'text', text: m[2], marks: [{ type: 'strong' }] });
      else if (m[3]) nodes.push({ type: 'text', text: m[3], marks: [{ type: 'code' }] });
      last = m.index + m[0].length;
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
