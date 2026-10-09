import { Cache, DAY } from '../vulns/cache.ts';
import { USER_AGENT } from '../version.ts';

export class RateLimited extends Error {}

export interface GitHubOptions {
  cache: Cache;
  offline?: boolean;
  /** Optional token (GITHUB_TOKEN) to lift unauthenticated limits. */
  token?: string;
  log?: (msg: string) => void;
}

const MAX_BYTES = 4 * 1024 * 1024;

async function cachedText(url: string, opts: GitHubOptions, headers: Record<string, string> = {}): Promise<string | undefined> {
  const key = `gh:${url}`;
  const hit = opts.cache.get<string | null>(key, opts.offline);
  if (hit !== undefined) return hit ?? undefined;
  if (opts.offline) return undefined;
  const res = await fetch(url, { headers: { 'user-agent': USER_AGENT, ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}), ...headers }, redirect: 'follow' });
  if (res.status === 429 || res.status === 403) throw new RateLimited(`GitHub rate limit at ${url} (${res.status})`);
  if (res.status === 404) {
    opts.cache.set(key, null, 7 * DAY);
    return undefined;
  }
  if (!res.ok) throw new Error(`GitHub ${res.status} for ${url}`);
  const len = Number(res.headers.get('content-length') ?? 0);
  if (len > MAX_BYTES) {
    opts.cache.set(key, null, 30 * DAY);
    return undefined;
  }
  const text = await res.text();
  if (text.length > MAX_BYTES) {
    opts.cache.set(key, null, 30 * DAY);
    return undefined;
  }
  opts.cache.set(key, text, 30 * DAY);
  return text;
}

/** Unified diff for a commit, PR or compare. */
export function fetchDiff(url: string, opts: GitHubOptions): Promise<string | undefined> {
  return cachedText(url, opts, { accept: 'text/plain' });
}

/** File contents at a ref. */
export function fetchRaw(owner: string, repo: string, ref: string, path: string, opts: GitHubOptions): Promise<string | undefined> {
  return cachedText(`https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${path}`, opts);
}
