export interface FixCandidate {
  kind: 'commit' | 'pull' | 'compare';
  owner: string;
  repo: string;
  /** commit sha, PR number, or "a...b" */
  ref: string;
  url: string;
  /** Repository name contains the package name (or vice versa). */
  repoMatch: boolean;
  /** Reference type from the advisory (FIX ranks first). */
  typed: boolean;
}

interface Ref {
  type?: string;
  url: string;
}

/** Picks GitHub fix commits / PRs / compares out of an advisory's references, best first. */
export function fixCandidates(references: (string | Ref)[], pkg: string, max = 3): FixCandidate[] {
  const out: FixCandidate[] = [];
  const seen = new Set<string>();
  const base = pkg.replace(/^@[^/]+\//, '').toLowerCase().replace(/[^a-z0-9]/g, '');
  for (const r of references) {
    const url = typeof r === 'string' ? r : r.url;
    const typed = typeof r !== 'string' && r.type === 'FIX';
    let m: RegExpExecArray | null;
    let c: FixCandidate | undefined;
    if ((m = /^https?:\/\/github\.com\/([^/]+)\/([^/#?]+)\/(?:commit|commits)\/([0-9a-f]{7,40})/i.exec(url))) {
      c = { kind: 'commit', owner: m[1]!, repo: m[2]!, ref: m[3]!, url, repoMatch: false, typed };
    } else if ((m = /^https?:\/\/github\.com\/([^/]+)\/([^/#?]+)\/pull\/(\d+)\/commits\/([0-9a-f]{7,40})/i.exec(url))) {
      c = { kind: 'commit', owner: m[1]!, repo: m[2]!, ref: m[4]!, url, repoMatch: false, typed };
    } else if ((m = /^https?:\/\/github\.com\/([^/]+)\/([^/#?]+)\/pull\/(\d+)/i.exec(url))) {
      c = { kind: 'pull', owner: m[1]!, repo: m[2]!, ref: m[3]!, url, repoMatch: false, typed };
    } else if ((m = /^https?:\/\/github\.com\/([^/]+)\/([^/#?]+)\/compare\/([^#?\s]+\.\.\.[^#?\s]+)/i.exec(url))) {
      c = { kind: 'compare', owner: m[1]!, repo: m[2]!, ref: m[3]!, url, repoMatch: false, typed };
    }
    if (!c) continue;
    const repoNorm = c.repo.toLowerCase().replace(/\.git$/, '').replace(/[^a-z0-9]/g, '');
    c.repoMatch = repoNorm.includes(base) || base.includes(repoNorm);
    const key = `${c.owner}/${c.repo}/${c.kind}/${c.ref}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }
  const rank = (c: FixCandidate) => (c.typed ? 0 : 4) + (c.repoMatch ? 0 : 2) + (c.kind === 'commit' ? 0 : 1);
  return out.sort((a, b) => rank(a) - rank(b)).slice(0, max);
}

export function diffUrl(c: FixCandidate): string {
  const path = c.kind === 'commit' ? `commit/${c.ref}` : c.kind === 'pull' ? `pull/${c.ref}` : `compare/${c.ref}`;
  return `https://github.com/${c.owner}/${c.repo}/${path}.diff`;
}

/** Ref to fetch the post-fix file contents from raw.githubusercontent.com. */
export function rawRef(c: FixCandidate): string {
  if (c.kind === 'commit') return c.ref;
  if (c.kind === 'pull') return `refs/pull/${c.ref}/head`;
  return c.ref.split('...')[1]!;
}
