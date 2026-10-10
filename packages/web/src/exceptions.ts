import type { Decision, Exception, ExceptionKind, ExceptionStatus, Role, ScanReport } from './api.ts';

/* A person's decision about a finding: the kinds, the statuses, and how an approved one changes a report. */

export const EXCEPTION_KINDS: ExceptionKind[] = ['accepted-risk', 'false-positive', 'mitigated'];

export const KIND_META: Record<ExceptionKind, { label: string; help: string; icon: 'scale' | 'flag' | 'shield' }> = {
  'accepted-risk': { label: 'Accepted risk', help: 'The risk is understood and the business accepts it for now.', icon: 'scale' },
  'false-positive': { label: 'False positive', help: 'The vulnerable code cannot be reached the way the advisory describes.', icon: 'flag' },
  mitigated: { label: 'Mitigated elsewhere', help: 'A control outside the code (gateway, WAF, validation) blocks the attack.', icon: 'shield' },
};

export const STATUS_META: Record<ExceptionStatus, { label: string; cls: string }> = {
  pending: { label: 'Awaiting approval', cls: 'attend' },
  approved: { label: 'Approved', cls: 'good' },
  rejected: { label: 'Rejected', cls: 'act' },
  revoked: { label: 'Revoked', cls: 'muted' },
  expired: { label: 'Expired', cls: 'muted' },
};

export const isExpired = (e: Exception, now = Date.now()) => !!e.expiresAt && Date.parse(e.expiresAt) <= now;
/** Approved and not past its expiry date. */
export const isAccepted = (e: Exception, now = Date.now()) => e.status === 'approved' && !isExpired(e, now);

/** The newest exception per finding; a later proposal supersedes a rejected or revoked one. */
export function latestByFinding(list: Exception[]): Record<string, Exception> {
  const out: Record<string, Exception> = {};
  for (const e of [...list].sort((a, b) => a.createdAt.localeCompare(b.createdAt))) out[e.findingId] = e;
  return out;
}

export const pendingCount = (list: Exception[]) => list.filter((e) => e.status === 'pending').length;

/**
 * Findings with an accepted exception leave the work queue: they are shown as Track with a
 * marker, and the summary counts follow. Nothing else about the report changes.
 */
export function applyExceptions(report: ScanReport, byFinding: Record<string, Exception>): { report: ScanReport; accepted: Set<string> } {
  const accepted = new Set<string>();
  for (const [id, e] of Object.entries(byFinding)) if (isAccepted(e)) accepted.add(id);
  if (!accepted.size) return { report, accepted };
  const byDecision: Record<Decision, number> = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };
  const findings = report.findings.map((f) => (accepted.has(f.id) && f.decision !== 'Track' ? { ...f, decision: 'Track' as Decision } : f));
  for (const f of findings) byDecision[f.decision]++;
  const actionable = byDecision.Act + byDecision.Attend;
  return { report: { ...report, findings, summary: { ...report.summary, byDecision, noiseRemoved: findings.length ? (findings.length - actionable) / findings.length : 0 } }, accepted };
}

/** What each role may do with exceptions; the reason is the tooltip on a disabled control. */
export function exceptionRights(role: Role): { propose: boolean; approve: boolean; why: string } {
  if (role === 'admin') return { propose: true, approve: true, why: '' };
  if (role === 'analyst') return { propose: true, approve: false, why: 'Only an administrator can approve, reject or revoke' };
  return { propose: false, approve: false, why: 'Viewers can read findings but not set them aside' };
}
