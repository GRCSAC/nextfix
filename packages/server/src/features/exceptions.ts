import type { DatabaseSync } from 'node:sqlite';
import type { Decision, ExceptionKind, ExceptionStatus, Finding, ScanReport } from '../../../engine/src/types.ts';
import type { VexException } from '../../../engine/src/report/vex.ts';
import { normalizeFindingId } from '../diff.ts';
import { FeatureError, type Route, type RouteUser } from './core.ts';

/*
 * Exceptions: a human decision about one finding of one target. An analyst proposes, an admin
 * approves (an admin's own proposal is approved on the spot), and an approved, unexpired
 * exception moves the finding to Track when a report is served.
 */

export const migrations: string[] = [
  // 4: exceptions (3 is the auth schema). proposed_by / approved_by hold usernames so the table stands without a users table.
  `
    CREATE TABLE IF NOT EXISTS exceptions (
      id INTEGER PRIMARY KEY,
      target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
      finding_id TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('accepted-risk', 'false-positive', 'mitigated')),
      reason TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked', 'expired')),
      proposed_by TEXT NOT NULL,
      approved_by TEXT,
      review_note TEXT,
      expires_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS exceptions_target ON exceptions(target_id, finding_id, status);
    CREATE INDEX IF NOT EXISTS exceptions_expiry ON exceptions(status, expires_at);
  `,
];

export const EXCEPTION_KINDS: ExceptionKind[] = ['accepted-risk', 'false-positive', 'mitigated'];
export const REASON_MIN = 10;
export const REASON_MAX = 2000;
/** An expiry may be at most this far ahead. */
export const MAX_EXPIRY_DAYS = 2 * 365;
const DAY_MS = 86_400_000;

export interface ExceptionRow {
  /** The rowid, served as a string (the dashboard treats ids as opaque strings). */
  id: string;
  targetId: number;
  findingId: string;
  kind: ExceptionKind;
  reason: string;
  status: ExceptionStatus;
  proposedBy: string;
  approvedBy: string | null;
  /** What the reviewer wrote when approving, rejecting or revoking. */
  reviewNote: string | null;
  expiresAt: string | null;
  createdAt: string;
  /** Changes on every status change, so for an approved row it is the approval time. */
  updatedAt: string;
}

interface RawRow {
  id: number;
  target_id: number;
  finding_id: string;
  kind: string;
  reason: string;
  status: string;
  proposed_by: string;
  approved_by: string | null;
  review_note: string | null;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
}

const COLUMNS = 'id, target_id, finding_id, kind, reason, status, proposed_by, approved_by, review_note, expires_at, created_at, updated_at';

function toRow(r: RawRow): ExceptionRow {
  return {
    id: String(r.id),
    targetId: r.target_id,
    findingId: r.finding_id,
    kind: r.kind as ExceptionKind,
    reason: r.reason,
    status: r.status as ExceptionStatus,
    proposedBy: r.proposed_by,
    approvedBy: r.approved_by,
    reviewNote: r.review_note,
    expiresAt: r.expires_at,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

const nowIso = () => new Date().toISOString();

/** Pending or approved (and not past expiry): the states that block another exception on the same finding. */
export function isActive(e: ExceptionRow, now = nowIso()): boolean {
  if (e.status === 'pending') return true;
  return e.status === 'approved' && (!e.expiresAt || e.expiresAt > now);
}

/** Approved and not past expiry: the state that changes a decision. */
export function isInForce(e: ExceptionRow, now = nowIso()): boolean {
  return e.status === 'approved' && (!e.expiresAt || e.expiresAt > now);
}

// ---------------------------------------------------------------------------------------------
// Pure functions over the database

export function listExceptions(db: DatabaseSync, targetId: number): ExceptionRow[] {
  const rows = db.prepare(`SELECT ${COLUMNS} FROM exceptions WHERE target_id = ? ORDER BY created_at DESC, id DESC`).all(targetId) as unknown as RawRow[];
  return rows.map(toRow);
}

export function getException(db: DatabaseSync, id: number | string): ExceptionRow | undefined {
  const n = Number(id);
  if (!Number.isInteger(n) || n < 1) return undefined;
  const r = db.prepare(`SELECT ${COLUMNS} FROM exceptions WHERE id = ?`).get(n) as RawRow | undefined;
  return r ? toRow(r) : undefined;
}

/** The active exception (pending or in force) per finding of a target, newest first so one wins per finding. */
export function activeExceptions(db: DatabaseSync, targetId: number, now = nowIso()): ExceptionRow[] {
  const seen = new Set<string>();
  const out: ExceptionRow[] = [];
  for (const e of listExceptions(db, targetId)) {
    if (!isActive(e, now) || seen.has(e.findingId)) continue;
    seen.add(e.findingId);
    out.push(e);
  }
  return out;
}

/** Exceptions in force across every target, for the VEX export and the portfolio. */
export function exceptionsInForce(db: DatabaseSync, targetId: number, now = nowIso()): ExceptionRow[] {
  return activeExceptions(db, targetId, now).filter((e) => isInForce(e, now));
}

/** Flip approved rows whose expiry has passed to `expired`; returns how many changed. */
export function expireExceptions(db: DatabaseSync, now = nowIso()): number {
  const res = db.prepare("UPDATE exceptions SET status = 'expired', updated_at = ? WHERE status = 'approved' AND expires_at IS NOT NULL AND expires_at <= ?").run(now, now);
  return Number(res.changes);
}

/** Exceptions still waiting for a review. */
export function pendingExceptions(db: DatabaseSync, targetId: number): ExceptionRow[] {
  return listExceptions(db, targetId).filter((e) => e.status === 'pending');
}

export interface ProposeInput {
  targetId: number;
  findingId: string;
  kind: ExceptionKind;
  reason: string;
  expiresAt?: string | null;
  user: RouteUser | null;
  now?: string;
}

/** Normalise an expiry given as an ISO date or timestamp to end-of-day UTC; throws 400 on bad input. */
export function parseExpiry(value: unknown, now = nowIso()): string | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') throw new FeatureError(400, 'expiresAt must be an ISO date (YYYY-MM-DD)');
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ].*)?$/.exec(value.trim());
  if (!m) throw new FeatureError(400, 'expiresAt must be an ISO date (YYYY-MM-DD)');
  const ms = Date.parse(`${m[1]}-${m[2]}-${m[3]}T23:59:59.999Z`);
  if (!Number.isFinite(ms)) throw new FeatureError(400, 'expiresAt is not a valid date');
  const nowMs = Date.parse(now);
  if (ms <= nowMs) throw new FeatureError(400, 'expiresAt must be in the future');
  if (ms - nowMs > MAX_EXPIRY_DAYS * DAY_MS) throw new FeatureError(400, 'expiresAt may be at most 2 years ahead');
  return new Date(ms).toISOString();
}

export function validateReason(value: unknown): string {
  const reason = typeof value === 'string' ? value.trim() : '';
  if (reason.length < REASON_MIN || reason.length > REASON_MAX) throw new FeatureError(400, `reason must be ${REASON_MIN} to ${REASON_MAX} characters`);
  return reason;
}

/** The latest stored report of a target, read directly (the store is not available to the features). */
export function latestReport(db: DatabaseSync, targetId: number): { scanId: number; report: ScanReport } | undefined {
  const r = db.prepare('SELECT id, report FROM scans WHERE target_id = ? ORDER BY created_at DESC, id DESC LIMIT 1').get(targetId) as { id: number; report: string } | undefined;
  if (!r) return undefined;
  return { scanId: r.id, report: JSON.parse(r.report) as ScanReport };
}

export function targetExists(db: DatabaseSync, targetId: number): boolean {
  return !!db.prepare('SELECT 1 FROM targets WHERE id = ?').get(targetId);
}

/**
 * Record a proposal. An admin's own proposal is approved immediately. 409 when the finding already
 * has a pending or in-force exception; 404 when the finding is not in the target's latest scan.
 */
export function proposeException(db: DatabaseSync, input: ProposeInput): ExceptionRow {
  const now = input.now ?? nowIso();
  if (!targetExists(db, input.targetId)) throw new FeatureError(404, 'Target not found');
  if (!EXCEPTION_KINDS.includes(input.kind)) throw new FeatureError(400, `kind must be one of ${EXCEPTION_KINDS.join(', ')}`);
  const reason = validateReason(input.reason);
  const expiresAt = parseExpiry(input.expiresAt, now);
  const latest = latestReport(db, input.targetId);
  if (!latest) throw new FeatureError(404, 'This application has not been scanned yet');
  const wanted = normalizeFindingId(input.findingId);
  if (!latest.report.findings.some((f) => normalizeFindingId(f.id) === wanted)) throw new FeatureError(404, 'Finding not in the latest scan of this application');
  expireExceptions(db, now);
  const clash = activeExceptions(db, input.targetId, now).find((e) => normalizeFindingId(e.findingId) === wanted);
  if (clash) throw new FeatureError(409, `An exception for this finding is already ${clash.status} (#${clash.id})`);
  const username = input.user?.username ?? 'local';
  const admin = input.user?.role === 'admin';
  const res = db
    .prepare('INSERT INTO exceptions (target_id, finding_id, kind, reason, status, proposed_by, approved_by, review_note, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)')
    .run(input.targetId, input.findingId, input.kind, reason, admin ? 'approved' : 'pending', username, admin ? username : null, expiresAt, now, now);
  return getException(db, Number(res.lastInsertRowid))!;
}

export type ReviewStatus = 'approved' | 'rejected' | 'revoked';

export interface ReviewInput {
  id: number | string;
  status: ReviewStatus;
  reason?: unknown;
  user: RouteUser | null;
  now?: string;
}

/**
 * Approve, reject or revoke. Only admins review; approving one's own proposal is therefore allowed
 * only because the caller is an admin (the route's role gate), and the handler checks it again.
 */
export function reviewException(db: DatabaseSync, input: ReviewInput): ExceptionRow {
  const now = input.now ?? nowIso();
  if (input.user && input.user.role !== 'admin') throw new FeatureError(403, 'Only an admin can review exceptions');
  const e = getException(db, input.id);
  if (!e) throw new FeatureError(404, 'Exception not found');
  if (!['approved', 'rejected', 'revoked'].includes(input.status)) throw new FeatureError(400, 'status must be approved, rejected or revoked');
  const note = input.reason === undefined || input.reason === null ? null : typeof input.reason === 'string' ? input.reason.trim().slice(0, REASON_MAX) || null : null;
  const allowed: Record<ReviewStatus, ExceptionStatus[]> = { approved: ['pending'], rejected: ['pending'], revoked: ['approved'] };
  if (!allowed[input.status].includes(e.status)) throw new FeatureError(409, `A ${e.status} exception cannot be ${input.status}`);
  if (input.status === 'approved' && e.expiresAt && e.expiresAt <= now) throw new FeatureError(409, 'The proposed expiry has already passed; propose it again with a new date');
  const username = input.user?.username ?? 'local';
  db.prepare('UPDATE exceptions SET status = ?, approved_by = ?, review_note = ?, updated_at = ? WHERE id = ?').run(input.status, input.status === 'approved' ? username : e.approvedBy, note, now, Number(e.id));
  return getException(db, e.id)!;
}

// ---------------------------------------------------------------------------------------------
// Applying exceptions to a report

/** What a served finding carries about its exception. */
export function publicException(e: ExceptionRow, originalDecision?: Decision): NonNullable<Finding['exception']> {
  return {
    id: e.id,
    kind: e.kind,
    status: e.status,
    reason: e.reason,
    expiresAt: e.expiresAt,
    approvedBy: e.approvedBy ?? undefined,
    approvedAt: e.status === 'approved' || e.status === 'expired' || e.status === 'revoked' ? e.updatedAt : undefined,
    originalDecision,
  };
}

/** The shape the engine's VEX writer accepts. */
export function toVexException(e: ExceptionRow): VexException {
  return { findingId: e.findingId, kind: e.kind, status: e.status, reason: e.reason, approvedBy: e.approvedBy ?? undefined, approvedAt: e.updatedAt, expiresAt: e.expiresAt ?? undefined };
}

/**
 * A copy of the report with exceptions attached to their findings. In-force ones set the decision
 * to Track and lead the why lines with who accepted it; the summary is recomputed to match.
 */
export function applyExceptions(report: ScanReport, exceptions: ExceptionRow[], now = nowIso()): ScanReport {
  const byId = new Map<string, ExceptionRow>();
  for (const e of exceptions) {
    const key = normalizeFindingId(e.findingId);
    const prev = byId.get(key);
    // One active exception per finding is enforced on write; if history leaked two, the one in force wins.
    if (!prev || (isInForce(e, now) && !isInForce(prev, now))) byId.set(key, e);
  }
  const findings = report.findings.map((f) => {
    const e = byId.get(normalizeFindingId(f.id));
    if (!e) return f;
    if (!isInForce(e, now)) return { ...f, exception: publicException(e) };
    const approver = e.approvedBy ?? 'an administrator';
    const line = `Accepted by ${approver} on ${e.updatedAt.slice(0, 10)}: ${e.reason}`;
    return { ...f, decision: 'Track' as Decision, why: [line, ...f.why], exception: publicException(e, f.decision) };
  });
  const byDecision: Record<Decision, number> = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };
  for (const f of findings) byDecision[f.decision] = (byDecision[f.decision] ?? 0) + 1;
  const actionable = byDecision.Act + byDecision.Attend;
  const noiseRemoved = findings.length ? (findings.length - actionable) / findings.length : 0;
  return { ...report, findings, summary: { ...report.summary, byDecision, noiseRemoved } };
}

// ---------------------------------------------------------------------------------------------
// Routes

function targetIdOf(params: Record<string, string>): number {
  const id = Number(params.id);
  if (!Number.isInteger(id) || id < 1) throw new FeatureError(400, 'Bad target id');
  return id;
}

export const routes: Route[] = [
  {
    method: 'GET',
    pattern: '/api/targets/:id/exceptions',
    role: 'viewer',
    handler({ db, params }) {
      const targetId = targetIdOf(params);
      if (!targetExists(db, targetId)) throw new FeatureError(404, 'Target not found');
      expireExceptions(db);
      return { body: listExceptions(db, targetId) };
    },
  },
  {
    method: 'POST',
    pattern: '/api/targets/:id/exceptions',
    role: 'analyst',
    handler({ db, params, body, user, audit }) {
      const targetId = targetIdOf(params);
      const findingId = typeof body.findingId === 'string' ? body.findingId : '';
      if (!findingId) throw new FeatureError(400, 'findingId is required');
      const row = proposeException(db, { targetId, findingId, kind: body.kind as ExceptionKind, reason: body.reason as string, expiresAt: body.expiresAt as string | undefined, user });
      audit(row.status === 'approved' ? 'exception.approve' : 'exception.propose', `target:${targetId}/finding:${findingId}`, { id: row.id, kind: row.kind, expiresAt: row.expiresAt });
      return { status: 201, body: row };
    },
  },
  {
    method: 'PATCH',
    pattern: '/api/exceptions/:id',
    role: 'admin',
    handler({ db, params, body, user, audit }) {
      const id = Number(params.id);
      if (!Number.isInteger(id) || id < 1) throw new FeatureError(400, 'Bad exception id');
      const row = reviewException(db, { id, status: body.status as ReviewStatus, reason: body.reason, user });
      audit(`exception.${row.status === 'approved' ? 'approve' : row.status === 'rejected' ? 'reject' : 'revoke'}`, `target:${row.targetId}/finding:${row.findingId}`, { id: row.id, note: row.reviewNote });
      return { body: row };
    },
  },
];
