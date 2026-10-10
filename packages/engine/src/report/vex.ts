import type { ExceptionKind, Finding, ScanReport } from '../types.ts';

/**
 * An approved exception the VEX document should speak for. The server passes the rows it keeps;
 * the engine only needs the finding id, the kind and the words to quote.
 */
export interface VexException {
  findingId: string;
  kind: ExceptionKind;
  status: string;
  reason: string;
  approvedBy?: string;
  approvedAt?: string;
  expiresAt?: string;
}

/**
 * OpenVEX v0.2.0 document: one statement per finding. Findings with an approved, unexpired
 * exception get the statement the exception implies instead of the one reachability gives.
 */
export function toOpenVex(report: ScanReport, exceptions: VexException[] = []): unknown {
  const ts = report.generatedAt;
  const docId = `https://nextfix.grcsac.com/vex/${report.target.name ?? 'app'}/${ts.replace(/[^0-9]/g, '').slice(0, 14)}`;
  const now = new Date().toISOString();
  const active = new Map<string, VexException>();
  for (const e of exceptions) if (e.status === 'approved' && (!e.expiresAt || e.expiresAt > now)) active.set(e.findingId, e);
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': docId,
    author: `NextFix ${report.tool.version}`,
    role: 'Automated reachability analysis',
    timestamp: ts,
    version: 1,
    tooling: `NextFix/${report.tool.version}`,
    statements: report.findings.map((f) => {
      const e = active.get(f.id) ?? attachedException(f, now);
      return e ? exceptionStatement(f, e, ts) : statement(f, ts);
    }),
  };
}

/** A finding the server already decorated carries its exception; use it when no row was passed. */
function attachedException(f: Finding, now: string): VexException | undefined {
  const e = f.exception;
  if (!e || e.status !== 'approved' || (e.expiresAt && e.expiresAt <= now)) return undefined;
  return { findingId: f.id, kind: e.kind, status: e.status, reason: e.reason ?? '', approvedBy: e.approvedBy, approvedAt: e.approvedAt, expiresAt: e.expiresAt ?? undefined };
}

function statementBase(f: Finding, ts: string) {
  const vuln = { name: f.advisory.cve ?? f.advisory.id, aliases: [f.advisory.id, ...f.advisory.aliases].filter((x) => x !== (f.advisory.cve ?? f.advisory.id)) };
  const products = [{ '@id': f.component.purl }];
  return { vulnerability: vuln, products, timestamp: ts };
}

function exceptionStatement(f: Finding, e: VexException, ts: string): Record<string, unknown> {
  const base = statementBase(f, ts);
  const approver = e.approvedBy ?? 'an administrator';
  const on = e.approvedAt ? ` on ${e.approvedAt.slice(0, 10)}` : '';
  const until = e.expiresAt ? e.expiresAt.slice(0, 10) : 'revoked';
  const impact = `${e.reason} (approved by ${approver}${on}, valid until ${until}).`;
  switch (e.kind) {
    case 'false-positive':
      // The reviewer found the vulnerable code is not in this product at all.
      return { ...base, status: 'not_affected', justification: 'vulnerable_code_not_present', impact_statement: `False positive: ${impact}` };
    case 'mitigated':
      return { ...base, status: 'not_affected', justification: 'inline_mitigations_already_exist', impact_statement: `Mitigated: ${impact}` };
    case 'accepted-risk':
      // OpenVEX has no not_affected justification for a risk someone chose to carry: the product
      // is still affected, so the statement stays `affected` and the acceptance is the action.
      return {
        ...base,
        status: 'affected',
        status_notes: f.why.find((w) => w.startsWith('Reachable:')) ?? `Risk accepted (${f.reach.tier}).`,
        action_statement: `Risk accepted by ${approver} until ${until}: ${e.reason}`,
        action_statement_timestamp: e.approvedAt ?? ts,
        impact_statement: `Accepted risk: ${impact}`,
      };
  }
}

function statement(f: Finding, ts: string): Record<string, unknown> {
  const base = statementBase(f, ts);
  switch (f.reach.tier) {
    case 'dev-only':
      return { ...base, status: 'not_affected', justification: 'component_not_present', impact_statement: `${f.component.name} is a devDependency and is not part of the shipped artifact.` };
    case 'unused':
      return { ...base, status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path', impact_statement: `${f.component.name} is installed but no source file imports it.` };
    case 'imported-not-called':
      return {
        ...base,
        status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
        impact_statement: `Vulnerable function(s) ${f.symbols?.symbols.join(', ')} of ${f.component.name} are never called (static call-graph analysis, confidence: ${f.reach.confidence}).`,
      };
    case 'called-unreached':
      return { ...base, status: 'under_investigation', status_notes: `Vulnerable function is called at ${f.reach.callSites.map((s) => `${s.file}:${s.line}`).join(', ')} but no HTTP entry point reaches it. Confirm the code is dead before marking not_affected.` };
    case 'imported-unknown-symbol':
      return { ...base, status: 'affected', status_notes: 'Package is imported; NextFix has no function-level data for this advisory, so it is treated as affected.', action_statement: f.fix ?? 'No fixed version published.' };
    case 'image-only':
      return { ...base, status: 'affected', status_notes: `Package is present in the container image${f.component.image ? ` ${f.component.image}` : ''}; NextFix does not trace code paths inside images, so it is treated as affected.`, action_statement: f.fix ?? 'No fixed version published by the distribution.' };
    case 'reachable':
      return { ...base, status: 'affected', status_notes: f.why.find((w) => w.startsWith('Reachable:')), action_statement: f.fix ?? 'No fixed version published; mitigate at the entry point.' };
  }
}
