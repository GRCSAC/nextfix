import type { Finding, ScanReport } from '../types.ts';

/** OpenVEX v0.2.0 document: one statement per finding. */
export function toOpenVex(report: ScanReport): unknown {
  const ts = report.generatedAt;
  const docId = `https://nextfix.grcsac.com/vex/${report.target.name ?? 'app'}/${ts.replace(/[^0-9]/g, '').slice(0, 14)}`;
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': docId,
    author: `NextFix ${report.tool.version}`,
    role: 'Automated reachability analysis',
    timestamp: ts,
    version: 1,
    tooling: `NextFix/${report.tool.version}`,
    statements: report.findings.map((f) => statement(f, ts)),
  };
}

function statement(f: Finding, ts: string): Record<string, unknown> {
  const vuln = { name: f.advisory.cve ?? f.advisory.id, aliases: [f.advisory.id, ...f.advisory.aliases].filter((x) => x !== (f.advisory.cve ?? f.advisory.id)) };
  const products = [{ '@id': f.component.purl }];
  const base = { vulnerability: vuln, products, timestamp: ts };
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
