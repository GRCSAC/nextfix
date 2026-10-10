import type { Component, Decision, Finding, ScanReport } from '../types.ts';
import { bestPathOf, fixCommandFor } from './ticket.ts';

/**
 * SARIF 2.1.0: one run, one rule per advisory, one result per finding. Written for GitHub
 * code scanning (relative URIs under %SRCROOT%, a level on every result, security-severity
 * on every rule) but valid against the schema for any consumer.
 */

export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
export const SARIF_INFORMATION_URI = 'https://nextfix.grcsac.com';

export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

export interface SarifMessage {
  text: string;
}

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId: string;
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: SarifArtifactLocation;
    region: { startLine: number; startColumn?: number };
  };
  message?: SarifMessage;
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: SarifMessage;
  fullDescription: SarifMessage;
  helpUri?: string;
  help?: SarifMessage;
  defaultConfiguration: { level: Exclude<SarifLevel, 'none'> };
  properties: {
    cvss?: number;
    epss?: number;
    kev: boolean;
    decision: Decision;
    tier: Finding['reach']['tier'];
    'security-severity'?: string;
    tags: string[];
  };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: SarifMessage;
  locations: SarifLocation[];
  relatedLocations?: SarifLocation[];
  partialFingerprints: { 'nextfix/finding': string };
  properties: {
    decision: Decision;
    score: number;
    tier: Finding['reach']['tier'];
    confidence: Finding['reach']['confidence'];
    package: string;
    version: string;
    purl: string;
    fixedVersion?: string;
    fixCommand?: string;
  };
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: [
    {
      tool: {
        driver: {
          name: 'NextFix';
          version: string;
          semanticVersion: string;
          informationUri: string;
          rules: SarifRule[];
        };
      };
      automationDetails: { id: string };
      results: SarifResult[];
    },
  ];
}

const LEVEL: Record<Decision, SarifLevel> = { Act: 'error', Attend: 'warning', 'Track*': 'note', Track: 'none' };
const DECISION_ORDER: Decision[] = ['Act', 'Attend', 'Track*', 'Track'];

export function sarifLevel(decision: Decision): SarifLevel {
  return LEVEL[decision];
}

/** Repository-relative path with forward slashes, as GitHub wants it under %SRCROOT%. */
function relativeUri(file: string): string {
  return file.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
}

/**
 * The file that pins the component: package-lock.json for `node_modules/…` paths (under the
 * workspace that owns them), the `<lockfile>:<key>` form of the yarn / pnpm inventories, the
 * requirements file for Python, and the Dockerfile for components that only exist in an image.
 */
export function manifestFor(c: Component): string {
  if (c.origin === 'image') return 'Dockerfile';
  const p = c.path.replace(/\\/g, '/');
  const nm = p.indexOf('node_modules/');
  if (nm >= 0) return `${p.slice(0, nm)}package-lock.json`;
  const colon = p.indexOf(':');
  if (colon > 0) return p.slice(0, colon);
  return p || 'package.json';
}

function location(uri: string, line: number, message?: string, column?: number): SarifLocation {
  return {
    physicalLocation: {
      artifactLocation: { uri: relativeUri(uri), uriBaseId: '%SRCROOT%' },
      region: { startLine: Math.max(1, line), ...(column && column > 0 ? { startColumn: column } : {}) },
    },
    ...(message ? { message: { text: message } } : {}),
  };
}

function ruleFor(f: Finding): SarifRule {
  const a = f.advisory;
  const level = sarifLevel(f.decision);
  const cvss = a.cvssScore;
  return {
    id: a.id,
    name: (a.cve ?? a.id).replace(/[^A-Za-z0-9_.-]/g, '_'),
    shortDescription: { text: a.summary || a.id },
    fullDescription: { text: f.why[0] ?? a.summary ?? a.id },
    ...(a.references[0] ? { helpUri: a.references[0] } : {}),
    help: { text: a.details ? a.details.slice(0, 4000) : a.summary || a.id },
    defaultConfiguration: { level: level === 'none' ? 'note' : level },
    properties: {
      cvss,
      epss: f.epss?.score,
      kev: !!f.kev,
      decision: f.decision,
      tier: f.reach.tier,
      ...(cvss !== undefined && cvss > 0 ? { 'security-severity': cvss.toFixed(1) } : {}),
      tags: ['security'],
    },
  };
}

function resultFor(f: Finding, ruleIndex: number): SarifResult {
  const c = f.component;
  const locations = [location(manifestFor(c), 1, `${c.name} ${c.version} is pinned here`)];
  const related: SarifLocation[] = [];
  const p = bestPathOf(f);
  if (f.reach.tier === 'reachable' && p) {
    related.push(location(p.entry.file, p.entry.line, `entry point ${p.entry.method} ${p.entry.path}`));
    const callee = p.callSite.text.split('(')[0]?.trim() || p.callSite.symbol;
    related.push(location(p.callSite.file, p.callSite.line, `vulnerable call ${callee}()`, p.callSite.col));
  }
  return {
    ruleId: f.advisory.id,
    ruleIndex,
    level: sarifLevel(f.decision),
    message: { text: f.why.join('\n') || `${c.name} ${c.version} is affected by ${f.advisory.id}.` },
    locations,
    ...(related.length ? { relatedLocations: related } : {}),
    partialFingerprints: { 'nextfix/finding': f.id },
    properties: {
      decision: f.decision,
      score: f.score,
      tier: f.reach.tier,
      confidence: f.reach.confidence,
      package: c.name,
      version: c.version,
      purl: c.purl,
      ...(f.advisory.fixedVersion ? { fixedVersion: f.advisory.fixedVersion } : {}),
      ...(fixCommandFor(f) ? { fixCommand: fixCommandFor(f) } : {}),
    },
  };
}

export function toSarif(report: ScanReport): SarifLog {
  // One rule per advisory. Findings are ordered worst first, so the rule's properties and
  // default level describe the worst finding the advisory has.
  const rules: SarifRule[] = [];
  const ruleIndex = new Map<string, number>();
  const ordered = [...report.findings].sort((a, b) => DECISION_ORDER.indexOf(a.decision) - DECISION_ORDER.indexOf(b.decision) || b.score - a.score);
  for (const f of ordered) {
    if (ruleIndex.has(f.advisory.id)) continue;
    ruleIndex.set(f.advisory.id, rules.length);
    rules.push(ruleFor(f));
  }
  const results = ordered.map((f) => resultFor(f, ruleIndex.get(f.advisory.id)!));
  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'NextFix',
            version: report.tool.version,
            semanticVersion: report.tool.version,
            informationUri: SARIF_INFORMATION_URI,
            rules,
          },
        },
        automationDetails: { id: `nextfix/${report.target.name ?? 'app'}` },
        results,
      },
    ],
  };
}
