import { test } from 'node:test';
import assert from 'node:assert/strict';
import { manifestFor, sarifLevel, toSarif, type SarifLog } from './sarif.ts';
import type { Component, Finding, ScanReport } from '../types.ts';

/*
 * A small structural check in place of the full SARIF 2.1.0 JSON schema: the required
 * properties and enums the schema demands on the objects NextFix writes, plus what GitHub
 * code scanning insists on (a level on every result, rule ids that resolve, relative URIs
 * under %SRCROOT%, at most 25,000 results and rules per run).
 */
export function validateSarif(log: unknown): string[] {
  const errors: string[] = [];
  const need = (obj: unknown, keys: string[], where: string) => {
    if (!obj || typeof obj !== 'object') return errors.push(`${where}: not an object`);
    for (const k of keys) if (!(k in (obj as object))) errors.push(`${where}: missing ${k}`);
  };
  const isUri = (s: unknown) => typeof s === 'string' && /^[a-z][a-z0-9+.-]*:/i.test(s);
  const message = (m: unknown, where: string) => {
    need(m, [], where);
    const mm = m as { text?: unknown; markdown?: unknown; id?: unknown };
    if (typeof mm.text !== 'string' && typeof mm.markdown !== 'string' && typeof mm.id !== 'string') errors.push(`${where}: message needs text, markdown or id`);
  };
  const location = (l: unknown, where: string) => {
    const loc = l as { physicalLocation?: { artifactLocation?: { uri?: unknown; uriBaseId?: unknown }; region?: { startLine?: unknown } }; message?: unknown };
    need(loc.physicalLocation, ['artifactLocation'], `${where}.physicalLocation`);
    const art = loc.physicalLocation?.artifactLocation;
    if (typeof art?.uri !== 'string') errors.push(`${where}: artifactLocation.uri missing`);
    else {
      if (art.uri.includes('\\')) errors.push(`${where}: uri has backslashes: ${art.uri}`);
      if (art.uri.startsWith('/') || isUri(art.uri)) errors.push(`${where}: uri is not relative: ${art.uri}`);
    }
    if (art?.uriBaseId !== '%SRCROOT%') errors.push(`${where}: uriBaseId is not %SRCROOT%`);
    const line = loc.physicalLocation?.region?.startLine;
    if (typeof line !== 'number' || line < 1) errors.push(`${where}: region.startLine must be >= 1`);
    if (loc.message !== undefined) message(loc.message, `${where}.message`);
  };

  need(log, ['version', 'runs'], 'log');
  const l = log as { $schema?: unknown; version?: unknown; runs?: unknown[] };
  if (l.version !== '2.1.0') errors.push(`log.version must be 2.1.0`);
  if (l.$schema !== undefined && !isUri(l.$schema)) errors.push('log.$schema must be a URI');
  if (!Array.isArray(l.runs)) return [...errors, 'log.runs must be an array'];
  if (l.runs.length > 20) errors.push('GitHub accepts at most 20 runs');
  l.runs.forEach((run, ri) => {
    const where = `runs[${ri}]`;
    need(run, ['tool'], where);
    const r = run as { tool?: { driver?: { name?: unknown; version?: unknown; informationUri?: unknown; rules?: unknown[] } }; results?: unknown[] };
    need(r.tool, ['driver'], `${where}.tool`);
    const d = r.tool?.driver;
    need(d, ['name'], `${where}.tool.driver`);
    if (d?.informationUri !== undefined && !isUri(d.informationUri)) errors.push(`${where}: informationUri must be a URI`);
    const rules = d?.rules ?? [];
    if (rules.length > 25000) errors.push(`${where}: GitHub accepts at most 25,000 rules`);
    const ruleIds = new Map<string, number>();
    rules.forEach((rule, i) => {
      const rw = `${where}.rules[${i}]`;
      need(rule, ['id'], rw);
      const ru = rule as { id?: unknown; shortDescription?: unknown; fullDescription?: unknown; helpUri?: unknown; help?: unknown; defaultConfiguration?: { level?: unknown }; properties?: { 'security-severity'?: unknown } };
      if (typeof ru.id === 'string') {
        if (ruleIds.has(ru.id)) errors.push(`${rw}: duplicate rule id ${ru.id}`);
        ruleIds.set(ru.id, i);
      }
      if (ru.shortDescription !== undefined) message(ru.shortDescription, `${rw}.shortDescription`);
      if (ru.fullDescription !== undefined) message(ru.fullDescription, `${rw}.fullDescription`);
      if (ru.help !== undefined) message(ru.help, `${rw}.help`);
      if (ru.helpUri !== undefined && !isUri(ru.helpUri)) errors.push(`${rw}: helpUri must be a URI`);
      const lvl = ru.defaultConfiguration?.level;
      if (lvl !== undefined && !['none', 'note', 'warning', 'error'].includes(lvl as string)) errors.push(`${rw}: bad defaultConfiguration.level ${String(lvl)}`);
      if (lvl === 'none') errors.push(`${rw}: GitHub only accepts note, warning or error as a default level`);
      const sev = ru.properties?.['security-severity'];
      if (sev !== undefined && !(typeof sev === 'string' && Number(sev) > 0 && Number(sev) <= 10)) errors.push(`${rw}: security-severity must be a string in (0, 10]`);
    });
    const results = r.results ?? [];
    if (results.length > 25000) errors.push(`${where}: GitHub accepts at most 25,000 results`);
    results.forEach((res, i) => {
      const w = `${where}.results[${i}]`;
      need(res, ['message'], w);
      const x = res as { ruleId?: unknown; ruleIndex?: unknown; level?: unknown; message?: unknown; locations?: unknown[]; relatedLocations?: unknown[]; partialFingerprints?: unknown };
      message(x.message, `${w}.message`);
      if (!['none', 'note', 'warning', 'error'].includes(x.level as string)) errors.push(`${w}: level missing or invalid`);
      if (typeof x.ruleId !== 'string') errors.push(`${w}: ruleId missing`);
      else if (!ruleIds.has(x.ruleId)) errors.push(`${w}: ruleId ${x.ruleId} matches no rule`);
      else if (x.ruleIndex !== undefined && x.ruleIndex !== ruleIds.get(x.ruleId)) errors.push(`${w}: ruleIndex does not match ruleId`);
      if (!Array.isArray(x.locations) || !x.locations.length) errors.push(`${w}: locations must be non-empty`);
      else x.locations.forEach((loc, j) => location(loc, `${w}.locations[${j}]`));
      (x.relatedLocations ?? []).forEach((loc, j) => location(loc, `${w}.relatedLocations[${j}]`));
      if (x.partialFingerprints !== undefined) {
        for (const [k, v] of Object.entries(x.partialFingerprints as Record<string, unknown>)) if (typeof v !== 'string') errors.push(`${w}: partialFingerprints.${k} must be a string`);
      }
    });
  });
  return errors;
}

const comp = (name: string, version: string, extra: Partial<Component> = {}): Component => ({ ecosystem: 'npm', name, version, purl: `pkg:npm/${name}@${version}`, dev: false, optional: false, direct: true, path: `node_modules/${name}`, ...extra });

const entry = { method: 'POST', path: '/preview', file: 'src\\app.js', line: 12, authenticated: false, guards: [], mounted: true, handlerIds: ['h1'] };
const callSite = { file: 'src/services/render.js', line: 6, col: 10, text: '_.template(source)', symbol: '_.template', userInput: true };

function finding(id: string, decision: Finding['decision'], component: Component, advisoryId: string, extra: Partial<Finding> = {}): Finding {
  return {
    id,
    component,
    advisory: { id: advisoryId, aliases: [], cve: advisoryId.startsWith('CVE-') ? advisoryId : undefined, summary: `Summary of ${advisoryId}`, details: 'Details.', cvssScore: 7.2, fixedVersion: '4.17.21', references: ['https://nvd.nist.gov/vuln/detail/' + advisoryId] },
    reach: { tier: 'unused', confidence: 'package-level', importedIn: [], callSites: [], paths: [] },
    exposure: { network: 'published', ports: [3000], evidence: [] },
    exploitation: 'none',
    decision,
    score: 50,
    why: [`${component.name} ${component.version} is affected by ${advisoryId}.`, 'Second why line.'],
    ...extra,
  };
}

function report(findings: Finding[]): ScanReport {
  const byDecision = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };
  for (const f of findings) byDecision[f.decision]++;
  return {
    tool: { name: 'NextFix', version: '0.9.0' },
    target: { dir: 'C:\\apps\\shop', name: 'express-shop', version: '1.0.0' },
    generatedAt: '2026-10-10T12:00:00.000Z',
    summary: { components: 3, advisories: 3, findings: findings.length, byDecision, byTier: { reachable: 0, 'called-unreached': 0, 'imported-unknown-symbol': 0, 'image-only': 0, 'imported-not-called': 0, unused: 0, 'dev-only': 0 }, noiseRemoved: 0 },
    exposure: { network: 'published', ports: [3000], evidence: [] },
    entryPoints: [entry],
    findings,
  };
}

const lodash = comp('lodash', '4.17.15');
const SAMPLE = report([
  finding('f-track', 'Track', comp('moment', '2.29.1', { path: 'yarn.lock:moment@^2.29.0' }), 'GHSA-xxxx-yyyy-zzzz'),
  finding('f-act', 'Act', lodash, 'CVE-2021-23337', { reach: { tier: 'reachable', confidence: 'confirmed', importedIn: ['src/services/render.js'], callSites: [callSite], paths: [{ entry, hops: [], callSite, userInput: true }] }, epss: { score: 0.21, percentile: 0.98 }, kev: { dateAdded: '2024-01-01', ransomware: false }, score: 81 }),
  finding('f-attend', 'Attend', lodash, 'CVE-2020-28500', { decision: 'Attend', score: 46 }),
  finding('f-act-2', 'Track*', lodash, 'CVE-2021-23337', { score: 42 }),
  finding('f-image', 'Track*', comp('libssl3', '3.0.11-1~deb12u2', { ecosystem: 'Debian:12', purl: 'pkg:deb/debian/libssl3@3.0.11-1~deb12u2', origin: 'image', image: 'shop:latest', path: '/usr/lib/x86_64-linux-gnu/libssl.so.3' }), 'CVE-2024-0727', { score: 30, reach: { tier: 'image-only', confidence: 'package-level', importedIn: [], callSites: [], paths: [] } }),
]);

test('decisions map to SARIF levels', () => {
  assert.equal(sarifLevel('Act'), 'error');
  assert.equal(sarifLevel('Attend'), 'warning');
  assert.equal(sarifLevel('Track*'), 'note');
  assert.equal(sarifLevel('Track'), 'none');
});

test('the component location is the file that pins it', () => {
  assert.equal(manifestFor(comp('a', '1')), 'package-lock.json');
  assert.equal(manifestFor(comp('a', '1', { path: 'packages/api/node_modules/a/node_modules/b' })), 'packages/api/package-lock.json');
  assert.equal(manifestFor(comp('a', '1', { path: 'yarn.lock:a@^1.0.0' })), 'yarn.lock');
  assert.equal(manifestFor(comp('a', '1', { path: 'packages/web/pnpm-lock.yaml:/a@1.0.0(b@2.0.0)' })), 'packages/web/pnpm-lock.yaml');
  assert.equal(manifestFor(comp('a', '1', { path: 'requirements.txt' })), 'requirements.txt');
  assert.equal(manifestFor(comp('a', '1', { origin: 'image', path: '/usr/lib/libssl.so.3' })), 'Dockerfile');
});

test('one run, one rule per advisory, one result per finding, worst first', () => {
  const log = toSarif(SAMPLE);
  assert.equal(log.version, '2.1.0');
  assert.equal(log.runs.length, 1);
  const run = log.runs[0];
  assert.equal(run.tool.driver.name, 'NextFix');
  assert.equal(run.tool.driver.version, '0.9.0');
  assert.equal(run.tool.driver.informationUri, 'https://nextfix.grcsac.com');
  assert.deepEqual(run.tool.driver.rules.map((r) => r.id), ['CVE-2021-23337', 'CVE-2020-28500', 'CVE-2024-0727', 'GHSA-xxxx-yyyy-zzzz']);
  assert.deepEqual(run.results.map((r) => r.partialFingerprints['nextfix/finding']), ['f-act', 'f-attend', 'f-act-2', 'f-image', 'f-track']);
  assert.deepEqual(run.results.map((r) => r.level), ['error', 'warning', 'note', 'note', 'none']);

  const rule = run.tool.driver.rules[0]!;
  assert.equal(rule.name, 'CVE-2021-23337');
  assert.equal(rule.shortDescription.text, 'Summary of CVE-2021-23337');
  assert.equal(rule.fullDescription.text, 'lodash 4.17.15 is affected by CVE-2021-23337.');
  assert.equal(rule.helpUri, 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337');
  assert.equal(rule.defaultConfiguration.level, 'error', 'the advisory has an Act and a Track* finding; the rule carries the worst');
  assert.deepEqual({ ...rule.properties, tags: undefined }, { cvss: 7.2, epss: 0.21, kev: true, decision: 'Act', tier: 'reachable', 'security-severity': '7.2', tags: undefined });

  const act = run.results[0]!;
  assert.equal(act.ruleId, 'CVE-2021-23337');
  assert.equal(act.ruleIndex, 0);
  assert.equal(act.message.text, 'lodash 4.17.15 is affected by CVE-2021-23337.\nSecond why line.');
  assert.deepEqual(act.locations[0]!.physicalLocation, { artifactLocation: { uri: 'package-lock.json', uriBaseId: '%SRCROOT%' }, region: { startLine: 1 } });
  assert.deepEqual(act.relatedLocations!.map((l) => [l.physicalLocation.artifactLocation.uri, l.physicalLocation.region.startLine, l.message!.text]), [
    ['src/app.js', 12, 'entry point POST /preview'],
    ['src/services/render.js', 6, 'vulnerable call _.template()'],
  ]);
  assert.deepEqual(act.properties, { decision: 'Act', score: 81, tier: 'reachable', confidence: 'confirmed', package: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15', fixedVersion: '4.17.21', fixCommand: 'npm install lodash@4.17.21' });

  const attend = run.results[1]!;
  assert.equal(attend.relatedLocations, undefined, 'only reachable findings carry code locations');
  assert.equal(run.results[3]!.locations[0]!.physicalLocation.artifactLocation.uri, 'Dockerfile');
  assert.equal(run.results[3]!.properties.fixCommand, 'apt-get update && apt-get install --only-upgrade -y libssl3');
  assert.equal(run.results[4]!.locations[0]!.physicalLocation.artifactLocation.uri, 'yarn.lock');
  assert.equal(run.tool.driver.rules[3]!.defaultConfiguration.level, 'note', 'a Track-only rule still gets a level GitHub accepts');
});

test('the document passes the structural and GitHub checks', () => {
  assert.deepEqual(validateSarif(toSarif(SAMPLE)), []);
  assert.deepEqual(validateSarif(toSarif(report([]))), []);
});

test('the validator catches what GitHub rejects', () => {
  const log = toSarif(SAMPLE) as unknown as { runs: { results: Record<string, unknown>[]; tool: { driver: { rules: Record<string, unknown>[] } } }[] };
  delete log.runs[0]!.results[0]!.level;
  log.runs[0]!.results[1]!.ruleId = 'nope';
  (log.runs[0]!.results[2]!.locations as { physicalLocation: { artifactLocation: { uri: string } } }[])[0]!.physicalLocation.artifactLocation.uri = 'C:\\apps\\package-lock.json';
  const errors = validateSarif(log as unknown as SarifLog);
  assert.ok(errors.some((e) => e.includes('level missing')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('matches no rule')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('backslashes')), errors.join('\n'));
});
