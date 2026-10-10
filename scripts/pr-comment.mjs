#!/usr/bin/env node
// Posts (or updates) one pull-request comment from a NextFix JSON report. No dependencies:
// the GitHub REST API over fetch, with the token and event GitHub Actions provides.
//
//   node scripts/pr-comment.mjs nextfix.json              # inside a pull_request job
//   node scripts/pr-comment.mjs nextfix.json --dry-run    # print the Markdown, post nothing
//
// Environment (set by GitHub Actions): GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH,
// GITHUB_SERVER_URL, GITHUB_RUN_ID, GITHUB_SHA. The comment is identified by a hidden marker
// so a later run edits it instead of adding another.

import { readFileSync } from 'node:fs';

const MARKER = '<!-- nextfix-pr-comment -->';
const DECISIONS = ['Act', 'Attend', 'Track*', 'Track'];
const SHORT = { Act: 'Fix now', Attend: 'Fix next cycle', 'Track*': 'Watch', Track: 'Set aside with evidence' };
const ICON = { Act: '▲', Attend: '●', 'Track*': '◐', Track: '○' };

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const file = args.find((a) => !a.startsWith('--')) ?? 'nextfix.json';
const report = JSON.parse(readFileSync(file, 'utf8'));

// ---------------------------------------------------------------------------------------------
// Verdict: the same rules the Overview page applies (packages/web/src/analytics.ts, verdict()).

const pct = (n) => `${Math.round(n * 100)}%`;
const bestPath = (f) => f.reach.paths.find((x) => !x.entry.authenticated && x.userInput) ?? f.reach.paths.find((x) => !x.entry.authenticated) ?? f.reach.paths.find((x) => x.userInput) ?? f.reach.paths[0];
const openPath = (f) => f.reach.paths.some((p) => !p.entry.authenticated);

function verdict(report) {
  const s = report.summary.byDecision;
  if (s.Act > 0) {
    const act = report.findings.filter((f) => f.decision === 'Act');
    const f = act[0];
    const p = bestPath(f);
    const one = act.length === 1;
    const bits = [
      `${one ? 'One vulnerability is' : `${act.length} vulnerabilities are`} reachable ${p ? (p.entry.authenticated ? 'behind a login' : 'without a login') : 'from the code'}`,
      p?.userInput ? (one ? 'carries request data' : 'carry request data') : undefined,
      f.kev ? `and ${one ? 'is' : 'the worst is'} on CISA's known-exploited list` : (f.epss?.score ?? 0) >= 0.1 ? `and ${one ? 'has' : 'the worst has'} a ${pct(f.epss.score)} chance of exploitation within 30 days` : undefined,
    ].filter(Boolean);
    return {
      posture: 'Exposed',
      headline: `${bits.join(', ')}.`,
      detail: `${f.component.name} ${f.component.version} · ${f.advisory.cve ?? f.advisory.id}${p ? ` · ${p.entry.method} ${p.entry.path}` : ''}${f.advisory.fixedVersion ? ` · fix: upgrade to ${f.advisory.fixedVersion}` : ' · no fix published yet'}`,
    };
  }
  if (s.Attend > 0) {
    const open = report.findings.filter((f) => f.decision === 'Attend' && openPath(f)).length;
    return {
      posture: 'Attention',
      headline: `${s.Attend} finding${s.Attend === 1 ? '' : 's'} need${s.Attend === 1 ? 's' : ''} fixing in the next release cycle; nothing is both reachable without a login and known to be exploited.`,
      detail: open ? `${open} of them ${open === 1 ? 'is' : 'are'} reachable without a login.` : 'None is reachable without a login.',
    };
  }
  if (s['Track*'] > 0) {
    return { posture: 'Contained', headline: `${s['Track*']} finding${s['Track*'] === 1 ? ' is' : 's are'} being watched; nothing needs a fix this cycle.`, detail: 'Watched items are re-checked when exploit data or the code changes.' };
  }
  return { posture: 'Clean', headline: report.findings.length ? `${report.findings.length} finding${report.findings.length === 1 ? '' : 's'}, all set aside with evidence; nothing needs action.` : 'No findings. Keep scanning after each release.' };
}

// ---------------------------------------------------------------------------------------------
// Shortest path to green: the upgrades that close the most actionable findings.

function compareVersions(a, b) {
  const pa = String(a).replace(/^v/, '').split(/[.\-+~]/);
  const pb = String(b).replace(/^v/, '').split(/[.\-+~]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? '0';
    const y = pb[i] ?? '0';
    const nx = Number(x);
    const ny = Number(y);
    if (Number.isFinite(nx) && Number.isFinite(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function upgrades(report) {
  const groups = new Map();
  for (const f of report.findings) {
    if (!f.advisory.fixedVersion) continue;
    const c = f.component;
    let g = groups.get(c.purl);
    if (!g) {
      g = { name: c.name, version: c.version, target: f.advisory.fixedVersion, inImage: c.origin === 'image', closes: 0, actionable: 0, byDecision: { Act: 0, Attend: 0, 'Track*': 0, Track: 0 } };
      groups.set(c.purl, g);
    }
    if (compareVersions(f.advisory.fixedVersion, g.target) > 0) g.target = f.advisory.fixedVersion;
    g.closes++;
    g.byDecision[f.decision]++;
    if (f.decision === 'Act' || f.decision === 'Attend') g.actionable++;
  }
  return [...groups.values()].sort((a, b) => b.actionable - a.actionable || b.closes - a.closes || a.name.localeCompare(b.name));
}

function leverageSentence(report, ups) {
  const actionable = report.findings.filter((f) => f.decision === 'Act' || f.decision === 'Attend');
  if (!actionable.length) return 'Nothing needs action; upgrades below close watched or set-aside findings.';
  const covering = ups.filter((u) => u.actionable > 0);
  const packages = covering.filter((u) => !u.inImage).length;
  const image = covering.filter((u) => u.inImage).length;
  const noFix = actionable.filter((f) => !f.advisory.fixedVersion).length;
  const parts = [];
  if (packages) parts.push(`${packages} package upgrade${packages === 1 ? '' : 's'}`);
  if (image) parts.push(`${image === 1 ? 'one' : image} base-image refresh${image === 1 ? '' : 'es'}`);
  const head = parts.length ? `${parts.join(' and ')} clear${parts.length === 1 && packages === 1 ? 's' : ''} ${noFix ? 'all but ' + noFix + ' of' : 'everything'} ${noFix ? 'the findings that need' : 'that needs'} action.` : '';
  const tail = noFix ? ` ${noFix} actionable finding${noFix === 1 ? ' has' : 's have'} no fix published yet; mitigate at the entry point.` : '';
  return (head + tail).trim() || `${noFix} actionable findings have no fix published yet.`;
}

// ---------------------------------------------------------------------------------------------
// The comment

function markdown(report, links) {
  const v = verdict(report);
  const s = report.summary.byDecision;
  const ups = upgrades(report);
  const top = ups.slice(0, 3);
  const name = report.target.name ?? 'this project';
  const lines = [
    MARKER,
    `### NextFix: ${v.posture}`,
    '',
    `**${v.headline}**${v.detail ? `  \n${v.detail}` : ''}`,
    '',
    `| ${DECISIONS.map((d) => `${ICON[d]} ${d}`).join(' | ')} |`,
    `| ${DECISIONS.map(() => '---:').join(' | ')} |`,
    `| ${DECISIONS.map((d) => s[d] ?? 0).join(' | ')} |`,
    '',
    `<sub>${DECISIONS.map((d) => `${d} = ${SHORT[d]}`).join(' · ')}. ${report.summary.components} components, ${report.summary.advisories} advisories, ${report.summary.findings} findings in ${name}.</sub>`,
    '',
    '**Shortest path to green.** ' + leverageSentence(report, ups),
  ];
  if (top.length) {
    lines.push('');
    for (const u of top) {
      const what = u.inImage ? `rebuild the image with ${u.name} ${u.target}` : `\`${u.name}\` ${u.version} → ${u.target}`;
      const counts = DECISIONS.filter((d) => u.byDecision[d]).map((d) => `${u.byDecision[d]} ${d}`).join(', ');
      lines.push(`- ${what}: closes ${u.closes} finding${u.closes === 1 ? '' : 's'} (${counts})`);
    }
  }
  lines.push('');
  const refs = [];
  if (links.codeScanning) refs.push(`[Code scanning alerts](${links.codeScanning})`);
  if (links.run) refs.push(`[SARIF and JSON report on the run](${links.run})`);
  if (refs.length) lines.push(`<sub>${refs.join(' · ')}${links.sha ? ` · ${links.sha.slice(0, 7)}` : ''}</sub>`);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------------------------
// GitHub

async function api(method, path, body) {
  const res = await fetch(`https://api.github.com${path}`, {
    method,
    headers: { authorization: `Bearer ${process.env.GITHUB_TOKEN}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'nextfix-pr-comment', ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`GitHub ${method} ${path}: ${res.status} ${(await res.text()).slice(0, 300)}`);
  return res.status === 204 ? undefined : res.json();
}

async function findExisting(repo, number) {
  for (let page = 1; page <= 10; page++) {
    const comments = await api('GET', `/repos/${repo}/issues/${number}/comments?per_page=100&page=${page}`);
    const mine = comments.find((c) => typeof c.body === 'string' && c.body.includes(MARKER));
    if (mine) return mine;
    if (comments.length < 100) return undefined;
  }
  return undefined;
}

async function main() {
  const repo = process.env.GITHUB_REPOSITORY;
  const server = process.env.GITHUB_SERVER_URL ?? 'https://github.com';
  const event = process.env.GITHUB_EVENT_PATH ? JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')) : {};
  const number = event.pull_request?.number ?? event.issue?.number;
  const links = {
    codeScanning: repo && number ? `${server}/${repo}/security/code-scanning?query=pr%3A${number}+tool%3ANextFix+is%3Aopen` : undefined,
    run: repo && process.env.GITHUB_RUN_ID ? `${server}/${repo}/actions/runs/${process.env.GITHUB_RUN_ID}` : undefined,
    sha: event.pull_request?.head?.sha ?? process.env.GITHUB_SHA,
  };
  const body = markdown(report, links);
  if (dryRun) {
    console.log(body);
    return;
  }
  if (!process.env.GITHUB_TOKEN) throw new Error('GITHUB_TOKEN is not set');
  if (!repo) throw new Error('GITHUB_REPOSITORY is not set');
  if (!number) throw new Error('No pull request number in the event payload; this script runs on pull_request events');
  const existing = await findExisting(repo, number);
  if (existing) {
    await api('PATCH', `/repos/${repo}/issues/comments/${existing.id}`, { body });
    console.log(`Updated comment ${existing.html_url}`);
  } else {
    const created = await api('POST', `/repos/${repo}/issues/${number}/comments`, { body });
    console.log(`Posted comment ${created.html_url}`);
  }
}

main().catch((err) => {
  console.error(`pr-comment: ${err.message}`);
  process.exit(1);
});
