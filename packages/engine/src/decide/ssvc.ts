import semver from 'semver';
import type { Decision, Exploitation, Finding } from '../types.ts';
import { isDistro } from '../vulns/ecosystems.ts';

type Input = Omit<Finding, 'decision' | 'score' | 'why' | 'fix' | 'exploitation'>;

/**
 * SSVC-style decision. Modelled on CISA's deployer tree (exploitation, automatable,
 * technical impact, mission) but with reachability and exposure as the automatable /
 * mission inputs, which is the whole point of NextFix. Every rule is written so the
 * "why" line can quote it back to the user.
 */
export function decide(f: Input): Pick<Finding, 'decision' | 'score' | 'why' | 'fix' | 'exploitation'> {
  const { component: c, advisory: a, reach, exposure } = f;
  const cvss = a.cvssScore;
  const exploitation: Exploitation = f.kev ? 'active' : (f.epss?.score ?? 0) >= 0.1 ? 'likely' : 'none';
  const why: string[] = [];

  const sev = cvss !== undefined ? `CVSS ${cvss.toFixed(1)}${a.severityLabel ? ' ' + a.severityLabel : ''}` : a.severityLabel ?? 'severity unknown';
  why.push(`${c.name} ${c.version} is affected by ${a.cve ?? a.id}: ${a.summary || 'no summary'} (${sev}).`);

  // Worst case first: unauthenticated and carrying request data, then unauthenticated, then any with data.
  const bestPath = reach.paths.find((p) => !p.entry.authenticated && p.userInput) ?? reach.paths.find((p) => !p.entry.authenticated) ?? reach.paths.find((p) => p.userInput) ?? reach.paths[0];
  const unauth = !!bestPath && !bestPath.entry.authenticated;
  const userInput = !!bestPath?.userInput;
  const obs = observedFor(f);

  let decision: Decision;
  switch (reach.tier) {
    case 'dev-only':
      decision = 'Track';
      why.push(`Not shipped: ${c.name} is a devDependency, so it is not in the production artifact.`);
      break;
    case 'unused':
      decision = 'Track';
      why.push(`Not loaded: no source file imports ${c.name}; it is installed but never executed.`);
      break;
    case 'imported-not-called':
      decision = 'Track';
      why.push(
        `Vulnerable code not in execute path: ${c.name} is imported in ${reach.importedIn.join(', ')} but none of the vulnerable function(s) ${list(f.symbols?.symbols ?? [])} are called.`,
      );
      break;
    case 'imported-unknown-symbol':
      decision = exploitation !== 'none' || (cvss ?? 0) >= 7 ? 'Attend' : 'Track*';
      why.push(`Package-level only: ${c.name} is imported in ${reach.importedIn.join(', ')} but NextFix has no function-level data for this advisory yet, so it cannot rule the call out.`);
      break;
    case 'called-unreached':
      decision = exploitation === 'active' ? 'Attend' : 'Track*';
      why.push(`Called but unreachable: ${describeSites(reach)} — no HTTP entry point leads there (dead or internal-only code).`);
      break;
    case 'image-only': {
      // No call path can be claimed for an OS package or tooling inside the image, so the call rests on
      // exploitation evidence, severity and whether a fix exists to move to.
      decision = exploitation === 'active' || (a.fixedVersion && (exploitation === 'likely' || (cvss ?? 0) >= 7)) ? 'Attend' : 'Track*';
      const kind = isDistro(c.ecosystem) ? `an OS package (${c.ecosystem})` : c.packageType === 'binary' ? 'a binary' : `a ${c.ecosystem} package`;
      why.push(`In the container image only: ${c.name} is ${kind} in ${c.image ?? 'the image'}${c.path && c.path !== c.name ? ` (${(c.paths ?? [c.path]).join(', ')})` : ''}; the application code does not import it, and NextFix does not trace code paths inside images.`);
      if (!a.fixedVersion && exploitation !== 'active') why.push('No fix is available to move to, so this is watched rather than scheduled.');
      break;
    }
    case 'reachable': {
      if (unauth) {
        // Public traffic on the route makes the exposure a fact rather than an inference, so the severity bar drops.
        const seenPublic = obs.publicOnOpen > 0 && ((cvss ?? 0) >= 7 || (userInput && (cvss ?? 0) >= 5));
        decision = exploitation !== 'none' || (cvss ?? 0) >= 9 || (userInput && (cvss ?? 0) >= 7) || seenPublic ? 'Act' : 'Attend';
      } else decision = exploitation === 'active' ? 'Act' : 'Attend';
      why.push(`Reachable: ${describePath(bestPath!)}.`);
      if (bestPath!.userInput && bestPath!.taintedArgument) {
        const t = bestPath!.taintedArgument;
        const src = bestPath!.inputSource ? `\`${bestPath!.inputSource}\`` : 'request data';
        if (bestPath!.callSite.userInput) why.push(`Request data ${src} is passed directly as argument ${t.index + 1} of ${bestPath!.callSite.text}().`);
        else if (bestPath!.inputEntersAt) {
          const e = bestPath!.inputEntersAt;
          why.push(`Request data ${src} enters the chain in ${e.name} (${e.file}:${e.line}) and arrives as argument ${t.index + 1} (\`${t.text}\`) of ${bestPath!.callSite.text}().`);
        } else why.push(`Request data ${src} arrives as argument ${t.index + 1} of ${bestPath!.callSite.text}().`);
      } else {
        const other = reach.paths.find((p) => p.userInput && p.taintedArgument);
        if (other) {
          why.push(`On this path the arguments are the application's own. Request data does reach it through ${other.entry.method} ${other.entry.path}${other.entry.authenticated ? ' (behind auth)' : ''}: \`${other.inputSource ?? 'request data'}\` arrives as argument ${other.taintedArgument!.index + 1} of ${other.callSite.text}().`);
        } else why.push("No request data was traced into the arguments of the vulnerable call on any path; the inputs appear to be the application's own.");
      }
      if (!bestPath!.entry.authenticated) why.push(`The entry point ${bestPath!.entry.method} ${bestPath!.entry.path} has no auth guard.`);
      else why.push(`The entry point ${bestPath!.entry.method} ${bestPath!.entry.path} sits behind ${list(bestPath!.entry.guards)}.`);
      if (reach.paths.length > 1) {
        const n = reach.paths.filter((p) => p.userInput).length;
        why.push(`${reach.paths.length} entry points reach this call in total, ${n} of them carrying request data.`);
      }
      // Observed traffic: what the access logs recorded for the route the decision rests on.
      if (obs.read) {
        const e = bestPath!.entry;
        const t = e.traffic!;
        const route = `${e.method} ${e.path}`;
        const n = (k: number) => k.toLocaleString('en-US');
        if (t.public > 0) {
          const lifted = unauth && decision === 'Act' && exploitation === 'none' && (cvss ?? 0) < 9 && !(userInput && (cvss ?? 0) >= 7);
          why.push(`Observed: ${route} received ${n(t.requests)} request${t.requests === 1 ? '' : 's'} in the ${obs.days} days to ${obs.to}, ${n(t.public)} from public addresses${e.authenticated ? ' (behind a login)' : ''}${t.lastSeenAt ? `, the last on ${t.lastSeenAt.slice(0, 10)}` : ''}.${lifted ? ' The internet is already calling this route, so this is Act rather than Attend.' : ''}`);
        } else if (t.requests > 0) why.push(`Observed: ${route} received ${n(t.requests)} request${t.requests === 1 ? '' : 's'} in the ${obs.days} days to ${obs.to}, all from internal addresses.`);
        else {
          why.push(`Observed: no request reached ${route}${obs.allCold && reach.paths.length > 1 ? ' or any other route to this call' : ''} in the ${obs.days} days of logs to ${obs.to}.`);
          if (unauth && decision === 'Act' && exploitation === 'none' && obs.allCold && obs.usable) {
            decision = 'Attend';
            why.push('Demoted from Act to Attend: the route is reachable in the code but nobody has called it; it is re-decided when traffic appears or exploit data changes.');
          } else if (obs.stale) why.push('The logs end more than a month before this scan, so they are reported but do not lower the decision.');
          else if (!obs.usable && obs.allCold) why.push('The window is shorter than two weeks, so the quiet route is reported but does not lower the decision.');
        }
      }
      // Internet reach, when it is known and the decision would otherwise rest on an inference.
      if (unauth && decision === 'Act' && exploitation === 'none' && exposure.reach === 'internal' && obs.publicOnOpen === 0) {
        decision = 'Attend';
        why.push(`Demoted from Act to Attend: the service is not reachable from the internet (${(exposure.reachEvidence ?? []).join('; ')}), so the open route is open to the internal network only.`);
      }
      break;
    }
  }

  if (reach.confidence === 'derived' && f.symbols?.evidence) {
    const ev = f.symbols.evidence;
    why.push(`Function-level data was derived from the fix commit (${ev.commits[0] ?? 'unknown'}): it changed ${list(ev.changedFunctions.slice(0, 4))}${ev.changedFunctions.length > 4 ? ` and ${ev.changedFunctions.length - 4} more` : ''}, reachable through ${list(f.symbols.symbols)}. Not hand-verified.`);
  } else if (reach.confidence === 'derived') why.push('Function-level data for this advisory was derived automatically from the fix commit, not hand-verified.');

  if (exposure.network === 'published') why.push(`Service is network-published: ${exposure.evidence.join('; ')}.`);
  else if (exposure.network === 'local-only') why.push('Service binds to loopback only; network exposure is limited to the host.');
  else why.push('Network exposure unknown (no Dockerfile EXPOSE or compose ports found).');
  if (exposure.reach === 'internet') why.push(`Internet-facing: ${(exposure.reachEvidence ?? []).join('; ')}.`);
  else if (exposure.reach === 'internal') why.push(`Not reachable from the internet: ${(exposure.reachEvidence ?? []).join('; ')}.`);

  const epssText = f.epss ? `EPSS ${(f.epss.score * 100).toFixed(2)}% (percentile ${(f.epss.percentile * 100).toFixed(0)})` : 'no EPSS score';
  const kevName = f.kev?.cve && f.kev.cve !== (a.cve ?? a.id) ? ` (${f.kev.cve}, one of ${(a.cves ?? []).length} CVEs in this advisory)` : '';
  why.push(f.kev ? `In CISA KEV since ${f.kev.dateAdded}${kevName}${f.kev.ransomware ? ', used in ransomware' : ''}; ${epssText}.` : `Not in CISA KEV; ${epssText}.`);

  let fix: string | undefined;
  if (a.fixedVersion) {
    const major = majorOf(a.fixedVersion) !== majorOf(c.version);
    if (c.origin === 'image' && reach.tier === 'image-only') fix = `Upgrade ${c.name} ${c.version} → ${a.fixedVersion} in the image (rebuild from an updated base image, or upgrade the package in the Dockerfile)`;
    else fix = `Upgrade ${c.name} ${c.version} → ${a.fixedVersion}${major ? ' (major version change — check for breaking changes)' : ''}`;
    why.push(`${fix}.`);
  } else {
    why.push('No fixed version is published yet.');
  }

  return { decision, score: score(f, exploitation, unauth, userInput, obs), why, fix, exploitation };
}

interface Observed {
  /** Access logs were read and cover this finding's routes. */
  read: boolean;
  /** Public requests on the unauthenticated route the decision rests on. */
  publicOnOpen: number;
  /** No route to the vulnerable call received a request. */
  allCold: boolean;
  /** The window is long enough (14 days), current, and covers routes of this service. */
  usable: boolean;
  stale: boolean;
  days: number;
  to: string;
}

/** What the logs recorded for the routes that reach this finding; `read` is false when no logs were read. */
function observedFor(f: Input): Observed {
  const o = f.exposure.observed;
  const paths = f.reach.paths;
  const read = !!o && paths.length > 0 && paths.every((p) => !!p.entry.traffic);
  if (!read || !o) return { read: false, publicOnOpen: 0, allCold: false, usable: false, stale: false, days: 0, to: '' };
  const best = paths.find((p) => !p.entry.authenticated && p.userInput) ?? paths.find((p) => !p.entry.authenticated) ?? paths.find((p) => p.userInput) ?? paths[0]!;
  const publicOnOpen = best.entry.authenticated ? 0 : best.entry.traffic!.public;
  const allCold = paths.every((p) => p.entry.traffic!.requests === 0);
  return { read, publicOnOpen, allCold, usable: !o.stale && o.days >= 14 && o.routesSeen > 0, stale: o.stale, days: o.days, to: o.to.slice(0, 10) };
}

function score(f: Input, exploitation: Exploitation, unauth: boolean, userInput: boolean, obs: Observed): number {
  const base = (f.advisory.cvssScore ?? 5) * 10;
  const reachMult: Record<string, number> = {
    reachable: 1,
    'called-unreached': 0.55,
    'imported-unknown-symbol': 0.6,
    'image-only': 0.5,
    'imported-not-called': 0.2,
    unused: 0.1,
    'dev-only': 0.05,
  };
  let s = base * (reachMult[f.reach.tier] ?? 0.5);
  if (f.reach.tier === 'reachable') s *= unauth ? 1 : 0.75;
  if (f.exposure.network === 'local-only') s *= 0.5;
  if (f.reach.tier === 'reachable' && obs.read) {
    if (obs.publicOnOpen > 0) s += 5;
    else if (obs.allCold && obs.usable) s *= 0.7;
  }
  if (f.reach.tier === 'reachable' && f.exposure.reach === 'internal' && obs.publicOnOpen === 0) s *= 0.8;
  s += (f.epss?.score ?? 0) * 20;
  if (exploitation === 'active') s += 15;
  if (userInput) s += 5;
  return Math.max(0, Math.min(100, Math.round(s)));
}

function majorOf(v: string): string {
  const s = semver.valid(v) ? String(semver.major(v)) : v.replace(/^v/, '').split(/[.+!-]/)[0];
  return s ?? v;
}

function list(items: string[]): string {
  return items.map((s) => `${s}()`).join(', ');
}

function describeSites(reach: Finding['reach']): string {
  return reach.callSites
    .slice(0, 3)
    .map((s) => `${s.text}() at ${s.file}:${s.line}`)
    .join(', ');
}

function describePath(p: Finding['reach']['paths'][number]): string {
  const hops = p.hops.map((h) => `${h.name} (${h.file}:${h.line})`);
  return `${p.entry.method} ${p.entry.path} → ${hops.join(' → ')} → ${p.callSite.text}() at ${p.callSite.file}:${p.callSite.line}`;
}
