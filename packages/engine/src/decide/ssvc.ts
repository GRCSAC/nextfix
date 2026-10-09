import semver from 'semver';
import type { Decision, Exploitation, Finding } from '../types.ts';

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

  const bestPath = reach.paths.find((p) => !p.entry.authenticated) ?? reach.paths[0];
  const unauth = !!bestPath && !bestPath.entry.authenticated;
  const userInput = !!bestPath?.userInput;

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
    case 'reachable': {
      if (unauth) decision = exploitation !== 'none' || (cvss ?? 0) >= 9 || (userInput && (cvss ?? 0) >= 7) ? 'Act' : 'Attend';
      else decision = exploitation === 'active' ? 'Act' : 'Attend';
      why.push(`Reachable: ${describePath(bestPath!)}.`);
      if (bestPath!.callSite.userInput) why.push('User-controlled request data flows directly into that call.');
      else if (bestPath!.inputEntersAt) {
        const e = bestPath!.inputEntersAt;
        why.push(`User-controlled request data enters the chain in ${e.name} (${e.file}:${e.line}) and is passed down to the vulnerable call.`);
      } else why.push('No request data was seen flowing into the call (static heuristic; treat as a hint, not proof).');
      if (!bestPath!.entry.authenticated) why.push(`The entry point ${bestPath!.entry.method} ${bestPath!.entry.path} has no auth guard.`);
      else why.push(`The entry point ${bestPath!.entry.method} ${bestPath!.entry.path} sits behind ${list(bestPath!.entry.guards)}.`);
      if (reach.paths.length > 1) why.push(`${reach.paths.length} entry points reach this call in total.`);
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

  const epssText = f.epss ? `EPSS ${(f.epss.score * 100).toFixed(2)}% (percentile ${(f.epss.percentile * 100).toFixed(0)})` : 'no EPSS score';
  why.push(f.kev ? `In CISA KEV since ${f.kev.dateAdded}${f.kev.ransomware ? ', used in ransomware' : ''}; ${epssText}.` : `Not in CISA KEV; ${epssText}.`);

  let fix: string | undefined;
  if (a.fixedVersion) {
    const major = semver.major(a.fixedVersion) !== semver.major(c.version);
    fix = `Upgrade ${c.name} ${c.version} → ${a.fixedVersion}${major ? ' (major version change — check for breaking changes)' : ''}`;
    why.push(`${fix}.`);
  } else {
    why.push('No fixed version is published yet.');
  }

  return { decision, score: score(f, exploitation, unauth, userInput), why, fix, exploitation };
}

function score(f: Input, exploitation: Exploitation, unauth: boolean, userInput: boolean): number {
  const base = (f.advisory.cvssScore ?? 5) * 10;
  const reachMult: Record<string, number> = {
    reachable: 1,
    'called-unreached': 0.55,
    'imported-unknown-symbol': 0.6,
    'imported-not-called': 0.2,
    unused: 0.1,
    'dev-only': 0.05,
  };
  let s = base * (reachMult[f.reach.tier] ?? 0.5);
  if (f.reach.tier === 'reachable') s *= unauth ? 1 : 0.75;
  if (f.exposure.network === 'local-only') s *= 0.5;
  s += (f.epss?.score ?? 0) * 20;
  if (exploitation === 'active') s += 15;
  if (userInput) s += 5;
  return Math.max(0, Math.min(100, Math.round(s)));
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
