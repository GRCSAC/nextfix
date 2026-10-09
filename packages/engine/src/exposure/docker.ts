import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Exposure } from '../types.ts';

/** Reads Dockerfile EXPOSE and compose `ports:` to decide whether the service is network-published. */
export function analyzeExposure(rootDir: string, listenLocalOnly: boolean): Exposure {
  const ports = new Set<number>();
  const evidence: string[] = [];
  let published = false;

  for (const name of readdirSync(rootDir)) {
    if (/^Dockerfile(\..+)?$/i.test(name)) {
      const text = readFileSync(join(rootDir, name), 'utf8');
      for (const line of text.split(/\r?\n/)) {
        const m = /^\s*EXPOSE\s+(.+)$/i.exec(line);
        if (!m) continue;
        for (const tok of m[1]!.split(/\s+/)) {
          const p = parseInt(tok, 10);
          if (!Number.isNaN(p)) {
            ports.add(p);
            evidence.push(`${name}: EXPOSE ${p}`);
          }
        }
      }
    }
  }

  for (const name of ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']) {
    const file = join(rootDir, name);
    if (!existsSync(file)) continue;
    const lines = readFileSync(file, 'utf8').split(/\r?\n/);
    let inPorts = false;
    let portsIndent = -1;
    for (const line of lines) {
      const indent = line.search(/\S/);
      if (indent < 0) continue;
      if (/^\s*ports\s*:/.test(line)) {
        inPorts = true;
        portsIndent = indent;
        continue;
      }
      if (inPorts) {
        if (indent <= portsIndent) {
          inPorts = false;
        } else {
          const m = /^\s*-\s*["']?(?:(?:[\d.]+):)?(\d+)(?::(\d+))?/.exec(line);
          if (m) {
            const host = parseInt(m[1]!, 10);
            ports.add(host);
            published = true;
            evidence.push(`${name}: publishes port ${host}${m[2] ? ` → ${m[2]}` : ''}`);
          }
        }
      }
    }
  }

  let network: Exposure['network'] = 'unknown';
  if (published) network = 'published';
  else if (listenLocalOnly) network = 'local-only';
  else if (ports.size) network = 'published';
  if (listenLocalOnly) evidence.push('app.listen binds to loopback only');
  return { network, ports: [...ports].sort((a, b) => a - b), evidence };
}
