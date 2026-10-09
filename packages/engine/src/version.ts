import { readFileSync } from 'node:fs';

/** Single source of truth: the repo root package.json. Stamped into every report. */
export function toolVersion(): string {
  const url = new URL('../../../package.json', import.meta.url);
  const pkg = JSON.parse(readFileSync(url, 'utf8')) as { version?: string };
  return pkg.version ?? '0.0.0';
}

export const USER_AGENT = `NextFix/${toolVersion()} (+https://github.com/GRCSAC/nextfix)`;
