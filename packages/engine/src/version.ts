import { readAsset } from './assets.ts';

let cached: string | undefined;

/** Single source of truth: the repo root package.json (embedded in the executable). Stamped into every report. */
export function toolVersion(): string {
  if (cached === undefined) {
    const pkg = JSON.parse(readAsset('package.json').toString('utf8')) as { version?: string };
    cached = pkg.version ?? '0.0.0';
  }
  return cached;
}

export const USER_AGENT = `NextFix/${toolVersion()} (+https://github.com/GRCSAC/nextfix)`;
