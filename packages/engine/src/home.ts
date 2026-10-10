import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * The folder NextFix keeps its state in: the scan history database, the advisory cache and
 * derived symbols. `~/.nextfix` unless NEXTFIX_HOME says otherwise (the Docker image sets it
 * to the /data volume).
 */
export function nextfixHome(): string {
  const env = process.env.NEXTFIX_HOME?.trim();
  return env ? env : join(homedir(), '.nextfix');
}
