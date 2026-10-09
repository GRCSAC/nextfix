#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { createNextFixServer } from './server.ts';
import { Store } from './store.ts';
import { toolVersion } from '../../engine/src/version.ts';

const HELP = `NextFix server ${toolVersion()}

Usage:
  nextfix-server serve [--port 8790] [--host 127.0.0.1] [--db <file>] [--target <dir>] [--no-open]

  --target <dir>   Register (and scan, if never scanned) this project on start.
  --host 0.0.0.0   Listen on all interfaces (team access). Default is loopback only.
  --no-open        Do not open the browser.
`;

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      port: { type: 'string', default: '8790' },
      host: { type: 'string', default: '127.0.0.1' },
      db: { type: 'string' },
      target: { type: 'string', multiple: true },
      open: { type: 'boolean', default: true },
      'no-open': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  if (values.help || positionals[0] !== 'serve') {
    console.log(HELP);
    return;
  }
  const store = new Store(values.db);
  const log = (m: string) => console.error(`· ${m}`);
  const server = createNextFixServer({ store, log });
  const port = Number(values.port);
  const host = values.host!;

  for (const dir of values.target ?? []) {
    const t = store.upsertTarget(resolve(dir));
    if (!store.listScans(t.id).length) {
      log(`first scan of ${t.dir} will run from the dashboard`);
    }
  }

  server.listen(port, host, () => {
    const url = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}`;
    console.log(`NextFix ${toolVersion()} — dashboards at ${url}`);
    if (values.open && !values['no-open']) openBrowser(url);
  });
  const shutdown = () => {
    server.close();
    store.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

function openBrowser(url: string) {
  try {
    const cmd = process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : process.platform === 'darwin' ? ['open', [url]] : ['xdg-open', [url]];
    spawn(cmd[0] as string, cmd[1] as string[], { detached: true, stdio: 'ignore' }).unref();
  } catch {
    /* best effort */
  }
}

main().catch((err: unknown) => {
  console.error(`nextfix-server: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
