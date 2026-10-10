#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { createNextFixServer, DEFAULT_SCAN_TIMEOUT_MS } from './server.ts';
import { Store } from './store.ts';
import { toolVersion } from '../../engine/src/version.ts';

const HELP = `NextFix server ${toolVersion()}

Usage:
  nextfix-server serve [--port 8790] [--host 127.0.0.1] [--db <file>] [--target <dir>] [--no-open]
                       [--allow-host <name>]... [--scan-timeout <minutes>]

  --target <dir>          Register (and scan, if never scanned) this project on start.
  --host 0.0.0.0          Listen on all interfaces (team access). Default is loopback only.
  --allow-host <name>     Also answer to this host name or address (repeatable). localhost,
                          127.0.0.1, [::1] and the --host value are always allowed; any other
                          name in the browser's address bar is refused with 421.
  --scan-timeout <min>    Give up on a scan after this many minutes (default 20).
  --no-open               Do not open the browser.
`;

function fail(message: string): never {
  console.error(`nextfix-server: ${message}`);
  process.exit(1);
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      port: { type: 'string', default: '8790' },
      host: { type: 'string', default: '127.0.0.1' },
      db: { type: 'string' },
      target: { type: 'string', multiple: true },
      'allow-host': { type: 'string', multiple: true },
      'scan-timeout': { type: 'string' },
      open: { type: 'boolean', default: true },
      'no-open': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  if (values.help || positionals[0] !== 'serve') {
    console.log(HELP);
    return;
  }
  const port = Number(values.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail(`--port must be a number between 0 and 65535, not "${values.port}"`);
  const host = values.host!;
  let scanTimeoutMs = DEFAULT_SCAN_TIMEOUT_MS;
  if (values['scan-timeout'] !== undefined) {
    const minutes = Number(values['scan-timeout']);
    if (!Number.isFinite(minutes) || minutes <= 0) fail(`--scan-timeout must be a number of minutes greater than 0, not "${values['scan-timeout']}"`);
    scanTimeoutMs = minutes * 60_000;
  }

  const store = new Store(values.db);
  const log = (m: string) => console.error(`· ${m}`);
  const server = createNextFixServer({ store, log, host, allowHosts: values['allow-host'] ?? [], scanTimeoutMs });

  for (const dir of values.target ?? []) {
    const t = store.upsertTarget(resolve(dir));
    if (!store.listScans(t.id).length) {
      log(`first scan of ${t.dir} will run from the dashboard`);
    }
  }

  server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') fail(`Port ${port} is in use; try --port ${port + 1}`);
    if (err.code === 'EACCES') fail(`Port ${port} needs elevated rights; try --port ${Math.max(port, 1024) + 1}`);
    fail(`cannot listen on ${host}:${port}: ${err.message}`);
  });
  server.listen(port, host, () => {
    const actualPort = (server.address() as { port: number }).port;
    const url = `http://${host === '0.0.0.0' || host === '::' ? '127.0.0.1' : host.includes(':') ? `[${host}]` : host}:${actualPort}`;
    console.log(`NextFix ${toolVersion()} — dashboards at ${url}`);
    if (values.open && !values['no-open']) openBrowser(url);
  });
  const shutdown = () => {
    server.close();
    try {
      store.releaseLocks();
      store.close();
    } catch {
      /* already closed */
    }
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

// A crash must be visible: log one line and exit non-zero instead of dying silently.
process.on('uncaughtException', (err: unknown) => {
  console.error(`nextfix-server: unexpected error, exiting: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
process.on('unhandledRejection', (reason: unknown) => {
  console.error(`nextfix-server: unhandled promise rejection, exiting: ${reason instanceof Error ? reason.message : String(reason)}`);
  process.exit(1);
});

main().catch((err: unknown) => {
  console.error(`nextfix-server: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
