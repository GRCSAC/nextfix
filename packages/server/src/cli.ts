#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { createNextFixServer, DEFAULT_SCAN_TIMEOUT_MS } from './server.ts';
import { Store } from './store.ts';
import { checkPassword, displayNameOf, hashPassword, normalizeUsername } from './auth/local.ts';
import { isRole } from './auth/roles.ts';
import { toolVersion } from '../../engine/src/version.ts';
import './features/index.ts';
import { closeFeatureDbs, featureDb } from './features/all.ts';
import { startScheduler } from './features/schedule.ts';

const HELP = `NextFix server ${toolVersion()}

Usage:
  nextfix-server serve [--port 8790] [--host 127.0.0.1] [--db <file>] [--target <dir>] [--no-open]
                       [--allow-host <name>]... [--scan-timeout <minutes>]
                       [--secure-cookies] [--allow-open]
  nextfix-server user add <name> --role admin|analyst|viewer [--display-name <text>] [--db <file>]
  nextfix-server user password <name> [--db <file>]

  --target <dir>          Register (and scan, if never scanned) this project on start.
  --host 0.0.0.0          Listen on all interfaces (team access). Default is loopback only.
  --allow-host <name>     Also answer to this host name or address (repeatable). localhost,
                          127.0.0.1, [::1] and the --host value are always allowed; any other
                          name in the browser's address bar is refused with 421.
  --scan-timeout <min>    Give up on a scan after this many minutes (default 20).
  --secure-cookies        Mark the session cookie Secure (use behind TLS).
  --allow-open            No sign-in at all: everyone on this machine is an admin. Loopback only.
  --no-open               Do not open the browser.

Until the first admin exists the server answers only on this machine, and the dashboard asks
for that admin's name and password. "user add" and "user password" are the recovery path when
nobody can sign in; both read the password from stdin, never from the command line.
`;

function fail(message: string): never {
  console.error(`nextfix-server: ${message}`);
  process.exit(1);
}

/** Read a password from stdin: hidden typing on a terminal, the first line when piped. */
async function readPassword(prompt: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const c of stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString('utf8').split(/\r?\n/)[0] ?? '';
  }
  process.stderr.write(prompt);
  return new Promise((resolvePassword, reject) => {
    let typed = '';
    const cleanup = () => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.off('data', onData);
      process.stderr.write('\n');
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') {
          cleanup();
          resolvePassword(typed);
          return;
        }
        if (ch === '') {
          cleanup();
          reject(new Error('cancelled'));
          return;
        }
        if (ch === '' || ch === '\b') typed = typed.slice(0, -1);
        else typed += ch;
      }
    };
    stdin.setRawMode(true);
    stdin.setEncoding('utf8');
    stdin.resume();
    stdin.on('data', onData);
  });
}

async function promptPasswordTwice(): Promise<string> {
  const first = await readPassword('Password: ');
  if (!process.stdin.isTTY) return first;
  const second = await readPassword('Again: ');
  if (first !== second) fail('the passwords do not match');
  return first;
}

async function userCommand(action: string | undefined, name: string | undefined, values: { db?: string; role?: string; 'display-name'?: string }) {
  if (action !== 'add' && action !== 'password') fail('usage: nextfix-server user add <name> --role <role> | user password <name>');
  if (!name) fail(`usage: nextfix-server user ${action} <name>`);
  let username: string;
  try {
    username = normalizeUsername(name);
  } catch (err) {
    return fail(err instanceof Error ? err.message : String(err));
  }
  const store = new Store(values.db);
  try {
    if (action === 'add') {
      const role = values.role ?? 'viewer';
      if (!isRole(role)) fail('--role must be admin, analyst or viewer');
      if (store.getUserByUsername(username)) fail(`a user named ${username} already exists; use "user password ${username}" to reset their password`);
      const password = checkPassword(await promptPasswordTwice());
      const user = store.createUser({ username, displayName: displayNameOf(values['display-name'], username), role, passwordHash: await hashPassword(password), source: 'local' });
      store.addAudit({ userId: null, username: 'cli', action: 'user.create', target: `user:${user.id}`, detail: { username, role, via: 'cli' }, ip: null });
      console.log(`Created ${role} ${username}`);
    } else {
      const user = store.getUserByUsername(username);
      if (!user) fail(`no user named ${username}`);
      const password = checkPassword(await promptPasswordTwice());
      store.setPasswordHash(user.id, await hashPassword(password));
      store.deleteUserSessions(user.id);
      store.clearLoginFailures(username);
      store.addAudit({ userId: null, username: 'cli', action: 'user.password', target: `user:${user.id}`, detail: { by: 'cli' }, ip: null });
      console.log(`Password for ${username} replaced; their sessions were ended`);
    }
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  } finally {
    store.close();
  }
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
      'secure-cookies': { type: 'boolean', default: false },
      'allow-open': { type: 'boolean', default: false },
      role: { type: 'string' },
      'display-name': { type: 'string' },
      open: { type: 'boolean', default: true },
      'no-open': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  if (positionals[0] === 'user' && !values.help) return userCommand(positionals[1], positionals[2], values);
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
  const allowOpen = values['allow-open'] === true;
  const server = createNextFixServer({ store, log, host, allowHosts: values['allow-host'] ?? [], scanTimeoutMs, allowOpen, secureCookies: values['secure-cookies'] === true });
  // Scheduled scans, the nightly re-decide pass and the weekly digest run beside the server.
  const scheduler = startScheduler({ db: featureDb(store.path), runScan: server.nextfix.runScan, redecide: server.nextfix.redecide, log });

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
    if (allowOpen) {
      console.error('WARNING: --allow-open is set. There is no sign-in: anyone who can reach this machine locally is an admin.');
      console.error('         Connections from other machines are refused. Drop the flag to use accounts.');
    } else if (store.countUsers() === 0) {
      console.error(`No accounts yet: open ${url} on this machine to create the first admin. Other machines are refused until then.`);
    }
    if (values.open && !values['no-open']) openBrowser(url);
  });
  const shutdown = () => {
    scheduler.stop();
    server.close();
    try {
      store.releaseLocks();
      store.close();
      closeFeatureDbs();
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
