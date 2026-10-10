#!/usr/bin/env node
// Entry point of the single executable and of the Docker image: one program, both command
// families. `scan`, `symbols` and `--version` belong to the engine CLI; `serve` and `user`
// to the server. Each CLI prints its own detailed help (`nextfix scan --help`,
// `nextfix serve --help`). From the repository: `node packaging/entry.ts <command> ...`.

const SERVER_COMMANDS = new Set(['serve', 'user']);

const USAGE = `NextFix — tells you what to fix next, and why.

Usage:
  nextfix scan <dir> [options]           Scan a project, print the decisions (nextfix scan --help)
  nextfix serve [--port 8790] [options]  Start the dashboards on this machine (nextfix serve --help)
  nextfix user add|password <name>       Manage accounts without the dashboard
  nextfix symbols <subcommand>           Derived vulnerable-symbol entries on this machine
  nextfix --version

Docs: https://github.com/GRCSAC/nextfix (docs/INSTALL.md for installation and upgrades)
`;

const command = process.argv[2];
if (command === undefined || command === 'help' || ((command === '--help' || command === '-h') && process.argv.length === 3)) {
  console.log(USAGE);
  process.exitCode = command === undefined ? 2 : 0;
} else if (SERVER_COMMANDS.has(command)) {
  void import('../packages/server/src/cli.ts');
} else {
  void import('../packages/engine/src/cli.ts');
}
