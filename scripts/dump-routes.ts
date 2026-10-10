// Debug helper: node scripts/dump-routes.ts <projectDir>
// Prints, per module, the app identifiers, routes, mounts, exports and router export the analyzer found.
// A Go project (go.mod at the root) prints the Go analyzer's entry points instead.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeProject } from '../packages/engine/src/graph/js/project.ts';
import { analyzeGoProject } from '../packages/engine/src/graph/go/project.ts';
import { readGoModules } from '../packages/engine/src/graph/go/gomod.ts';

const dir = process.argv[2]!;
if (existsSync(join(dir, 'go.mod'))) {
  const installed = new Set(readGoModules(dir).flatMap((m) => m.requires.map((r) => r.path)));
  const g = await analyzeGoProject(dir, { installed });
  const byFile = new Map<string, typeof g.entryPoints>();
  for (const e of g.entryPoints) (byFile.get(e.file) ?? byFile.set(e.file, []).get(e.file)!).push(e);
  for (const [file, eps] of byFile) {
    const m = g.modules.get(file);
    console.log(`== ${file}  app=[${[...(m?.appIdents ?? [])].join(',')}] root=${m?.isRootApp ?? false}`);
    for (const e of eps) console.log(`   ${e.method.padEnd(6)} ${e.path.padEnd(36)} ${e.authenticated ? 'auth [' + e.guards.join(', ').slice(0, 60) + ']' : 'noauth'} handlers=${e.handlerIds.length}${e.unresolvedHandlers ? ' ?' + e.unresolvedHandlers.join(',') : ''}${e.mounted ? '' : ' (unmounted)'}`);
  }
  console.log(`entry points: ${g.entryPoints.length} (${g.modules.size} files, ${g.functions.size} functions, listenLocalOnly=${g.listenLocalOnly})`);
  console.log(`packages imported: ${[...g.packagesImported.keys()].sort().join(', ')}`);
} else {
  const g = analyzeProject(dir);
  for (const m of g.modules.values()) {
    if (!m.routes.length && !m.appIdents.size && !m.autoload.length) continue;
    console.log(`== ${m.rel}  app=[${[...m.appIdents].join(',')}] root=${m.isRootApp} exportsRouter=${m.exportsRouter ?? '-'} exports=[${[...m.exports.keys()].join(',')}]`);
    for (const r of m.routes) console.log(`   ${r.method.toUpperCase().padEnd(6)} ${r.path.padEnd(28)} on=${r.app} guards=[${r.guards.join(',')}] handlers=${r.handlerIds.length} unresolved=[${r.unresolved.join(',')}]${r.mountLocal ? ' MOUNT ' + r.mountLocal : ''}`);
    for (const a of m.autoload) console.log(`   autoload ${a.dir} prefix=${a.prefix || '-'}`);
  }
  console.log(`entry points: ${g.entryPoints.length}`);
}
