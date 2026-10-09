// Debug helper: node scripts/dump-routes.ts <projectDir>
// Prints, per module, the app identifiers, routes, mounts, exports and router export the analyzer found.
import { analyzeProject } from '../packages/engine/src/graph/js/project.ts';

const g = analyzeProject(process.argv[2]!);
for (const m of g.modules.values()) {
  if (!m.routes.length && !m.appIdents.size && !m.autoload.length) continue;
  console.log(`== ${m.rel}  app=[${[...m.appIdents].join(',')}] root=${m.isRootApp} exportsRouter=${m.exportsRouter ?? '-'} exports=[${[...m.exports.keys()].join(',')}]`);
  for (const r of m.routes) console.log(`   ${r.method.toUpperCase().padEnd(6)} ${r.path.padEnd(28)} on=${r.app} guards=[${r.guards.join(',')}] handlers=${r.handlerIds.length} unresolved=[${r.unresolved.join(',')}]${r.mountLocal ? ' MOUNT ' + r.mountLocal : ''}`);
  for (const a of m.autoload) console.log(`   autoload ${a.dir} prefix=${a.prefix || '-'}`);
}
console.log(`entry points: ${g.entryPoints.length}`);
