import type { ReachPath } from '../api.ts';
import { I } from './Icons.tsx';

/** Entry point → hops → vulnerable call, as responsive HTML nodes (wraps on narrow screens). */
export function PathDiagram({ path, pkg }: { path: ReachPath; pkg: string }) {
  const e = path.entry;
  const enters = path.inputEntersAt;
  return (
    <div className="path" aria-label="Call path from entry point to vulnerable function">
      <div className="node entry">
        <span className="t">{e.method} {e.path}</span>
        <span className="s">{e.file}:{e.line}</span>
        <span className={`tag ${e.authenticated ? 'ok' : 'warn'}`}>{e.authenticated ? <><I.lock /> {e.guards.join(', ')}</> : <><I.unlock /> no auth guard</>}</span>
      </div>
      {path.hops.map((h) => (
        <Hop key={h.functionId} name={h.name} file={h.file} line={h.line} tag={enters && enters.file === h.file && enters.line === h.line ? 'request data enters here' : undefined} />
      ))}
      <span className="arrow" aria-hidden="true"><I.arrow /></span>
      <div className="node sink">
        <span className="t">{pkg}.{path.callSite.symbol}()</span>
        <span className="s">{path.callSite.file}:{path.callSite.line}</span>
        {path.callSite.userInput && <span className="tag warn">request data in arguments</span>}
      </div>
    </div>
  );
}

function Hop({ name, file, line, tag }: { name: string; file: string; line: number; tag?: string }) {
  return (
    <>
      <span className="arrow" aria-hidden="true"><I.arrow /></span>
      <div className="node">
        <span className="t">{name === '<handler>' ? 'route handler' : name}</span>
        <span className="s">{file}:{line}</span>
        {tag && <span className="tag warn">{tag}</span>}
      </div>
    </>
  );
}
