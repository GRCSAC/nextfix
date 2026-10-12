import { useEffect, useMemo, useState } from 'react';
import { api, type InternetReach, type MapEdge, type MapNode, type PortfolioMap, type Posture } from '../api.ts';
import { I } from '../components/Icons.tsx';
import '../map.css';

/*
 * The portfolio map: every application as a node, the services it calls as edges, the internet
 * on the left, the outside world on the right. Click an application to light up its blast
 * radius: what depends on it (breaks if it falls) and what it reaches (where an intruder goes next).
 */

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export const POSTURE_META: Record<Posture, { icon: string; cls: string; help: string }> = {
  Exposed: { icon: '▲', cls: 'act', help: 'Something needs fixing now' },
  Attention: { icon: '●', cls: 'attend', help: 'Fixes due next release cycle' },
  Contained: { icon: '◐', cls: 'watch', help: 'Only watched findings remain' },
  Clean: { icon: '✓', cls: 'good', help: 'Nothing open' },
  'Never scanned': { icon: '○', cls: 'muted', help: 'No scan yet' },
};
const RANK: Record<Posture, number> = { Exposed: 0, Attention: 1, Contained: 2, Clean: 3, 'Never scanned': 4 };
export const REACH_LABEL: Record<InternetReach, string> = { internet: 'Internet-facing', internal: 'Internal only', unknown: 'Reach not confirmed' };

const COL_W = 250;
const NODE_W = 196;
const NODE_H = 78;
const ROW_H = 104;
const PAD = 24;
const EXTERNAL_MAX = 10;

interface Placed {
  id: string;
  kind: 'internet' | 'app' | 'external';
  x: number;
  y: number;
  node?: MapNode;
  host?: string;
  external?: boolean;
  callers?: number;
}

/** Layers left to right: the internet, then applications by longest path from an entry, then outside services. */
function layout(m: PortfolioMap): { placed: Placed[]; width: number; height: number; layers: number } {
  const ids = m.nodes.map((n) => n.id);
  const callees = new Map<number, number[]>(ids.map((id) => [id, []]));
  const callers = new Map<number, number[]>(ids.map((id) => [id, []]));
  for (const e of m.edges) {
    callees.get(e.from)?.push(e.to);
    callers.get(e.to)?.push(e.from);
  }
  const hasInternet = m.internet.length > 0;
  const base = hasInternet ? 1 : 0;
  // Roots: internet-facing, or nothing calls them. Everything else is one step past its furthest caller (cycles cut by visit order).
  const layer = new Map<number, number>();
  const visiting = new Set<number>();
  const depth = (id: number): number => {
    const known = layer.get(id);
    if (known !== undefined) return known;
    if (visiting.has(id)) return base;
    visiting.add(id);
    const ins = callers.get(id) ?? [];
    const root = m.internet.includes(id) || ins.length === 0;
    const d = root ? base : Math.max(base, ...ins.map((c) => depth(c) + 1));
    visiting.delete(id);
    layer.set(id, d);
    return d;
  };
  for (const id of ids) depth(id);
  const maxLayer = Math.max(base, ...layer.values());
  const externalLayer = m.external.length ? maxLayer + 1 : maxLayer;
  const columns = new Map<number, Placed[]>();
  const put = (l: number, p: Placed) => {
    if (!columns.has(l)) columns.set(l, []);
    columns.get(l)!.push(p);
  };
  if (hasInternet) put(0, { id: 'internet', kind: 'internet', x: 0, y: 0 });
  const sorted = [...m.nodes].sort((a, b) => RANK[a.posture] - RANK[b.posture] || a.name.localeCompare(b.name));
  for (const n of sorted) put(layer.get(n.id) ?? base, { id: `app:${n.id}`, kind: 'app', x: 0, y: 0, node: n });
  for (const x of m.external.slice(0, EXTERNAL_MAX)) put(externalLayer, { id: `ext:${x.host}`, kind: 'external', x: 0, y: 0, host: x.host, external: x.external, callers: x.callers.length });
  const rows = Math.max(1, ...[...columns.values()].map((c) => c.length));
  const height = PAD * 2 + rows * ROW_H;
  const placed: Placed[] = [];
  for (const [l, col] of columns) {
    const top = PAD + ((rows - col.length) * ROW_H) / 2;
    col.forEach((p, i) => {
      p.x = PAD + l * COL_W;
      p.y = top + i * ROW_H;
      placed.push(p);
    });
  }
  return { placed, width: PAD * 2 + (externalLayer + 1) * COL_W - (COL_W - NODE_W), height, layers: externalLayer + 1 };
}

function curve(a: Placed, b: Placed): string {
  const x1 = a.x + (a.kind === 'internet' ? 120 : NODE_W);
  const y1 = a.y + NODE_H / 2;
  const x2 = b.x;
  const y2 = b.y + NODE_H / 2;
  const dx = Math.max(40, (x2 - x1) / 2);
  return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
}

export function MapView({ onOpen }: { onOpen: (id: number) => void }) {
  const [data, setData] = useState<PortfolioMap | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  useEffect(() => {
    const ac = new AbortController();
    api.portfolioMap(ac.signal).then(setData).catch((e) => { if (!ac.signal.aborted) setError(message(e)); });
    return () => ac.abort();
  }, []);
  const lay = useMemo(() => (data ? layout(data) : null), [data]);

  if (error) return <div className="card"><p className="empty">Could not load the map: {error}</p></div>;
  if (!data || !lay) return <p className="empty">Loading…</p>;
  const byId = new Map(data.nodes.map((n) => [n.id, n]));
  const sel = selected !== null ? byId.get(selected) : undefined;
  const up = new Set(sel?.upstream ?? []);
  const down = new Set(sel?.downstream ?? []);
  const place = new Map(lay.placed.map((p) => [p.id, p]));
  const edgeState = (e: MapEdge): string => {
    if (!sel) return '';
    if (e.to === sel.id || (up.has(e.to) && up.has(e.from)) || (e.to === sel.id && up.has(e.from))) return 'up';
    if (e.from === sel.id || (down.has(e.from) && down.has(e.to))) return 'down';
    return 'dim';
  };
  const nodeState = (id: number): string => {
    if (!sel) return '';
    if (id === sel.id) return 'selected';
    if (up.has(id)) return 'up';
    if (down.has(id)) return 'down';
    return 'dim';
  };
  const internetCount = data.internet.length;
  const linked = new Set(data.edges.flatMap((e) => [e.from, e.to]));
  const extEdges: { from: Placed; to: Placed }[] = [];
  for (const x of data.external.slice(0, EXTERNAL_MAX)) {
    const to = place.get(`ext:${x.host}`)!;
    for (const c of x.callers) {
      const from = place.get(`app:${c.id}`);
      if (from) extEdges.push({ from, to });
    }
  }

  return (
    <div className="stack map-page">
      <div className="app-head">
        <span className="icon-box big"><I.map size={28} /></span>
        <div className="grow">
          <h1>Map</h1>
          <div className="muted small">{data.nodes.length} application{data.nodes.length === 1 ? '' : 's'} · {data.edges.length} link{data.edges.length === 1 ? '' : 's'} between them · {internetCount} internet-facing · {data.external.length} outside service{data.external.length === 1 ? '' : 's'}</div>
        </div>
      </div>

      {!data.edges.length && !data.external.length && (
        <div className="card">
          <p className="empty">No links between applications yet. NextFix reads each application's compose files, Kubernetes manifests, <code>.env</code> and configuration files for the services it calls, and connects them to the applications that answer to those names. Scan the applications that call each other and the map draws itself.</p>
        </div>
      )}

      <div className="card map-card">
        <div className="map-scroll">
          <div className="map-canvas" style={{ width: lay.width, height: lay.height }} role="group" aria-label="Portfolio map">
            <svg className="map-edges" width={lay.width} height={lay.height} aria-hidden="true">
              <defs>
                <marker id="map-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" /></marker>
              </defs>
              {data.internet.map((id) => {
                const a = place.get('internet');
                const b = place.get(`app:${id}`);
                return a && b ? <path key={`inet-${id}`} className={`map-edge internet ${sel ? (id === sel.id ? 'selected' : 'dim') : ''}`} d={curve(a, b)} markerEnd="url(#map-arrow)" /> : null;
              })}
              {data.edges.map((e) => {
                const a = place.get(`app:${e.from}`);
                const b = place.get(`app:${e.to}`);
                return a && b ? <path key={`${e.from}-${e.to}`} className={`map-edge ${edgeState(e)}`} d={curve(a, b)} markerEnd="url(#map-arrow)"><title>{e.evidence}</title></path> : null;
              })}
              {extEdges.map(({ from, to }, i) => <path key={`x-${i}`} className={`map-edge external ${sel ? (from.node?.id === sel.id || down.has(from.node?.id ?? -1) ? 'down' : 'dim') : ''}`} d={curve(from, to)} markerEnd="url(#map-arrow)" />)}
            </svg>
            {lay.placed.map((p) => {
              if (p.kind === 'internet') return <div key={p.id} className="map-internet" style={{ left: p.x, top: p.y }}><I.globe size={18} /> Internet<span className="small muted">{internetCount} reachable</span></div>;
              if (p.kind === 'external') return <div key={p.id} className={`map-ext ${p.external ? 'public' : 'unknown'}`} style={{ left: p.x, top: p.y }} title={p.external ? 'An outside service (SaaS or partner)' : 'A service no scanned application answers to'}><span className="map-ext-host">{p.host}</span><span className="small muted">{p.external ? 'outside service' : 'not in the portfolio'} · {p.callers} caller{p.callers === 1 ? '' : 's'}</span></div>;
              const n = p.node!;
              const m = POSTURE_META[n.posture];
              const actionable = n.byDecision.Act + n.byDecision.Attend;
              return (
                <button key={p.id} type="button" className={`map-node p-${m.cls} ${nodeState(n.id)}`} style={{ left: p.x, top: p.y }} aria-pressed={selected === n.id} onClick={() => setSelected(selected === n.id ? null : n.id)} title={`${n.name}: ${n.posture}`}>
                  <span className="map-node-top"><span className="map-node-name">{n.name}</span>{n.reach === 'internet' && <I.globe size={14} className="map-node-globe" />}</span>
                  <span className="map-node-posture"><span aria-hidden="true">{m.icon}</span> {n.posture}</span>
                  <span className="map-node-foot small">{n.posture === 'Never scanned' ? 'not scanned' : `${actionable} need action`}{!linked.has(n.id) ? ' · no links found' : ''}</span>
                </button>
              );
            })}
          </div>
        </div>
        <div className="map-legend muted small">
          <span><i className="map-key edge" /> calls (arrow points at the service called)</span>
          <span><i className="map-key up" /> depends on the selected application</span>
          <span><i className="map-key down" /> reached from it</span>
          <span><I.globe size={13} /> internet-facing</span>
        </div>
      </div>

      {sel ? <BlastPanel node={sel} map={data} onOpen={onOpen} onClose={() => setSelected(null)} /> : (
        <p className="hint">Click an application to see its blast radius: what depends on it and what it can reach. Hover a link for the file that declared it.</p>
      )}

      <ul className="map-list" aria-label="Applications and their connections">
        {data.nodes.map((n) => <li key={n.id}><ConnectionRow node={n} map={data} onOpen={onOpen} /></li>)}
      </ul>
    </div>
  );
}

function names(ids: number[], map: PortfolioMap): string {
  const by = new Map(map.nodes.map((n) => [n.id, n]));
  return ids.map((id) => by.get(id)?.name ?? `#${id}`).join(', ');
}

/** What the selection means in words: who falls with it, where an intruder goes next, and what it talks to outside. */
function BlastPanel({ node, map, onOpen, onClose }: { node: MapNode; map: PortfolioMap; onOpen: (id: number) => void; onClose: () => void }) {
  const m = POSTURE_META[node.posture];
  const direct = map.edges.filter((e) => e.from === node.id).map((e) => e.to);
  const directCallers = map.edges.filter((e) => e.to === node.id).map((e) => e.from);
  const outside = map.external.filter((x) => x.callers.some((c) => c.id === node.id));
  const up = node.upstream.length;
  const down = node.downstream.length;
  return (
    <section className={`card blast p-${m.cls}`} aria-label={`${node.name} on the map`}>
      <div className="card-head">
        <div>
          <h2>{node.name} <span className={`posture-tag p-${m.cls}`}><span aria-hidden="true">{m.icon}</span> {node.posture}</span></h2>
          <p className="sub">{REACH_LABEL[node.reach]}{node.reachEvidence[0] ? ` · ${node.reachEvidence[0]}` : ''}{node.owner ? ` · owner ${node.owner}` : ''}</p>
        </div>
        <div className="actions">
          <button type="button" className="btn small primary" onClick={() => onOpen(node.id)}>Open overview <I.arrow /></button>
          <button type="button" className="btn ghost icon" onClick={onClose} aria-label="Close"><I.close /></button>
        </div>
      </div>
      {node.headline && <p className="blast-headline">{node.headline}</p>}
      <div className="blast-grid">
        <div className="blast-col up">
          <h3><span className="blast-n">{up}</span> depend{up === 1 ? 's' : ''} on it</h3>
          <p className="small">{up ? <>If {node.name} is compromised or down, these are affected: <strong>{names(node.upstream, map)}</strong>{directCallers.length < up ? ` (${directCallers.length} directly)` : ''}.</> : 'Nothing in the portfolio calls it.'}</p>
        </div>
        <div className="blast-col down">
          <h3><span className="blast-n">{down}</span> reached from it</h3>
          <p className="small">{down ? <>From {node.name} an intruder can reach: <strong>{names(node.downstream, map)}</strong>{direct.length < down ? ` (${direct.length} directly)` : ''}.</> : 'It calls nothing else in the portfolio.'}</p>
        </div>
        <div className="blast-col ext">
          <h3><span className="blast-n">{outside.length}</span> outside service{outside.length === 1 ? '' : 's'}</h3>
          <p className="small">{outside.length ? outside.map((x) => x.host).join(', ') : 'No outside services found in its files.'}</p>
        </div>
      </div>
      {node.reach === 'internet' && (node.posture === 'Exposed' || node.posture === 'Attention') && down > 0 && (
        <p className="blast-note">This application is internet-facing with open findings and reaches {down} other application{down === 1 ? '' : 's'}: fixing it first shortens every path on this map.</p>
      )}
    </section>
  );
}

/** One row per application for narrow screens and screen readers: the same facts as the drawing. */
function ConnectionRow({ node, map, onOpen }: { node: MapNode; map: PortfolioMap; onOpen: (id: number) => void }) {
  const m = POSTURE_META[node.posture];
  const calls = map.edges.filter((e) => e.from === node.id).map((e) => e.to);
  const calledBy = map.edges.filter((e) => e.to === node.id).map((e) => e.from);
  const outside = map.external.filter((x) => x.callers.some((c) => c.id === node.id)).map((x) => x.host);
  return (
    <button type="button" className="pf-card" onClick={() => onOpen(node.id)}>
      <span className="pf-top"><span className="pkg">{node.name}</span><span className={`posture-tag p-${m.cls}`}><span aria-hidden="true">{m.icon}</span> {node.posture}</span></span>
      <span className="pf-meta muted small">{REACH_LABEL[node.reach]}{node.reach === 'internet' ? ' · the internet reaches it' : ''}</span>
      <span className="pf-meta small">Calls: {calls.length ? names(calls, map) : 'nothing in the portfolio'}{outside.length ? `; outside: ${outside.join(', ')}` : ''}</span>
      <span className="pf-meta small">Called by: {calledBy.length ? names(calledBy, map) : 'nothing in the portfolio'}</span>
    </button>
  );
}

/** The Overview card for one application: what it calls and what calls it, from the same map. */
export function ConnectionsPanel({ targetId, go, onOpen }: { targetId: number; go: (page: string) => void; onOpen: (id: number) => void }) {
  const [data, setData] = useState<PortfolioMap | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const ac = new AbortController();
    api.portfolioMap(ac.signal).then(setData).catch((e) => { if (!ac.signal.aborted) setError(message(e)); });
    return () => ac.abort();
  }, [targetId]);
  if (error) return <p className="empty">Could not load connections: {error}</p>;
  if (!data) return <p className="empty">Loading…</p>;
  const node = data.nodes.find((n) => n.id === targetId);
  if (!node) return <p className="empty">This application is not on the map yet.</p>;
  const by = new Map(data.nodes.map((n) => [n.id, n]));
  const calls = data.edges.filter((e) => e.from === node.id);
  const calledBy = data.edges.filter((e) => e.to === node.id);
  const outside = data.external.filter((x) => x.callers.some((c) => c.id === node.id));
  const chip = (id: number) => {
    const n = by.get(id)!;
    const m = POSTURE_META[n.posture];
    return <button key={id} type="button" className={`conn-chip p-${m.cls}`} onClick={() => onOpen(id)} title={`${n.name}: ${n.posture}`}><span aria-hidden="true">{m.icon}</span> {n.name}</button>;
  };
  const total = calls.length + calledBy.length + outside.length;
  if (!total) return <div className="stack"><p className="empty">No links found in this application's compose, Kubernetes, .env or configuration files, and nothing in the portfolio names it.</p><div className="actions"><button type="button" className="btn small" onClick={() => go('map')}><I.map /> Open the map</button></div></div>;
  return (
    <div className="conn">
      <div className="conn-row"><span className="conn-label">Called by</span><span className="conn-chips">{calledBy.length ? calledBy.map((e) => chip(e.from)) : <span className="muted small">nothing in the portfolio</span>}</span></div>
      <div className="conn-row"><span className="conn-label">Calls</span><span className="conn-chips">{calls.length ? calls.map((e) => chip(e.to)) : <span className="muted small">nothing in the portfolio</span>}</span></div>
      <div className="conn-row"><span className="conn-label">Outside</span><span className="conn-chips">{outside.length ? outside.map((x) => <span key={x.host} className="conn-chip ext">{x.host}</span>) : <span className="muted small">none found</span>}</span></div>
      <p className="small muted">{node.upstream.length} application{node.upstream.length === 1 ? '' : 's'} depend{node.upstream.length === 1 ? 's' : ''} on this one in total; it reaches {node.downstream.length}.</p>
      <div className="actions"><button type="button" className="btn small" onClick={() => go('map')}><I.map /> Open the map</button></div>
    </div>
  );
}
