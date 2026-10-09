import { useCallback, useEffect, useState } from 'react';
import { api, type Finding, type ScanDiff, type ScanMeta, type ScanReport, type Target } from './api.ts';
import { Executive } from './views/Executive.tsx';
import { Remediation } from './views/Remediation.tsx';

type View = 'exec' | 'fix';

function readHash(): { view: View; findingId?: string } {
  const h = location.hash.replace(/^#\/?/, '');
  const [view, ...rest] = h.split('/');
  const findingId = rest.length ? decodeURIComponent(rest.join('/')) : undefined;
  return { view: view === 'fix' ? 'fix' : 'exec', findingId };
}

function writeHash(view: View, findingId?: string) {
  location.hash = findingId ? `#/${view}/${encodeURIComponent(findingId)}` : `#/${view}`;
}

export function App() {
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [targetId, setTargetId] = useState<number | null>(() => {
    try { const v = localStorage.getItem('nextfix.target'); return v ? Number(v) : null; } catch { return null; }
  });
  const [scans, setScans] = useState<ScanMeta[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [diff, setDiff] = useState<ScanDiff | undefined>();
  const [route, setRoute] = useState(readHash());
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState('');

  useEffect(() => {
    const onHash = () => setRoute(readHash());
    addEventListener('hashchange', onHash);
    return () => removeEventListener('hashchange', onHash);
  }, []);

  const loadTargets = useCallback(async () => {
    const list = await api.targets();
    setTargets(list);
    return list;
  }, []);

  const loadTarget = useCallback(async (id: number) => {
    const list = await api.scans(id);
    setScans(list);
    const last = list[list.length - 1];
    if (last) {
      const [r, d] = await Promise.all([api.report(last.id), api.diff(last.id)]);
      setReport(r);
      setDiff(d);
    } else {
      setReport(null);
      setDiff(undefined);
    }
  }, []);

  useEffect(() => {
    api.health().then((h) => setVersion(h.version)).catch(() => {});
    loadTargets().then((list) => {
      const chosen = list.find((t) => t.id === targetId) ?? list[0];
      if (chosen) {
        setTargetId(chosen.id);
        loadTarget(chosen.id).catch((e) => setError(String(e.message ?? e)));
      } else setTargetId(null);
    }).catch((e) => setError(String(e.message ?? e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    try { if (targetId) localStorage.setItem('nextfix.target', String(targetId)); } catch { /* ignore */ }
  }, [targetId]);

  const selectTarget = async (id: number) => {
    setTargetId(id);
    setError(null);
    writeHash(route.view);
    await loadTarget(id).catch((e) => setError(String(e.message ?? e)));
  };

  const addTarget = async (dir: string) => {
    setBusy(`Scanning ${dir}…`);
    setError(null);
    try {
      const res = await api.addTarget(dir);
      await loadTargets();
      setTargetId(res.target.id);
      await loadTarget(res.target.id);
      writeHash('exec');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const rescan = async () => {
    if (!targetId) return;
    setBusy('Scanning…');
    setError(null);
    try {
      await api.rescan(targetId);
      await loadTargets();
      await loadTarget(targetId);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const openFinding = (f: Finding) => writeHash('fix', f.id);
  const current = targets?.find((t) => t.id === targetId);
  const lastScan = scans[scans.length - 1];

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <a className="wordmark" href="#/exec" aria-label="NextFix home">
            <svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="var(--accent)" /><path d="M9 23V9l14 14V9" fill="none" stroke="#fff" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" /></svg>
            NextFix<small>{version}</small>
          </a>
          {targets && targets.length > 0 && (
            <select className="target-select" aria-label="Target" value={targetId ?? ''} onChange={(e) => selectTarget(Number(e.target.value))}>
              {targets.map((t) => <option key={t.id} value={t.id}>{t.name ?? t.dir}</option>)}
            </select>
          )}
          <span className="spacer" />
          {current && (
            <div className="seg" role="group" aria-label="View">
              <button type="button" aria-pressed={route.view === 'exec'} onClick={() => writeHash('exec')}>Executive</button>
              <button type="button" aria-pressed={route.view === 'fix'} onClick={() => writeHash('fix')}>Remediation</button>
            </div>
          )}
          {current && <button type="button" className="btn primary" onClick={rescan} disabled={!!busy}>{busy ? 'Scanning…' : 'Scan again'}</button>}
        </div>
      </header>

      <main className="page">
        {busy && <div className="banner" role="status"><span className="spin" aria-hidden="true" />{busy}</div>}
        {error && <div className="banner" role="alert" style={{ borderColor: 'var(--st-critical)' }}>{error}</div>}

        {targets === null ? (
          <p className="empty">Loading…</p>
        ) : !current ? (
          <Onboarding onAdd={addTarget} busy={!!busy} />
        ) : !report || !lastScan ? (
          <div className="hero">
            <h1>{current.name ?? current.dir}</h1>
            <p>This target has not been scanned yet.</p>
            <button type="button" className="btn primary" onClick={rescan} disabled={!!busy}>Run the first scan</button>
          </div>
        ) : route.view === 'exec' ? (
          <Executive report={report} scans={scans} diff={diff} onOpenFinding={openFinding} />
        ) : (
          <Remediation report={report} scanId={lastScan.id} selectedId={route.findingId} onSelect={(id) => writeHash('fix', id)} />
        )}

        {current && (
          <div className="footer">
            <AddTargetInline onAdd={addTarget} busy={!!busy} /> · <code>{current.dir}</code>
          </div>
        )}
      </main>
    </>
  );
}

function Onboarding({ onAdd, busy }: { onAdd: (dir: string) => void; busy: boolean }) {
  const [dir, setDir] = useState('');
  return (
    <div className="hero">
      <h1>Scanners find. NextFix decides.</h1>
      <p>Point NextFix at a Node.js project folder with a <code>package-lock.json</code>. It works out which vulnerabilities are reachable and exposed, and tells you what to fix first.</p>
      <form onSubmit={(e) => { e.preventDefault(); if (dir.trim()) onAdd(dir.trim()); }}>
        <input type="text" value={dir} onChange={(e) => setDir(e.target.value)} placeholder="C:\path\to\your\app" aria-label="Project folder" autoFocus />
        <button type="submit" className="btn primary" disabled={busy || !dir.trim()}>Scan</button>
      </form>
      <p className="hint">Nothing leaves your machine except advisory lookups to OSV, FIRST EPSS and CISA KEV.</p>
    </div>
  );
}

function AddTargetInline({ onAdd, busy }: { onAdd: (dir: string) => void; busy: boolean }) {
  const [open, setOpen] = useState(false);
  const [dir, setDir] = useState('');
  if (!open) return <a href="#" onClick={(e) => { e.preventDefault(); setOpen(true); }}>Add another target</a>;
  return (
    <form style={{ display: 'inline-flex', gap: 6 }} onSubmit={(e) => { e.preventDefault(); if (dir.trim()) { onAdd(dir.trim()); setOpen(false); } }}>
      <input type="text" value={dir} onChange={(e) => setDir(e.target.value)} placeholder="Project folder" aria-label="Project folder" />
      <button type="submit" className="btn small primary" disabled={busy}>Scan</button>
      <button type="button" className="btn small ghost" onClick={() => setOpen(false)}>Cancel</button>
    </form>
  );
}
