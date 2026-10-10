import { useCallback, useEffect, useState } from 'react';
import { api, type Health, type ScanDiff, type ScanMeta, type ScanReport, type Target } from './api.ts';
import { I, Wordmark } from './components/Icons.tsx';
import { Overview } from './views/Overview.tsx';
import { Findings } from './views/Findings.tsx';
import { Components } from './views/Components.tsx';
import { Evidence } from './views/Evidence.tsx';
import { Reports } from './views/Reports.tsx';
import { Apps } from './views/Apps.tsx';
import { Settings, applyTheme, readTheme, type Theme } from './views/Settings.tsx';
import { dateTime } from './format.ts';

type Page = 'overview' | 'findings' | 'components' | 'evidence' | 'reports' | 'apps' | 'settings';
const PAGES: { id: Page; label: string; icon: React.ReactNode }[] = [
  { id: 'overview', label: 'Overview', icon: <I.overview /> },
  { id: 'findings', label: 'Findings', icon: <I.findings /> },
  { id: 'components', label: 'Components', icon: <I.components /> },
  { id: 'evidence', label: 'Evidence', icon: <I.evidence /> },
  { id: 'reports', label: 'Reports', icon: <I.reports /> },
];

interface Route { page: Page; id?: string; query: Record<string, string> }

function readHash(): Route {
  const raw = location.hash.replace(/^#\/?/, '');
  const [pathPart, qs] = raw.split('?');
  const [p, ...rest] = (pathPart ?? '').split('/');
  const alias: Record<string, Page> = { exec: 'overview', fix: 'findings' };
  const page = (['overview', 'findings', 'components', 'evidence', 'reports', 'apps', 'settings'].includes(p ?? '') ? p : alias[p ?? ''] ?? 'overview') as Page;
  const query: Record<string, string> = {};
  new URLSearchParams(qs ?? '').forEach((v, k) => { query[k] = v; });
  return { page, id: rest.length ? decodeURIComponent(rest.join('/')) : undefined, query };
}

function hashFor(page: Page, id?: string, query?: Record<string, string>) {
  const qs = query && Object.keys(query).length ? `?${new URLSearchParams(query).toString()}` : '';
  return id ? `#/${page}/${encodeURIComponent(id)}${qs}` : `#/${page}${qs}`;
}

export function App() {
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [targetId, setTargetId] = useState<number | null>(() => {
    try { const v = localStorage.getItem('nextfix.target'); return v ? Number(v) : null; } catch { return null; }
  });
  const [scans, setScans] = useState<ScanMeta[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [diff, setDiff] = useState<ScanDiff | undefined>();
  const [route, setRoute] = useState<Route>(readHash());
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | undefined>();
  const [theme, setTheme] = useState<Theme>(readTheme());

  useEffect(() => { applyTheme(theme); try { localStorage.setItem('nextfix.theme', theme); } catch { /* ignore */ } }, [theme]);
  useEffect(() => {
    const onHash = () => setRoute(readHash());
    addEventListener('hashchange', onHash);
    return () => removeEventListener('hashchange', onHash);
  }, []);

  const go = useCallback((page: string, id?: string, query?: Record<string, string>) => { location.hash = hashFor(page as Page, id, query); }, []);

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
    api.health().then(setHealth).catch(() => {});
    loadTargets().then((list) => {
      const chosen = list.find((t) => t.id === targetId) ?? list[0];
      if (chosen) {
        setTargetId(chosen.id);
        loadTarget(chosen.id).catch((e) => setError(String(e.message ?? e)));
      } else setTargetId(null);
    }).catch((e) => setError(String(e.message ?? e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { try { if (targetId) localStorage.setItem('nextfix.target', String(targetId)); } catch { /* ignore */ } }, [targetId]);

  const selectTarget = async (id: number) => {
    setTargetId(id);
    setError(null);
    if (route.page === 'apps' || route.id) go('overview');
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
      go('overview');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const removeTarget = async (id: number) => {
    setError(null);
    try {
      await api.removeTarget(id);
      const list = await loadTargets();
      const next = list[0];
      if (id === targetId) {
        setTargetId(next?.id ?? null);
        if (next) await loadTarget(next.id); else { setReport(null); setScans([]); setDiff(undefined); }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
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

  const current = targets?.find((t) => t.id === targetId);
  const lastScan = scans[scans.length - 1];
  const s = report?.summary;
  const actionable = s ? s.byDecision.Act + s.byDecision.Attend : 0;
  const showTabs = !!current && !!report;

  const railItems: { id: Page; label: string; icon: React.ReactNode }[] = [
    { id: 'apps', label: 'Apps', icon: <I.grid /> },
    { id: 'settings', label: 'Settings', icon: <I.settings /> },
  ];

  return (
    <div className="shell">
      <nav className="rail" aria-label="Sections">
        <a className="rail-brand" href="#/overview" aria-label="NextFix"><Wordmark size={30} /></a>
        {railItems.map((r) => (
          <a key={r.id} className={`rail-item ${route.page === r.id ? 'active' : ''}`} href={hashFor(r.id)}>{r.icon}<span>{r.label}</span></a>
        ))}
        <span className="grow" />
        <a className="rail-item" href="https://github.com/GRCSAC/nextfix#readme" target="_blank" rel="noreferrer"><I.help /><span>Help</span></a>
      </nav>

      <div className="main">
        <header className="topbar">
          <div className="topbar-inner">
            <a className="wordmark" href="#/overview"><Wordmark size={24} /><span>Next<b>Fix</b></span></a>
            {targets && targets.length > 0 && (
              <select className="target-select" aria-label="Application" value={targetId ?? ''} onChange={(e) => selectTarget(Number(e.target.value))}>
                {targets.map((t) => <option key={t.id} value={t.id}>{t.name ?? t.dir}</option>)}
              </select>
            )}
            {showTabs && (
              <nav className="tabs" aria-label="Pages">
                {PAGES.map((p) => <a key={p.id} className={route.page === p.id ? 'active' : ''} href={hashFor(p.id)}>{p.icon}<span>{p.label}</span></a>)}
                <a className={`mobile-only ${route.page === 'apps' ? 'active' : ''}`} href={hashFor('apps')}><I.grid size={18} /><span>Apps</span></a>
                <a className={`mobile-only ${route.page === 'settings' ? 'active' : ''}`} href={hashFor('settings')}><I.settings size={18} /><span>Settings</span></a>
              </nav>
            )}
            <span className="grow" />
            <span className="version muted small">v{health?.version ?? ''}</span>
          </div>
        </header>

        <main className="page">
          {busy && <div className="banner" role="status"><span className="spin" aria-hidden="true" />{busy}</div>}
          {error && <div className="banner error-banner" role="alert">{error}</div>}

          {targets === null ? (
            <p className="empty">Loading…</p>
          ) : route.page === 'apps' || !current ? (
            targets.length === 0 && route.page !== 'apps' ? (
              <Welcome onAdd={addTarget} busy={!!busy} />
            ) : (
              <Apps targets={targets} currentId={targetId} busy={!!busy} onSelect={selectTarget} onAdd={addTarget} onRemove={removeTarget} />
            )
          ) : route.page === 'settings' ? (
            <Settings theme={theme} onTheme={setTheme} health={health} />
          ) : !report || !lastScan ? (
            <div className="hero">
              <h1>{current.name ?? current.dir}</h1>
              <p>This application has not been scanned yet.</p>
              <button type="button" className="btn primary" onClick={rescan} disabled={!!busy}><I.refresh /> Run the first scan</button>
            </div>
          ) : (
            <>
              <div className="app-head">
                <span className="icon-box big"><I.cube /></span>
                <div className="grow">
                  <div className="app-title"><h1>{report.target.name ?? report.target.dir}</h1><span className="tag ok"><I.check /> Scanned</span></div>
                  <div className="muted small">Last scan {dateTime(report.generatedAt)} · NextFix v{report.tool.version} · {report.summary.components} components</div>
                </div>
                {s && (
                  <div className="app-summary">
                    <strong>{s.findings} findings across {s.components} components. {actionable} need action.</strong>
                    <span className="muted"> The rest are unreachable, unused, or not shipped, and each one carries a reason you can hand to an auditor.</span>
                  </div>
                )}
                <button type="button" className="btn primary" onClick={rescan} disabled={!!busy}><I.refresh /> {busy ? 'Scanning…' : 'Scan again'}</button>
              </div>
              {route.page === 'overview' && <Overview report={report} scans={scans} diff={diff} go={go} />}
              {route.page === 'findings' && <Findings report={report} scanId={lastScan.id} selectedId={route.id} query={route.query} onSelect={(id) => go('findings', id, route.query)} />}
              {route.page === 'components' && <Components report={report} go={go} />}
              {route.page === 'evidence' && <Evidence report={report} scanId={lastScan.id} query={route.query} go={go} />}
              {route.page === 'reports' && <Reports report={report} scans={scans} scanId={lastScan.id} />}
            </>
          )}
        </main>
      </div>
    </div>
  );
}

function Welcome({ onAdd, busy }: { onAdd: (dir: string) => void; busy: boolean }) {
  const [dir, setDir] = useState('');
  return (
    <div className="hero">
      <div className="tagline">Find › Prioritize › Fix › Prove</div>
      <h1>From findings to fixes.</h1>
      <p>Point NextFix at a Node.js project with a <code>package-lock.json</code>, or a Python project with pinned <code>requirements.txt</code>, <code>Pipfile.lock</code>, <code>poetry.lock</code> or <code>uv.lock</code>. It works out which vulnerabilities are reachable and exposed, and tells you what to fix first.</p>
      <form onSubmit={(e) => { e.preventDefault(); if (dir.trim()) onAdd(dir.trim()); }}>
        <input type="text" value={dir} onChange={(e) => setDir(e.target.value)} placeholder="C:\path\to\your\app" aria-label="Project folder" autoFocus />
        <button type="submit" className="btn primary" disabled={busy || !dir.trim()}>Scan</button>
      </form>
      <p className="hint">Nothing leaves your machine except advisory lookups to OSV, FIRST EPSS and CISA KEV.</p>
    </div>
  );
}
