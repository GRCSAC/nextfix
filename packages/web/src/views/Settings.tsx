import { useEffect, useState } from 'react';
import { api, type AuthMode, type Health, type Integrations, type Role, type Settings as SettingsValues, type TicketKind, type User } from '../api.ts';
import { I } from '../components/Icons.tsx';
import { UsersPage } from './Users.tsx';
import { SsoPage } from './Sso.tsx';
import { DigestPage } from './Digest.tsx';
import { AuditPage } from './Audit.tsx';

export type SettingsSection = 'general' | 'users' | 'sso' | 'digest' | 'audit';
export const SETTINGS_SECTIONS: { id: SettingsSection; label: string; admin: boolean }[] = [
  { id: 'general', label: 'General', admin: false },
  { id: 'users', label: 'Users & access', admin: true },
  { id: 'sso', label: 'Single sign-on', admin: true },
  { id: 'digest', label: 'Weekly digest', admin: true },
  { id: 'audit', label: 'Audit log', admin: true },
];

export type Theme = 'dark' | 'light' | 'system';

export function applyTheme(t: Theme) {
  const root = document.documentElement;
  if (t === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', t);
}

export function readTheme(): Theme {
  try {
    const v = localStorage.getItem('nextfix.theme');
    return v === 'light' || v === 'system' ? v : 'dark';
  } catch {
    return 'dark';
  }
}

interface Props {
  theme: Theme;
  onTheme: (t: Theme) => void;
  health?: Health;
  /** The app owns the integrations state; this page edits it and asks for a refetch. */
  integrations: Integrations;
  onIntegrationsChange: () => void;
  settings?: SettingsValues;
  onSettingsChange: (s: SettingsValues) => void;
  role: Role;
  authMode: AuthMode;
  me?: User;
  section: SettingsSection;
  go: (page: string, id?: string) => void;
}

/** Settings is one page with sections in the hash (`#/settings/users`); the admin ones are hidden from other roles. */
export function Settings({ theme, onTheme, health, integrations, onIntegrationsChange, settings, onSettingsChange, role, authMode, me, section, go }: Props) {
  const admin = role === 'admin';
  const sections = SETTINGS_SECTIONS.filter((s) => admin || !s.admin);
  const current = sections.some((s) => s.id === section) ? section : 'general';
  return (
    <div className="stack">
      <nav className="subnav" aria-label="Settings sections">
        {sections.map((s) => <a key={s.id} href={s.id === 'general' ? '#/settings' : `#/settings/${s.id}`} className={current === s.id ? 'active' : ''} aria-current={current === s.id ? 'page' : undefined}>{s.label}</a>)}
      </nav>
      {current === 'users' && <UsersPage me={me} />}
      {current === 'sso' && <SsoPage />}
      {current === 'digest' && <DigestPage />}
      {current === 'audit' && <AuditPage />}
      {current === 'general' && <General theme={theme} onTheme={onTheme} health={health} integrations={integrations} onIntegrationsChange={onIntegrationsChange} settings={settings} onSettingsChange={onSettingsChange} role={role} authMode={authMode} go={go} />}
    </div>
  );
}

function General({ theme, onTheme, health, integrations, onIntegrationsChange, settings, onSettingsChange, role, authMode, go }: Omit<Props, 'section' | 'me'>) {
  const admin = role === 'admin';
  return (
    <div className="stack">
      <section className="card">
        <h2>Appearance</h2>
        <div className="seg" role="group" aria-label="Theme">
          {(['dark', 'light', 'system'] as Theme[]).map((t) => (
            <button key={t} type="button" aria-pressed={theme === t} onClick={() => onTheme(t)}>{t === 'system' ? 'Match OS' : t.charAt(0).toUpperCase() + t.slice(1)}</button>
          ))}
        </div>
      </section>

      <section className="card">
        <h2>Integrations</h2>
        <p className="sub">Create tracker issues straight from a finding. Credentials are stored only in this machine's NextFix database.</p>
        {!admin && <p className="hint"><I.lock /> Only an administrator can change integrations; the fields below are read-only for you.</p>}
        <div className={`grid two ${admin ? '' : 'readonly'}`} style={{ marginTop: 12 }}>
          <IntegrationForm
            kind="github"
            title="GitHub Issues"
            configured={!!integrations.github}
            fields={[
              { name: 'repo', label: 'Repository (owner/name)', value: integrations.github?.repo ?? '', placeholder: 'acme/shop-api' },
              { name: 'token', label: 'Token', value: '', placeholder: integrations.github?.hasToken ? '•••••••• (saved; leave blank to keep)' : 'fine-grained token with Issues: write', secret: true },
              { name: 'labels', label: 'Labels (comma-separated)', value: (integrations.github?.labels ?? []).join(', '), placeholder: 'security, nextfix' },
            ]}
            onSaved={onIntegrationsChange}
          />
          <IntegrationForm
            kind="jira"
            title="Jira Cloud"
            configured={!!integrations.jira}
            fields={[
              { name: 'baseUrl', label: 'Site URL', value: integrations.jira?.baseUrl ?? '', placeholder: 'https://acme.atlassian.net' },
              { name: 'email', label: 'Account email', value: integrations.jira?.email ?? '', placeholder: 'you@acme.com' },
              { name: 'apiToken', label: 'API token', value: '', placeholder: integrations.jira?.hasToken ? '•••••••• (saved; leave blank to keep)' : 'from id.atlassian.com → Security → API tokens', secret: true },
              { name: 'projectKey', label: 'Project key', value: integrations.jira?.projectKey ?? '', placeholder: 'SEC' },
              { name: 'issueType', label: 'Issue type', value: integrations.jira?.issueType ?? 'Task', placeholder: 'Task' },
            ]}
            onSaved={onIntegrationsChange}
          />
        </div>
      </section>

      <section className="card">
        <h2>Scan history</h2>
        <p className="sub">How long a finding may stay open before it counts as past its SLA, and how many scans are kept per application.</p>
        {!admin && <p className="hint"><I.lock /> Only an administrator can change these.</p>}
        <div className={admin ? '' : 'readonly'}><HistoryForm settings={settings} onSaved={onSettingsChange} /></div>
      </section>

      <section className="card">
        <h2>Data</h2>
        <dl className="kv">
          <dt>Scan history</dt><dd className="mono">{health?.dbPath ?? '—'}</dd>
          <dt>Advisory cache</dt><dd className="mono">{health?.cachePath ?? '—'}</dd>
          <dt>Version</dt><dd>NextFix {health?.version ?? ''}</dd>
        </dl>
        <p className="hint">Scans run on this machine. The only outbound requests are advisory lookups to OSV, FIRST EPSS and CISA KEV, fix-commit reads from GitHub, and the trackers you configure above.</p>
      </section>

      <section className="card">
        <h2>Team access</h2>
        {authMode === 'none' ? (
          <>
            <p className="sub">Sign-in is off on this server: everyone who can reach it has administrator rights. Users, single sign-on, the digest and the audit log can still be set up here.</p>
            <p className="hint"><I.info /> Sharing without sign-in exposes scan results and the use of tracker credentials to anyone on that network.</p>
          </>
        ) : (
          <p className="sub">{admin ? 'Manage people, roles, API tokens and single sign-on under ' : 'People, roles and single sign-on are managed by an administrator under '}<button type="button" className="link" onClick={() => go('settings', 'users')} disabled={!admin}>Users &amp; access</button>.</p>
        )}
      </section>
    </div>
  );
}

interface Field { name: string; label: string; value: string; placeholder?: string; secret?: boolean }

/**
 * Saved values arrive through `fields`; a refetch updates only the inputs the user has not
 * typed in, so a save or a background refresh never wipes what is being edited.
 */
function IntegrationForm({ kind, title, configured, fields, onSaved }: { kind: TicketKind; title: string; configured: boolean; fields: Field[]; onSaved: () => void }) {
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(fields.map((f) => [f.name, f.value])));
  const [touched, setTouched] = useState<Set<string>>(() => new Set());
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const saved = JSON.stringify(fields.map((f) => f.value));
  useEffect(() => {
    setValues((v) => {
      const next = { ...v };
      for (const f of fields) if (!touched.has(f.name)) next[f.name] = f.value;
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [saved]);

  const edit = (name: string, value: string) => {
    setValues((v) => ({ ...v, [name]: value }));
    setTouched((t) => new Set(t).add(name));
  };

  const save = async (thenTest: boolean) => {
    setBusy(true);
    setStatus(null);
    try {
      const body: Record<string, string> = {};
      for (const f of fields) if (values[f.name] || !f.secret) body[f.name] = values[f.name] ?? '';
      await api.saveIntegration(kind, body);
      if (thenTest) {
        const r = await api.testIntegration(kind);
        setStatus({ ok: true, text: r.message });
      } else setStatus({ ok: true, text: 'Saved' });
      // What was typed is now what is saved; secrets are never echoed back, so clear them.
      setTouched(new Set());
      setValues((v) => {
        const next = { ...v };
        for (const f of fields) if (f.secret) next[f.name] = '';
        return next;
      });
      onSaved();
    } catch (e) {
      setStatus({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    setBusy(true);
    try {
      await api.removeIntegration(kind);
      setValues(Object.fromEntries(fields.map((f) => [f.name, ''])));
      setTouched(new Set());
      setStatus({ ok: true, text: 'Removed' });
      onSaved();
    } catch (e) {
      setStatus({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="integration" onSubmit={(e) => { e.preventDefault(); save(false); }}>
      <div className="card-head"><h3>{title}</h3>{configured && <span className="tag ok"><I.check /> configured</span>}</div>
      {fields.map((f) => (
        <label key={f.name} className="field">
          <span>{f.label}</span>
          <input type={f.secret ? 'password' : 'text'} value={values[f.name] ?? ''} placeholder={f.placeholder} onChange={(e) => edit(f.name, e.target.value)} autoComplete="off" />
        </label>
      ))}
      <div className="actions">
        <button type="submit" className="btn small primary" disabled={busy}>Save</button>
        <button type="button" className="btn small" disabled={busy} onClick={() => save(true)}>Save and test</button>
        {configured && <button type="button" className="btn small ghost" disabled={busy} onClick={remove}>Remove</button>}
        {status && <span className={status.ok ? 'hint' : 'error'} role="status">{status.text}</span>}
      </div>
    </form>
  );
}

const HISTORY_FIELDS: { key: keyof SettingsValues; label: string; hint: string }[] = [
  { key: 'slaActDays', label: 'Fix now within (days)', hint: 'Act findings older than this count as past SLA' },
  { key: 'slaAttendDays', label: 'Fix next cycle within (days)', hint: 'Attend findings older than this count as past SLA' },
  { key: 'retentionScans', label: 'Scans kept per application', hint: 'Older scans are removed when a new one is stored' },
];

function HistoryForm({ settings, onSaved }: { settings?: SettingsValues; onSaved: (s: SettingsValues) => void }) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [touched, setTouched] = useState<Set<string>>(() => new Set());
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!settings) return;
    setValues((v) => {
      const next = { ...v };
      for (const f of HISTORY_FIELDS) if (!touched.has(f.key)) next[f.key] = String(settings[f.key]);
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings]);

  const save = async () => {
    setBusy(true);
    setStatus(null);
    try {
      const patch: Partial<SettingsValues> = {};
      for (const f of HISTORY_FIELDS) {
        const n = Number(values[f.key]);
        if (!Number.isInteger(n) || n < 1 || n > 3650) throw new Error(`${f.label}: enter a whole number between 1 and 3650`);
        patch[f.key] = n;
      }
      const saved = await api.saveSettings(patch);
      setTouched(new Set());
      setStatus({ ok: true, text: 'Saved' });
      onSaved(saved);
    } catch (e) {
      setStatus({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="history-form" onSubmit={(e) => { e.preventDefault(); save(); }}>
      <div className="grid three">
        {HISTORY_FIELDS.map((f) => (
          <label key={f.key} className="field">
            <span>{f.label}</span>
            <input type="number" inputMode="numeric" min={1} max={3650} value={values[f.key] ?? ''} onChange={(e) => { setValues((v) => ({ ...v, [f.key]: e.target.value })); setTouched((t) => new Set(t).add(f.key)); }} disabled={!settings} />
            <span className="hint">{f.hint}</span>
          </label>
        ))}
      </div>
      <div className="actions">
        <button type="submit" className="btn small primary" disabled={busy || !settings}>Save</button>
        {status && <span className={status.ok ? 'hint' : 'error'} role="status">{status.text}</span>}
      </div>
    </form>
  );
}
