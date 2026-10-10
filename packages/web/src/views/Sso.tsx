import { useEffect, useState } from 'react';
import { api, type OidcPreset, type OidcProvider, type Role } from '../api.ts';
import { I } from '../components/Icons.tsx';
import { Modal } from '../components/Modal.tsx';

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));
const ROLES: Role[] = ['admin', 'analyst', 'viewer'];

interface Preset { id: OidcPreset; name: string; issuer: (v: string) => string; input?: { label: string; placeholder: string; hint: string }; help: string }
const PRESETS: Preset[] = [
  { id: 'entra', name: 'Microsoft Entra ID', issuer: (t) => `https://login.microsoftonline.com/${t.trim()}/v2.0`, input: { label: 'Tenant ID', placeholder: '9a1f2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d', hint: 'Directory (tenant) ID from the app registration overview.' }, help: 'Register an app in Entra, add the redirect URI from this card as a Web platform, and create a client secret.' },
  { id: 'google', name: 'Google Workspace', issuer: () => 'https://accounts.google.com', help: 'Create an OAuth client (Web application) in Google Cloud and add the redirect URI from this card. Limit sign-in to your domain with Allowed domains.' },
  { id: 'okta', name: 'Okta', issuer: (d) => `https://${d.trim().replace(/^https?:\/\//, '').replace(/\/+$/, '')}`, input: { label: 'Org domain', placeholder: 'acme.okta.com', hint: 'Your Okta org URL without https://.' }, help: 'Create an OIDC Web application in Okta with the redirect URI from this card.' },
  { id: 'generic', name: 'Other OpenID Connect', issuer: (u) => u.trim(), input: { label: 'Issuer URL', placeholder: 'https://sso.example.com/realms/acme', hint: 'The server must publish /.well-known/openid-configuration under this URL.' }, help: 'Keycloak, Auth0, Authentik, Dex and any other OpenID Connect provider.' },
];

const PRESET_NAME = Object.fromEntries(PRESETS.map((p) => [p.id, p.name])) as Record<OidcPreset, string>;

/** Settings → Single sign-on: one card per provider, add from a preset, save all at once. */
export function SsoPage() {
  const [providers, setProviders] = useState<OidcProvider[] | null>(null);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [adding, setAdding] = useState(false);
  const [removeId, setRemoveId] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  useEffect(() => { api.oidcSettings().then((s) => setProviders(s.providers)).catch((e) => setStatus({ ok: false, text: message(e) })); }, []);

  const edit = (id: string, patch: Partial<OidcProvider>) => { setProviders((l) => (l ?? []).map((p) => (p.id === id ? { ...p, ...patch } : p))); setDirty(true); };
  const save = async () => {
    if (!providers) return;
    setBusy(true);
    setStatus(null);
    try {
      const body = providers.map((p) => ({ ...p, clientSecret: secrets[p.id] || undefined }));
      const saved = await api.saveOidcSettings({ providers: body });
      setProviders(saved.providers);
      setSecrets({});
      setDirty(false);
      setStatus({ ok: true, text: 'Saved. Secrets are stored and never shown again.' });
    } catch (e) {
      setStatus({ ok: false, text: message(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <section className="card">
        <div className="card-head">
          <div><h2>Single sign-on</h2><p className="sub">Let people sign in with the identity provider they already use. Roles can come from a claim; new users get the default role.</p></div>
          <button type="button" className="btn small primary" onClick={() => setAdding(true)}><I.plus /> Add provider</button>
        </div>
        {!providers ? <p className="empty">Loading…</p> : providers.length === 0 ? <p className="empty">No provider yet. Add one to show a “Sign in with …” button on the sign-in page.</p> : (
          <div className="stack">
            {providers.map((p) => <ProviderCard key={p.id} p={p} secret={secrets[p.id] ?? ''} onSecret={(v) => { setSecrets((s) => ({ ...s, [p.id]: v })); setDirty(true); }} onEdit={(patch) => edit(p.id, patch)} onRemove={() => setRemoveId(p.id)} />)}
          </div>
        )}
        <div className="actions">
          <button type="button" className="btn primary" disabled={!providers || busy || !dirty} onClick={save}>{busy ? 'Saving…' : 'Save'}</button>
          {dirty && !busy && <span className="hint">Unsaved changes.</span>}
          {status && <span className={status.ok ? 'hint' : 'error'} role="status">{status.text}</span>}
        </div>
        <p className="hint"><I.info /> Client secrets are stored only: the server keeps them encrypted and never sends them back to the browser. Leave the field blank to keep the saved one.</p>
      </section>
      {adding && <AddProviderModal existing={(providers ?? []).map((p) => p.id)} onClose={() => setAdding(false)} onAdd={(p) => { setProviders((l) => [...(l ?? []), p]); setDirty(true); setAdding(false); }} />}
      {removeId && (
        <Modal title="Remove this provider?" onClose={() => setRemoveId(null)}>
          <p>People who signed in through it keep their accounts but will need another way to sign in. The change applies when you press Save.</p>
          <div className="actions">
            <button type="button" className="btn danger" onClick={() => { setProviders((l) => (l ?? []).filter((p) => p.id !== removeId)); setDirty(true); setRemoveId(null); }}>Remove</button>
            <button type="button" className="btn ghost" onClick={() => setRemoveId(null)}>Cancel</button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function ProviderCard({ p, secret, onSecret, onEdit, onRemove }: { p: OidcProvider; secret: string; onSecret: (v: string) => void; onEdit: (patch: Partial<OidcProvider>) => void; onRemove: () => void }) {
  const [copied, setCopied] = useState(false);
  const preset = PRESETS.find((x) => x.id === p.preset) ?? PRESETS[3]!;
  const roleMapText = Object.entries(p.roleMap ?? {}).map(([k, v]) => `${k} = ${v}`).join('\n');
  const copy = async () => { try { await navigator.clipboard.writeText(p.redirectUri); setCopied(true); setTimeout(() => setCopied(false), 1600); } catch { /* clipboard blocked */ } };
  return (
    <div className="integration provider">
      <div className="card-head">
        <div><h3>{p.name || PRESET_NAME[p.preset]}</h3><span className="muted small">{PRESET_NAME[p.preset]} · id <code>{p.id}</code></span></div>
        <button type="button" className="btn small ghost" onClick={onRemove}><I.trash /> Remove</button>
      </div>
      <div className="grid two">
        <label className="field"><span>Display name</span><input type="text" value={p.name} onChange={(e) => onEdit({ name: e.target.value })} placeholder={PRESET_NAME[p.preset]} /></label>
        <label className="field"><span>{preset.id === 'generic' ? 'Issuer URL' : 'Issuer'}</span><input type="text" value={p.issuer} onChange={(e) => onEdit({ issuer: e.target.value })} readOnly={preset.id === 'google'} className="mono" /></label>
        <label className="field"><span>Client ID</span><input type="text" value={p.clientId} onChange={(e) => onEdit({ clientId: e.target.value })} autoComplete="off" className="mono" /></label>
        <label className="field"><span>Client secret</span><input type="password" value={secret} onChange={(e) => onSecret(e.target.value)} placeholder={p.hasSecret ? '•••••••• (saved; leave blank to keep)' : 'paste the secret from the provider'} autoComplete="new-password" /></label>
        <label className="field"><span>Scopes <span className="muted">(optional)</span></span><input type="text" value={p.scopes ?? ''} onChange={(e) => onEdit({ scopes: e.target.value })} placeholder="openid profile email" className="mono" /></label>
        <label className="field"><span>Allowed email domains <span className="muted">(optional)</span></span><input type="text" value={(p.allowedDomains ?? []).join(', ')} onChange={(e) => onEdit({ allowedDomains: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} placeholder="acme.com, acme.co.uk" /><span className="hint">Anyone else is refused even if the provider signs them in.</span></label>
        <label className="field"><span>Role claim <span className="muted">(optional)</span></span><input type="text" value={p.roleClaim ?? ''} onChange={(e) => onEdit({ roleClaim: e.target.value })} placeholder="groups" className="mono" /><span className="hint">The ID-token claim that carries group or role names.</span></label>
        <label className="field"><span>Default role</span><select value={p.defaultRole} onChange={(e) => onEdit({ defaultRole: e.target.value as Role })}>{ROLES.map((r) => <option key={r} value={r}>{r}</option>)}</select><span className="hint">Given to new users and to anyone the role map does not match.</span></label>
        <label className="field span-2"><span>Role map <span className="muted">(optional, one per line: claim value = role)</span></span><textarea rows={3} value={roleMapText} onChange={(e) => onEdit({ roleMap: parseRoleMap(e.target.value) })} placeholder={'sec-admins = admin\nsec-analysts = analyst'} className="mono" /></label>
      </div>
      <div className="redirect">
        <span className="field-label">Redirect URI <span className="muted">(add this to the provider)</span></span>
        <div className="redirect-row"><code className="grow">{p.redirectUri}</code><button type="button" className="btn small" onClick={copy}>{copied ? <><I.check /> Copied</> : <><I.copy /> Copy</>}</button></div>
      </div>
      <p className="hint">{preset.help}</p>
    </div>
  );
}

function parseRoleMap(text: string): Record<string, Role> {
  const out: Record<string, Role> = {};
  for (const line of text.split('\n')) {
    const [k, v] = line.split('=').map((s) => s.trim());
    if (k && v && ROLES.includes(v as Role)) out[k] = v as Role;
  }
  return out;
}

function AddProviderModal({ existing, onClose, onAdd }: { existing: string[]; onClose: () => void; onAdd: (p: OidcProvider) => void }) {
  const [preset, setPreset] = useState<Preset>(PRESETS[0]!);
  const [value, setValue] = useState('');
  const [clientId, setClientId] = useState('');
  const ready = clientId.trim() && (!preset.input || value.trim());
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    let id = preset.id as string;
    let n = 2;
    while (existing.includes(id)) id = `${preset.id}-${n++}`;
    onAdd({ id, name: preset.name, preset: preset.id, issuer: preset.issuer(value), clientId: clientId.trim(), hasSecret: false, scopes: 'openid profile email', defaultRole: 'viewer', redirectUri: `${location.origin}/api/auth/oidc/${id}/callback` });
  };
  return (
    <Modal title="Add a sign-in provider" onClose={onClose}>
      <form className="auth-form" onSubmit={submit} noValidate>
        <fieldset className="choice-set">
          <legend>Provider</legend>
          {PRESETS.map((p) => <label key={p.id} className={`choice ${preset.id === p.id ? 'on' : ''}`}><input type="radio" name="preset" checked={preset.id === p.id} onChange={() => { setPreset(p); setValue(''); }} /><span><strong>{p.name}</strong><span className="muted small">{p.help}</span></span></label>)}
        </fieldset>
        {preset.input && <label className="field"><span>{preset.input.label}</span><input type="text" value={value} onChange={(e) => setValue(e.target.value)} placeholder={preset.input.placeholder} className="mono" autoComplete="off" /><span className="hint">{preset.input.hint}</span></label>}
        <label className="field"><span>Client ID</span><input type="text" value={clientId} onChange={(e) => setClientId(e.target.value)} className="mono" autoComplete="off" /></label>
        <p className="hint">The client secret and the rest go on the provider card; the redirect URI is shown there to copy into the provider.</p>
        <div className="actions">
          <button type="submit" className="btn primary" disabled={!ready}>Add</button>
          <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Modal>
  );
}
