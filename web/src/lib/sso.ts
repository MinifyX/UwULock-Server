/**
 * Logging in through an OpenID Connect provider (docs/uwu-api.md §19), as the web vault and the
 * admin portal do it — the same way Bitwarden's web vault does, with `client_id=web` and the
 * connector page as the way back — and the admin portal's side of setting it up.
 *
 * The PKCE verifier and the state stay in this tab's session storage while the browser is at the
 * provider; the connector page brings code and state back to `#/sso` here.
 */

import { passwordHash } from './admin';
import { request } from './web/http';

const STARTED = 'uwulock.sso';

type Started = { state: string; verifier: string };

function random(bytes: number): string {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return base64url(data.buffer);
}

function base64url(buffer: ArrayBuffer): string {
  let text = '';
  for (const byte of new Uint8Array(buffer)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function challengeOf(verifier: string): Promise<string> {
  return base64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
}

async function prevalidate(): Promise<string> {
  const answer = await request<{ token: string }>('/identity/sso/prevalidate', { auth: false });
  return answer.token;
}

/**
 * Off to the provider. `admin`: come back to the admin portal (the connector page reads it from
 * the state).
 */
export async function startSso(target: 'vault' | 'admin'): Promise<void> {
  const token = await prevalidate();
  const verifier = random(48);
  const state = `${random(24)}${target === 'admin' ? ':admin' : ''}:clientId=web`;
  sessionStorage.setItem(STARTED, JSON.stringify({ state, verifier } satisfies Started));
  const query = new URLSearchParams({
    client_id: 'web',
    redirect_uri: `${location.origin}/sso-connector.html`,
    response_type: 'code',
    scope: 'api offline_access',
    state,
    code_challenge: await challengeOf(verifier),
    code_challenge_method: 'S256',
    response_mode: 'query',
    domain_hint: 'uwulock',
    ssoToken: token,
  });
  location.assign(`/identity/connect/authorize?${query}`);
}

/** The verifier of the login this tab started with `state`, used up; null for another. */
export function takeStarted(state: string): string | null {
  const raw = sessionStorage.getItem(STARTED);
  sessionStorage.removeItem(STARTED);
  if (!raw) return null;
  try {
    const started = JSON.parse(raw) as Started;
    return started.state === state ? started.verifier : null;
  } catch {
    return null;
  }
}

/**
 * Another client's login that opened the web vault at `#/sso?clientId=…` — Bitwarden's browser
 * extension, desktop app and CLI do that. Any SSO identifier will do here, so it goes straight on
 * to the server's authorize with the client's own redirect, state and PKCE challenge.
 */
export async function forwardSso(query: URLSearchParams): Promise<void> {
  const token = await prevalidate();
  const forwarded = new URLSearchParams({
    client_id: query.get('clientId') ?? '',
    redirect_uri: query.get('redirectUri') ?? '',
    response_type: 'code',
    scope: 'api offline_access',
    state: query.get('state') ?? '',
    code_challenge: query.get('codeChallenge') ?? '',
    code_challenge_method: 'S256',
    response_mode: 'query',
    domain_hint: query.get('identifier') ?? 'uwulock',
    ssoToken: token,
  });
  location.replace(`/identity/connect/authorize?${forwarded}`);
}

// ── The admin portal ──────────────────────────────────────

export type Signups = 'off' | 'invitation' | 'group';

export type SsoSettings = {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecretSet?: boolean;
  /** Only when it changes; left out, the stored one stays (for the same provider and client). */
  clientSecret?: string | null;
  scopes: string[];
  pkce: boolean;
  identifier: string;
  label: string;
  only: boolean;
  signups: Signups;
  userGroup: string | null;
  adminGroup: string | null;
  adminsOnlyWithSso: boolean;
  trustUnverifiedEmail: boolean;
  groupsClaim: string;
  rolesClaim: string | null;
  extensionIds?: string[];
  paired: { url: string; appId: string; manageUrl: string | null; date: string } | null;
  redirectUri?: string;
  scimUrl?: string;
  scimTokenSet?: boolean;
  scimOnDelete?: 'disable' | 'delete';
};

const base = '/uwu/v1/admin';

export const ssoSettings = () => request<SsoSettings>(`${base}/sso`);
/**
 * Whether saving `draft` over `current` changes who may log in as whom — another provider or
 * client, a new secret, unverified addresses, extensions, SSO on or off: then the server asks
 * for the admin's master password.
 */
export function ssoNeedsPassword(current: SsoSettings, draft: SsoSettings, secret: string) {
  return (
    secret !== '' ||
    current.issuer.trim().replace(/\/+$/, '') !== draft.issuer.trim().replace(/\/+$/, '') ||
    current.clientId.trim() !== draft.clientId.trim() ||
    Boolean(current.trustUnverifiedEmail) !== Boolean(draft.trustUnverifiedEmail) ||
    JSON.stringify(current.extensionIds ?? []) !==
      JSON.stringify(
        (draft.extensionIds ?? []).map((id) => id.trim().toLowerCase()).filter(Boolean),
      ) ||
    current.enabled !== draft.enabled
  );
}

export async function saveSso(settings: SsoSettings, password?: string) {
  const masterPasswordHash = password ? await passwordHash(password) : undefined;
  return request<SsoSettings>(`${base}/sso`, {
    method: 'PUT',
    body: { ...settings, masterPasswordHash },
  });
}
export const testSso = (issuer: string) =>
  request<{ ok: boolean; error: string | null }>(`${base}/sso/test`, { body: { issuer } });
export async function pairSso(url: string, code: string, password: string) {
  const masterPasswordHash = await passwordHash(password);
  return request<SsoSettings>(`${base}/sso/pair`, { body: { url, code, masterPasswordHash } });
}
export const unpairSso = () => request<SsoSettings>(`${base}/sso/pairing`, { method: 'DELETE' });
export const newScimToken = () => request<{ token: string }>(`${base}/scim/token`, { body: {} });

/** What a person removed over SCIM means: kept in the general settings (§21.1). */
export async function saveScimOnDelete(onDelete: 'disable' | 'delete'): Promise<void> {
  const all = await request<Record<string, unknown>>(`${base}/settings`);
  const scim = (all.scim as Record<string, unknown> | undefined) ?? {};
  await request(`${base}/settings`, {
    method: 'PUT',
    body: { ...all, scim: { ...scim, onDelete } },
  });
}
