/**
 * Talking to the server: Bitwarden's API and UwULock's own, on this page's origin.
 *
 * The session — access token, refresh token, the address — is kept in the tab's session
 * storage, so a reload keeps you logged in (with the vault locked: keys never go into storage)
 * and closing the tab ends it. An access token that runs out is renewed with the refresh token
 * once, on the next request that needs it.
 */

import { emit } from '../events';

export type Session = {
  email: string;
  accessToken: string;
  refreshToken: string;
  /** Milliseconds since 1970. */
  expiresAt: number;
};

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

const SESSION_KEY = 'uwulock.session';
const DEVICE_KEY = 'uwulock.device';

/** Bitwarden's client version these requests speak for: what the server unlocks features by. */
export const CLIENT_VERSION = '2026.9.0';

function storage(kind: 'local' | 'session'): Storage | null {
  try {
    return kind === 'local' ? window.localStorage : window.sessionStorage;
  } catch {
    return null;
  }
}

let session: Session | null = (() => {
  try {
    const raw = storage('session')?.getItem(SESSION_KEY);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
})();

export function currentSession(): Session | null {
  return session;
}

export function setSession(next: Session | null) {
  session = next;
  try {
    if (next) storage('session')?.setItem(SESSION_KEY, JSON.stringify(next));
    else storage('session')?.removeItem(SESSION_KEY);
  } catch {
    // Private windows may refuse; the session then lasts as long as the page.
  }
}

/** This browser, as a device of the account: made once, kept in local storage. */
export function deviceId(): string {
  const store = storage('local');
  let id = store?.getItem(DEVICE_KEY) ?? null;
  if (!id) {
    id = crypto.randomUUID();
    store?.setItem(DEVICE_KEY, id);
  }
  return id;
}

/** Bitwarden's device type for this browser. */
export function deviceType(): { kind: number; name: string } {
  const agent = navigator.userAgent;
  if (/Edg\//.test(agent)) return { kind: 12, name: 'Edge' };
  if (/OPR\//.test(agent)) return { kind: 11, name: 'Opera' };
  if (/Vivaldi/.test(agent)) return { kind: 18, name: 'Vivaldi' };
  if (/Firefox\//.test(agent)) return { kind: 10, name: 'Firefox' };
  if (/Chrome\//.test(agent)) return { kind: 9, name: 'Chrome' };
  if (/Safari\//.test(agent)) return { kind: 17, name: 'Safari' };
  return { kind: 14, name: 'Browser' };
}

function headers(extra?: Record<string, string>): Record<string, string> {
  return {
    Accept: 'application/json',
    'Bitwarden-Client-Name': 'web',
    'Bitwarden-Client-Version': CLIENT_VERSION,
    'Device-Type': String(deviceType().kind),
    ...extra,
  };
}

/** The message a person reads, from whatever the server answered. */
function messageOf(status: number, body: unknown): string {
  if (body && typeof body === 'object') {
    const value = body as Record<string, unknown>;
    const model = value.errorModel as Record<string, unknown> | undefined;
    const message = (model?.message ?? value.message ?? value.error_description) as
      string | undefined;
    if (message && message !== 'invalid_grant') return message;
  }
  if (status === 0) return 'The server does not answer.';
  return `The server answered with HTTP ${status}.`;
}

async function parse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

let refreshing: Promise<void> | null = null;

/** A new access token from the refresh token. Throws when the session is over. */
async function refresh(): Promise<void> {
  if (!session) throw new ApiError(401, 'Not logged in.', null);
  refreshing ??= (async () => {
    const form = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: 'web',
      refresh_token: session!.refreshToken,
    });
    const response = await fetch('/identity/connect/token', {
      method: 'POST',
      headers: headers({ 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: form,
    });
    const body = (await parse(response)) as Record<string, unknown> | null;
    if (!response.ok || !body) {
      setSession(null);
      // Logged out elsewhere, by a new password, or by an admin: whatever is open here closes.
      emit('session-ended');
      throw new ApiError(401, 'The session has ended. Log in again.', body);
    }
    setSession({
      ...session!,
      accessToken: String(body.access_token),
      refreshToken: String(body.refresh_token ?? session!.refreshToken),
      expiresAt: Date.now() + Number(body.expires_in ?? 3600) * 1000,
    });
  })().finally(() => {
    refreshing = null;
  });
  return refreshing;
}

type Options = {
  method?: string;
  body?: unknown;
  /** Send the access token (the default). */
  auth?: boolean;
  /** A form instead of JSON. */
  form?: URLSearchParams;
  extraHeaders?: Record<string, string>;
};

/** A request; the answer's JSON (or text, or null). Throws `ApiError` for anything but 2xx. */
export async function request<T = unknown>(path: string, options: Options = {}): Promise<T> {
  const auth = options.auth ?? true;
  if (auth && session && session.expiresAt - Date.now() < 60_000) await refresh();
  const send = () => {
    const extra: Record<string, string> = { ...options.extraHeaders };
    if (options.form) extra['Content-Type'] = 'application/x-www-form-urlencoded';
    else if (options.body !== undefined) extra['Content-Type'] = 'application/json';
    if (auth && session) extra.Authorization = `Bearer ${session.accessToken}`;
    return fetch(path, {
      method: options.method ?? (options.body !== undefined || options.form ? 'POST' : 'GET'),
      headers: headers(extra),
      body: options.form ?? (options.body !== undefined ? JSON.stringify(options.body) : undefined),
    });
  };
  let response: Response;
  try {
    response = await send();
    if (response.status === 401 && auth && session) {
      await refresh();
      response = await send();
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(0, messageOf(0, null), null);
  }
  const body = await parse(response);
  if (!response.ok) throw new ApiError(response.status, messageOf(response.status, body), body);
  return body as T;
}

/**
 * A file from the server, with the access token: for downloads the browser cannot fetch itself.
 * With a `body`, it is asked for by POST, with that JSON.
 */
export async function download(path: string, body?: unknown): Promise<Blob> {
  if (session && session.expiresAt - Date.now() < 60_000) await refresh();
  const extra: Record<string, string> = session
    ? { Authorization: `Bearer ${session.accessToken}` }
    : {};
  if (body !== undefined) extra['Content-Type'] = 'application/json';
  const response = await fetch(path, {
    method: body !== undefined ? 'POST' : 'GET',
    headers: headers(extra),
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!response.ok)
    throw new ApiError(response.status, messageOf(response.status, await parse(response)), null);
  return response.blob();
}
