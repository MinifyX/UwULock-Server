/**
 * Masked addresses (§13): a mail address of its own for every website, made at the person's
 * UwUMail server through the connection this server keeps. The page asks this server; it talks
 * to UwUMail. What the vault needs often — which item has an address — comes from this server's
 * own links, without asking UwUMail.
 *
 * The master password's hash for a new key comes from the caller: this file stays free of the
 * crypto module, so the tests can load it.
 */

import { useCallback, useSyncExternalStore } from 'react';
import { listen } from './events';
import { N_ } from './i18n';
import { request } from './web/http';

export type MaskedState = 'pending' | 'enabled' | 'disabled' | 'deleted';

export type MaskedServer = { url: string; name: string };

export type MaskedConnection = {
  connected: boolean;
  server: string | null;
  username: string | null;
  domains: string[] | null;
  defaultDomain: string | null;
  /** `revoked`: connect again; `unreachable`: the last call failed. */
  status: 'ok' | 'revoked' | 'unreachable' | null;
  connectedDate: string | null;
  lastUsedDate: string | null;
  allowedServers: MaskedServer[];
};

export type MaskedAddress = {
  id: string;
  email: string;
  state: MaskedState;
  forDomain: string;
  description: string;
  url: string | null;
  createdAt: string | null;
  lastMessageAt: string | null;
  createdBy: string | null;
  cipherId: string | null;
};

/** An item's address as this server remembers it; `state` null when UwUMail was not asked yet. */
export type MaskedLink = { id: string; email: string; state: MaskedState | null };

export type MaskedApiKey = {
  id: string;
  name: string;
  hint: string;
  creationDate: string;
  lastUsedDate: string | null;
  /** Only in the answer that made it: shown once. */
  key?: string;
};

export const STATE_LABEL: Record<MaskedState, string> = {
  pending: N_('wartet'),
  enabled: N_('aktiv'),
  disabled: N_('abgeschaltet'),
  deleted: N_('gelöscht'),
};

const id = encodeURIComponent;
const base = '/uwu/v1/masked';

// ── The connection ────────────────────────────────────────

export const maskedConnection = () => request<MaskedConnection>(`${base}/connection`);

/** Where UwUMail asks the person to agree; the server set its cookie for the way back. */
export const connectMasked = (server: string) =>
  request<{ authorizeUrl: string }>(`${base}/connect`, { body: { server } });

export const disconnectMasked = () => request(`${base}/connection`, { method: 'DELETE' });

// ── Addresses ─────────────────────────────────────────────

export async function maskedAddresses(cipherId?: string): Promise<MaskedAddress[]> {
  const query = cipherId ? `?cipherId=${id(cipherId)}` : '';
  return (await request<{ data: MaskedAddress[] }>(`${base}/addresses${query}`)).data;
}

export type NewMasked = {
  forDomain: string;
  description: string;
  /** One of the connection's domains; null: UwUMail's default. */
  domain: string | null;
  cipherId: string | null;
};

export const createMasked = (draft: NewMasked) =>
  request<MaskedAddress>(`${base}/addresses`, { body: { ...draft, emailPrefix: null } });

export const updateMasked = (
  addressId: string,
  change: Partial<Pick<MaskedAddress, 'state' | 'description' | 'forDomain' | 'cipherId'>>,
) =>
  request<MaskedAddress>(`${base}/addresses/${id(addressId)}`, { method: 'PATCH', body: change });

/** Gone for good: UwUMail refuses mail to it and never hands it out again. */
export const deleteMasked = (addressId: string) =>
  request(`${base}/addresses/${id(addressId)}`, { method: 'DELETE' });

export const maskedLinks = () => request<Record<string, MaskedLink>>(`${base}/links`);

// ── Keys for the official clients ─────────────────────────

export const maskedApiKeys = async () =>
  (await request<{ data: MaskedApiKey[] }>(`${base}/api-keys`)).data;

export const createMaskedApiKey = (name: string, masterPasswordHash: string) =>
  request<MaskedApiKey>(`${base}/api-keys`, { body: { name, masterPasswordHash } });

export const deleteMaskedApiKey = (keyId: string) =>
  request(`${base}/api-keys/${id(keyId)}`, { method: 'DELETE' });

/** The "Self-host server URL"s the official clients' generator takes (§13.4, §13.5). */
export function forwarderUrls(origin: string = location.origin) {
  const root = origin.replace(/\/+$/, '');
  return { addy: `${root}${base}/addy`, simpleLogin: `${root}${base}/simplelogin` };
}

// ── What the pages need ───────────────────────────────────

/**
 * The website an address is for, from an item's first address: its origin, like
 * `https://shop.example.com`. A bare host counts as https; an app's address or nothing: "".
 */
export function forDomainOf(uri: string | null | undefined): string {
  const text = (uri ?? '').trim();
  if (!text) return '';
  const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(text) ? text : `https://${text}`;
  try {
    const url = new URL(withScheme);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return '';
    if (!url.hostname.includes('.') && url.hostname !== 'localhost') return '';
    return `${url.protocol}//${url.host}`;
  } catch {
    return '';
  }
}

export type ConnectResult =
  | { ok: true }
  | { ok: false; reason: 'denied' | 'expired' | 'invalid_state' | 'upstream' | 'unknown' };

/** The way back from UwUMail: `#/settings/masked?result=connected` or `?result=error&reason=…`. */
export function connectResultOf(query: URLSearchParams): ConnectResult | null {
  const result = query.get('result');
  if (result === 'connected') return { ok: true };
  if (result !== 'error') return null;
  const reason = query.get('reason');
  return {
    ok: false,
    reason:
      reason === 'denied' ||
      reason === 'expired' ||
      reason === 'invalid_state' ||
      reason === 'upstream'
        ? reason
        : 'unknown',
  };
}

/** The domain a new address gets at first: the connection's default, else its first. */
export function defaultDomainOf(connection: MaskedConnection | null): string {
  return connection?.defaultDomain ?? connection?.domains?.[0] ?? '';
}

// ── Kept for the page: the connection and the links ───────

/** The connection as last asked: `error` what that threw, `loaded` once it answered at all. */
export type ConnectionState = {
  connection: MaskedConnection | null;
  error: unknown;
  loaded: boolean;
};

const UNASKED: ConnectionState = { connection: null, error: null, loaded: false };
let connection: ConnectionState = UNASKED;
let connectionLoading: Promise<void> | null = null;
let links: Record<string, MaskedLink> = {};
let linksLoaded = 0;
let linksLoading: Promise<void> | null = null;
const listeners = new Set<() => void>();

function notify() {
  for (const listener of listeners) listener();
}

/** Ask again (after connecting, disconnecting, or a change here). */
export function reloadMaskedConnection(): Promise<void> {
  connectionLoading = maskedConnection().then(
    (answer) => {
      connection = { connection: answer, error: null, loaded: true };
      notify();
    },
    (error: unknown) => {
      connection = { connection: null, error, loaded: true };
      notify();
    },
  );
  return connectionLoading;
}

export function reloadMaskedLinks(): Promise<void> {
  linksLoaded = Date.now();
  linksLoading = maskedLinks().then(
    (answer) => {
      links = answer ?? {};
      notify();
    },
    () => undefined,
  );
  return linksLoading;
}

// Another account, or none, must not see these.
void listen<{ state: string }>('vault-status', ({ payload }) => {
  if (payload.state === 'unlocked') return;
  connection = UNASKED;
  connectionLoading = null;
  links = {};
  linksLoading = null;
  linksLoaded = 0;
  notify();
});

// After a sync the links may have changed on another device; asked at most every 10 seconds.
void listen('vault-changed', () => {
  if (linksLoading && Date.now() - linksLoaded > 10_000) void reloadMaskedLinks();
});

/** The account's connection to UwUMail, asked once; nothing while the feature is off. */
export function useMaskedConnectionState(enabled: boolean): ConnectionState {
  const subscribe = useCallback(
    (listener: () => void) => {
      listeners.add(listener);
      if (enabled && !connectionLoading) void reloadMaskedConnection();
      return () => void listeners.delete(listener);
    },
    [enabled],
  );
  const value = useSyncExternalStore(subscribe, () => connection);
  return enabled ? value : UNASKED;
}

/**
 * The connection when it can make addresses now — connected, not revoked — else `null`: whether
 * the editor and the generator offer one.
 */
export function useUsableMasked(enabled: boolean): MaskedConnection | null {
  const found = useMaskedConnectionState(enabled).connection;
  return found?.connected && found.status !== 'revoked' ? found : null;
}

/** Which item has which address (by item id); empty while the feature is off. */
export function useMaskedLinks(enabled: boolean): Record<string, MaskedLink> {
  const subscribe = useCallback(
    (listener: () => void) => {
      listeners.add(listener);
      if (enabled && !linksLoading) void reloadMaskedLinks();
      return () => void listeners.delete(listener);
    },
    [enabled],
  );
  const value = useSyncExternalStore(subscribe, () => links);
  return enabled ? value : NONE;
}

const NONE: Record<string, MaskedLink> = {};

/** The links as they are now, outside a component: for deleting several items. */
export const currentMaskedLinks = () => links;
