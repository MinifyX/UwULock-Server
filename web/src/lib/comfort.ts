/**
 * The vault's comforts (docs/uwu-api.md §7–§10): icons for items, earlier versions of items,
 * travel mode and reminders to renew a password.
 *
 * - Automatic icons come from this server (`/icons/<host>/icon.png`), which fetches them from
 *   the websites; the browser never asks a website or a CDN.
 * - Own icons — uploaded, from the icon library, or from a device in the home network — are
 *   encrypted in the browser under the extras key (or the organisation's key) before they go up.
 * - Versions are opened in the browser with the key of their item.
 */

import { useSyncExternalStore } from 'react';
import { sync } from './api';
import { emit, listen } from './events';
import { openExtras } from './requests';
import { call, callJson } from './web/core';
import { download, request } from './web/http';
import * as webauthn from './web/webauthn';

const id = encodeURIComponent;

type List<T> = { data: T[] };

/** Tell whoever shows icons, reminders or travel mode to look again. */
function changed() {
  version++;
  for (const listener of listeners) listener();
}

let version = 0;
const listeners = new Set<() => void>();

/** Re-renders when icons or reminders changed. */
export function useComfort(): number {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => version,
  );
}

// ── Icons ─────────────────────────────────────────────────

/** The pixels an own icon has at most, and its largest encrypted size. */
export const OWN_PIXELS = 128;

/** Names and addresses the server never asks: the home network. Their icons come from here. */
export function isLocalHost(host: string): boolean {
  const name = host.toLowerCase().replace(/\.$/, '');
  if (!name.includes('.')) return true;
  if (/^\[?[0-9a-f:]+\]?$/.test(name) && name.includes(':')) return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(name)) return true;
  const last = name.split('.').pop() ?? '';
  return [
    'local',
    'lan',
    'home',
    'internal',
    'intranet',
    'localhost',
    'localdomain',
    'test',
    'invalid',
    'example',
    'onion',
    'arpa',
    'corp',
    'private',
  ].includes(last);
}

/** Whether `host` is an address (IPv4 or IPv6) rather than a name. */
function isAddress(host: string): boolean {
  const name = host.toLowerCase().replace(/\.$/, '');
  return (/^\[?[0-9a-f:]+\]?$/.test(name) && name.includes(':')) || /^[\d.]+$/.test(name);
}

/**
 * The name of the app a device in the home network is called after: `jellyfin` of
 * `jellyfin.local`, `nextcloud` of `nextcloud.home.arpa`. None for addresses and public names.
 */
export function localLabel(host: string | null): string | null {
  if (!host || !isLocalHost(host) || isAddress(host)) return null;
  const label = host.toLowerCase().split('.')[0] ?? '';
  return /^[a-z0-9_-]{1,63}$/.test(label) && /[a-z]/.test(label) && label !== 'localhost'
    ? label
    : null;
}

/**
 * Where this server hands out a website's icon. A device in the home network is never asked by
 * the server, but may get an app's icon by its name from the server's own databases; an address
 * names no app.
 */
export function automaticIcon(host: string | null): string | null {
  if (!host) return null;
  if (isLocalHost(host) && !localLabel(host)) return null;
  return `/icons/${id(host)}/icon.png`;
}

type OwnIconMeta = { cipherId: string; keyType: string; revisionDate: string; data?: string };
type Kept = { revision: string; url: string | null | 'loading' };

const own = new Map<string, Kept>();
const waiting: string[] = [];
let asked: Promise<void> | null = null;

/** Which items have an own icon, read again; their pictures are opened when they are shown. */
export async function loadOwnIcons(): Promise<void> {
  let list: OwnIconMeta[];
  try {
    list = (await request<List<OwnIconMeta>>('/uwu/v1/icons/own')).data;
  } catch {
    return;
  }
  const seen = new Set(list.map((icon) => icon.cipherId));
  for (const [cipher, kept] of own) {
    if (!seen.has(cipher)) {
      if (kept.url && kept.url !== 'loading') URL.revokeObjectURL(kept.url);
      own.delete(cipher);
    }
  }
  for (const icon of list) {
    const kept = own.get(icon.cipherId);
    if (kept?.revision === icon.revisionDate) continue;
    if (kept?.url && kept.url !== 'loading') URL.revokeObjectURL(kept.url);
    own.set(icon.cipherId, { revision: icon.revisionDate, url: null });
  }
  changed();
}

async function openWaiting() {
  const ids = waiting.splice(0, 500);
  if (!ids.length) return;
  try {
    await openExtras().catch(() => undefined);
    const icons = (
      await request<List<OwnIconMeta>>('/uwu/v1/icons/own/get', { body: { cipherIds: ids } })
    ).data;
    for (const icon of icons) {
      try {
        const png = await call((core) => core.openIcon(icon.cipherId, icon.data ?? ''));
        const url = URL.createObjectURL(new Blob([png as BlobPart], { type: 'image/png' }));
        own.set(icon.cipherId, { revision: icon.revisionDate, url });
      } catch {
        // A key that does not open it (reset, or not ours): the automatic icon instead.
        own.delete(icon.cipherId);
      }
    }
  } finally {
    changed();
  }
}

/** The item's own icon as an address for `<img>`, once opened; null while there is none. */
export function ownIcon(cipherId: string): string | null {
  const kept = own.get(cipherId);
  if (!kept) return null;
  if (kept.url === null) {
    kept.url = 'loading';
    waiting.push(cipherId);
    asked ??= Promise.resolve().then(async () => {
      asked = null;
      while (waiting.length) await openWaiting();
    });
  }
  return kept.url === 'loading' ? null : kept.url;
}

export function hasOwnIcon(cipherId: string): boolean {
  return own.has(cipherId);
}

/** Load an image the browser reads and make it a PNG of at most 128 × 128 pixels. */
export async function toIconPng(blob: Blob): Promise<Uint8Array> {
  const url = URL.createObjectURL(blob);
  try {
    const image = new Image();
    image.decoding = 'async';
    image.src = url;
    await image.decode();
    const width = image.naturalWidth || OWN_PIXELS;
    const height = image.naturalHeight || OWN_PIXELS;
    const scale = Math.min(1, OWN_PIXELS / Math.max(width, height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(width * scale));
    canvas.height = Math.max(1, Math.round(height * scale));
    const context = canvas.getContext('2d');
    if (!context) throw { kind: 'unsupported', message: 'This browser cannot draw the picture.' };
    context.imageSmoothingQuality = 'high';
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    const png = await new Promise<Blob | null>((done) => canvas.toBlob(done, 'image/png'));
    if (!png) throw { kind: 'invalid', message: 'The picture could not be read.' };
    return new Uint8Array(await png.arrayBuffer());
  } catch (error) {
    if (typeof error === 'object' && error && 'kind' in error) throw error;
    throw { kind: 'invalid', message: 'This is no picture the browser can read.' };
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** A picture the person chose, checked to be one of the formats the vault takes. */
export async function iconFromFile(file: File): Promise<Uint8Array> {
  if (!/^image\/(png|jpeg|webp|svg\+xml)$/.test(file.type))
    throw { kind: 'invalid', message: 'PNG, JPEG, WebP or SVG, please.' };
  if (file.size > 5 * 1024 * 1024) throw { kind: 'invalid', message: 'The picture is too large.' };
  return toIconPng(file);
}

/**
 * The icon of a device in the home network, fetched by this browser — never by the server. Often
 * the browser refuses (an https vault may not load from an http device, and the device has to
 * allow it); then the desktop app or an upload does it.
 */
export async function iconFromDevice(address: string): Promise<Uint8Array> {
  const base = new URL(address.includes('://') ? address : `http://${address}`);
  const tries = [new URL('/favicon.ico', base), new URL('/apple-touch-icon.png', base)];
  try {
    const page = await fetch(base, { mode: 'cors', credentials: 'omit' });
    const html = await page.text();
    const found = [...html.matchAll(/<link[^>]+>/gi)]
      .map((match) => match[0])
      .filter((tag) => /rel=["']?[^"'>]*icon/i.test(tag))
      .map((tag) => tag.match(/href=["']?([^"'\s>]+)/i)?.[1])
      .filter((href): href is string => Boolean(href));
    tries.unshift(...found.map((href) => new URL(href, base)));
  } catch {
    // No page to read: the usual places.
  }
  for (const url of tries) {
    try {
      const response = await fetch(url, { mode: 'cors', credentials: 'omit' });
      if (response.ok) return await toIconPng(await response.blob());
    } catch {
      // The next one.
    }
  }
  throw {
    kind: 'device',
    message: 'The browser could not load an icon from the device.',
  };
}

/** Encrypt `png` for the item and keep it as its own icon. */
export async function setOwnIcon(cipherId: string, png: Uint8Array): Promise<void> {
  await openExtras();
  const sealed = await callJson<{ data: string; keyType: string }>((core) =>
    core.sealIcon(cipherId, png),
  );
  await request(`/uwu/v1/icons/own/${id(cipherId)}`, { method: 'PUT', body: sealed });
  await loadOwnIcons();
}

export async function removeOwnIcon(cipherId: string): Promise<void> {
  await request(`/uwu/v1/icons/own/${id(cipherId)}`, { method: 'DELETE' });
  await loadOwnIcons();
}

// ── The icon library ──────────────────────────────────────

export type LibrarySource = {
  id: string;
  name: string;
  url: string;
  license: string;
  licenseUrl: string;
  attribution: string;
};
export type LibraryIcon = {
  source: string;
  id: string;
  name: string;
  variants: string[];
  aliases: string[];
};
export type Library = { updated: string; sources: LibrarySource[]; icons: LibraryIcon[] };

let library: Promise<Library> | null = null;

/** The library's index, as this server mirrors it; fetched once per session. */
export function iconLibrary(): Promise<Library> {
  library ??= request<Library>('/uwu/v1/icons/library').catch((error: unknown) => {
    library = null;
    throw error;
  });
  return library;
}

/**
 * Library icons that fit an item in the home network: by the device's name (`jellyfin.local`),
 * then by the item's name — whole, else word by word (`My Jellyfin`) — the best first, each once.
 */
export function suggestLibrary(
  index: Library,
  host: string | null,
  name: string,
  most = 6,
): LibraryIcon[] {
  const found = new Map<string, LibraryIcon>();
  const add = (query: string | undefined) => {
    if (!query?.trim()) return 0;
    const icons = searchLibrary(index, query, most);
    for (const icon of icons) found.set(`${icon.source}/${icon.id}`, icon);
    return icons.length;
  };
  add(localLabel(host)?.replace(/[-_]+/g, ' '));
  if (!add(name)) {
    for (const word of name.split(/\s+/).filter((word) => word.length >= 4)) add(word);
  }
  return [...found.values()].slice(0, most);
}

/** Icons whose name or id has every word of `query`, the best first. */
export function searchLibrary(index: Library, query: string, most = 60): LibraryIcon[] {
  const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return [];
  const score = (icon: LibraryIcon) => {
    const name = icon.name.toLowerCase();
    const haystack = [name, icon.id, ...icon.aliases].join(' ');
    if (!words.every((word) => haystack.includes(word))) return -1;
    return (name === words.join(' ') ? 0 : name.startsWith(words[0]!) ? 1 : 2) * 1000 + name.length;
  };
  return index.icons
    .map((icon) => ({ icon, rank: score(icon) }))
    .filter((found) => found.rank >= 0)
    .sort((a, b) => a.rank - b.rank)
    .slice(0, most)
    .map((found) => found.icon);
}

/** A library icon as the server fetched it: its address for a preview, with the session. */
export async function libraryIconBlob(icon: LibraryIcon, variant = 'default'): Promise<Blob> {
  return download(
    `/uwu/v1/icons/library/${id(icon.source)}/${id(icon.id)}.png?variant=${id(variant)}`,
  );
}

// ── Versions ──────────────────────────────────────────────

export type CipherVersion = {
  id: string;
  cipherId: string;
  revisionDate: string;
  replacedDate: string;
  size: number;
  cipher: Record<string, unknown>;
};

export type OpenedVersion = {
  name: string;
  notes: string | null;
  login: {
    username: string | null;
    password: string | null;
    totp: string | null;
    uris: string[];
  } | null;
  card: Record<string, string | null> | null;
  identity: Record<string, string> | null;
  sshKey: {
    privateKey: string | null;
    publicKey: string | null;
    fingerprint: string | null;
  } | null;
  fields: { name: string | null; value: string | null; hidden: boolean }[];
  broken: boolean;
};

export const itemVersions = async (itemId: string) =>
  (await request<List<CipherVersion>>(`/uwu/v1/ciphers/${id(itemId)}/versions`)).data;

export const openVersion = (itemId: string, version: CipherVersion) =>
  callJson<OpenedVersion>((core) => core.openVersion(itemId, JSON.stringify(version)));

/** Bring the version back; what the item holds now becomes a version itself. */
export async function restoreVersion(itemId: string, versionId: string, revisionDate: string) {
  await request(`/uwu/v1/ciphers/${id(itemId)}/versions/${id(versionId)}/restore`, {
    body: { lastKnownRevisionDate: revisionDate },
  });
  await sync();
}

export const deleteVersion = (itemId: string, versionId: string) =>
  request(`/uwu/v1/ciphers/${id(itemId)}/versions/${id(versionId)}`, { method: 'DELETE' });

// ── Travel mode ───────────────────────────────────────────

export type Travel = {
  enabled: boolean;
  enabledDate: string | null;
  folderIds: string[];
  hiddenCount: number;
};

export const travel = () => request<Travel>('/uwu/v1/travel');

export async function setTravelFolders(folderIds: string[]): Promise<Travel> {
  const next = await request<Travel>('/uwu/v1/travel/folders', {
    method: 'PUT',
    body: { folderIds },
  });
  if (next.enabled) await sync();
  return next;
}

export async function enableTravel(): Promise<Travel> {
  const next = await request<Travel>('/uwu/v1/travel/enable', { body: {} });
  await sync();
  emit('travel-changed');
  return next;
}

const hashOf = (password: string) => call((core) => core.passwordHash(password));

export async function travelCodeByMail(password: string): Promise<void> {
  await request('/uwu/v1/travel/disable/send-email', {
    body: { masterPasswordHash: await hashOf(password) },
  });
}

/**
 * Switch travel mode off: the master password, and the second step — a code (authenticator 0,
 * mail 1) or, with `provider` 7, the security key, asked here.
 */
export async function disableTravel(password: string, provider: 0 | 1 | 7, code: string) {
  const masterPasswordHash = await hashOf(password);
  let token = code.trim();
  if (provider === 7) {
    const options = await request<Record<string, unknown>>(
      '/uwu/v1/travel/disable/webauthn-challenge',
      { body: { masterPasswordHash } },
    );
    const credential = await webauthn.get(webauthn.requestOptions(options));
    token = JSON.stringify(webauthn.assertionJson(credential));
  }
  const next = await request<Travel>('/uwu/v1/travel/disable', {
    body: { masterPasswordHash, twoFactorProvider: provider, twoFactorToken: token },
  });
  await sync();
  emit('travel-changed');
  return next;
}

// ── Reminders ─────────────────────────────────────────────

export type Reminder = {
  cipherId: string;
  due: string;
  everyMonths: number | null;
  isDue: boolean;
  mailedDate: string | null;
};

const reminders = new Map<string, Reminder>();

export async function loadReminders(): Promise<void> {
  try {
    const list = (await request<List<Reminder>>('/uwu/v1/reminders')).data;
    reminders.clear();
    for (const reminder of list) reminders.set(reminder.cipherId, reminder);
  } catch {
    return;
  }
  changed();
}

export const reminderOf = (cipherId: string) => reminders.get(cipherId) ?? null;
export const dueItems = () =>
  new Set([...reminders.values()].filter((r) => r.isDue).map((r) => r.cipherId));

export async function setReminder(
  cipherId: string,
  when: { due: string } | { everyMonths: number },
): Promise<void> {
  await request(`/uwu/v1/reminders/${id(cipherId)}`, { method: 'PUT', body: when });
  await loadReminders();
}

export async function removeReminder(cipherId: string): Promise<void> {
  await request(`/uwu/v1/reminders/${id(cipherId)}`, { method: 'DELETE' });
  await loadReminders();
}

// Whenever the vault was read again, what hangs on its items is too.
void listen('vault-changed', () => {
  void loadOwnIcons();
  void loadReminders();
});
