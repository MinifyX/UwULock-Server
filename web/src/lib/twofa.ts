/**
 * The report "2FA possible, not set up": the vault's logins compared, in this browser, with the
 * list of 2FA Directory, which the server mirrors (docs/uwu-api.md §15). The server never learns
 * which websites are in the vault; the browser never talks to 2FA Directory.
 */

import type { ItemSummary } from './api';
import { request } from './web/http';

export type TwofaEntry = {
  domain: string;
  additionalDomains: string[];
  name: string;
  /** `totp`, `u2f`, `sms`, `email`, `call`, `custom-software`, `custom-hardware` */
  methods: string[];
  documentation: string | null;
};

export type TwofaDirectory = {
  updated: string;
  source: { name: string; url: string; license: string };
  entries: TwofaEntry[];
};

let cached: TwofaDirectory | null = null;

/** The mirrored list; asked for once per page. */
export async function twofaDirectory(): Promise<TwofaDirectory> {
  cached ??= await request<TwofaDirectory>('/uwu/v1/twofa-directory');
  return cached;
}

/** Every domain of the list, to its entry. */
export function indexOf(entries: TwofaEntry[]): Map<string, TwofaEntry> {
  const index = new Map<string, TwofaEntry>();
  for (const entry of entries) {
    for (const domain of [entry.domain, ...entry.additionalDomains]) {
      const key = domain.toLowerCase();
      if (!index.has(key)) index.set(key, entry);
    }
  }
  return index;
}

/**
 * The entry for a host: the host itself, or the nearest domain above it (`login.example.com`
 * finds `example.com`), never just a top-level domain. Addresses and local names find nothing.
 */
export function entryFor(index: Map<string, TwofaEntry>, host: string | null): TwofaEntry | null {
  if (!host) return null;
  let name = host.toLowerCase().replace(/\.$/, '');
  if (/^[\d.]+$/.test(name) || name.includes(':') || !name.includes('.')) return null;
  if (name.startsWith('www.')) name = name.slice(4);
  for (;;) {
    const found = index.get(name);
    if (found) return found;
    const dot = name.indexOf('.');
    const parent = name.slice(dot + 1);
    if (dot < 0 || !parent.includes('.')) return null;
    name = parent;
  }
}

export type MissingTwoFactor = { item: ItemSummary; entry: TwofaEntry };

/** Logins for sites that offer codes from an authenticator app, without one stored. */
export function missingTwoFactor(items: ItemSummary[], entries: TwofaEntry[]): MissingTwoFactor[] {
  const index = indexOf(entries);
  const out: MissingTwoFactor[] = [];
  for (const item of items) {
    if (item.kind !== 'login' || item.deleted || item.hasTotp || item.broken) continue;
    const entry = entryFor(index, item.host);
    if (entry?.methods.includes('totp')) out.push({ item, entry });
  }
  return out.sort((a, b) => a.item.name.localeCompare(b.item.name));
}
