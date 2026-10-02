/**
 * Entry Sends: an item shared as a Send that UwULock's Send page shows as an entry — its fields
 * with copy buttons and live one-time codes — rather than as raw text. The text stays readable
 * for Bitwarden's apps; its last line, `uwulock-entry:v1:…`, carries the entry (uwulock-core
 * `entry_send`, docs/sharing.md). Decoding needs no login: the recipient's page does it.
 */

import type { TotpCode } from './api';
import { callJson } from './web/core';

export const ENTRY_MARKER = 'uwulock-entry:v1:';

export type EntryField = { name: string; value: string; hidden: boolean };

/** The entry in a Send. `totp` is the authenticator key: only ever shown as live codes. */
export type SharedEntry = {
  name: string;
  username?: string;
  password?: string;
  websites: string[];
  notes?: string;
  fields: EntryField[];
  totp?: string;
};

/** The entry in a Send's text and the readable lines above it, or `null` for a plain text. */
export async function decodeEntrySend(
  text: string,
): Promise<{ entry: SharedEntry; readable: string } | null> {
  // Most Sends are plain: no need to ask the module.
  if (!text.includes(ENTRY_MARKER)) return null;
  return callJson<{ entry: SharedEntry; readable: string } | null>((core) =>
    core.decodeEntrySend(text),
  );
}

/** The codes of an entry's authenticator key right now. */
export const entryCodes = (secret: string): Promise<TotpCode> =>
  callJson<TotpCode>((core) => core.totpCodes(secret, Date.now() / 1000));

/**
 * The readable lines of a Send's text: without the marker line of an entry Send. A plain text
 * comes back whole. (Only what is shown in the vault's own list; the Send page decodes.)
 */
export function readableOf(text: string): string {
  const trimmed = text.replace(/[\s]+$/, '');
  const at = trimmed.lastIndexOf('\n');
  const last = trimmed.slice(at + 1).trim();
  if (!last.startsWith(ENTRY_MARKER)) return text;
  return at < 0 ? '' : trimmed.slice(0, at).replace(/\r$/, '');
}

/** Whether a Send's text is an entry Send (its last line is the marker). */
export const isEntrySend = (text: string | null | undefined): boolean =>
  Boolean(text) && readableOf(text ?? '') !== text;
