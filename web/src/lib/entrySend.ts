/**
 * Entry Sends: an item shared as a Send that UwULock's Send page shows as an entry — its fields
 * with copy buttons and live one-time codes — rather than as raw text. The text stays readable
 * for Bitwarden's apps; its last line, `uwulock-entry:v2:<JSON>.<tag>`, carries the entry
 * (uwulock-core `entry_send`, docs/sharing.md). The tag is made with the Send's seed — the part
 * of the link after `#` — so a marker line someone put into an item's notes does not turn a plain
 * Send into an entry. Decoding needs no login: the recipient's page does it, with the link's key.
 */

import type { TotpCode } from './api';
import { callJson } from './web/core';

export const ENTRY_MARKER = 'uwulock-entry:v2:';

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

/** A decoded entry Send: the entry, the readable lines above the marker, which websites may be links. */
export type DecodedEntry = { entry: SharedEntry; readable: string; openable: boolean[] };

/** Whether a text may be an entry Send at all, before asking the module. */
export const mayBeEntrySend = (text: string | null | undefined): boolean =>
  Boolean(text?.includes(ENTRY_MARKER));

/**
 * The entry in a Send's text and the readable lines above it, or `null` for a plain text (or a
 * marker that isn't this Send's). `urlKey` is the link's part after `#`.
 */
export async function decodeEntrySend(text: string, urlKey: string): Promise<DecodedEntry | null> {
  // Most Sends are plain: no need to ask the module.
  if (!mayBeEntrySend(text)) return null;
  return callJson<DecodedEntry | null>((core) => core.decodeEntrySend(text, urlKey));
}

/** The codes of an entry's authenticator key right now. */
export const entryCodes = (secret: string): Promise<TotpCode> =>
  callJson<TotpCode>((core) => core.totpCodes(secret, Date.now() / 1000));
