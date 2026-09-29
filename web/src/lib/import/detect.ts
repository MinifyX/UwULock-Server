/**
 * Which app a file comes from, by what is in it: KeePass's signature, the files in a zip, the
 * keys of a JSON export, the columns of a CSV header.
 */

import { text } from './bytes';
import { parseCsv } from './csv';
import { isKdbx } from './kdbx';
import type { Source } from './types';
import { Zip } from './zip';

export type Kind = 'kdbx' | 'zip' | 'pgp' | 'json' | 'xml' | 'csv';

export function kindOf(bytes: Uint8Array): Kind {
  if (isKdbx(bytes)) return 'kdbx';
  if (Zip.is(bytes)) return 'zip';
  const start = text(bytes.subarray(0, 64)).trimStart();
  if (start.startsWith('-----BEGIN PGP')) return 'pgp';
  if (start.startsWith('{') || start.startsWith('[')) return 'json';
  if (start.startsWith('<')) return 'xml';
  return 'csv';
}

/** The CSV header's column names, lower case. */
export function csvColumns(content: string): Set<string> {
  const firstRows = content.split(/\r?\n/, 5).join('\n');
  const header = parseCsv(firstRows)[0] ?? [];
  return new Set(header.map((name) => name.trim().toLowerCase()));
}

export function sourceOfCsv(columns: Set<string>): Source | null {
  const has = (...names: string[]) => names.every((name) => columns.has(name));
  if (has('login_uri') || has('folder', 'favorite', 'type', 'name', 'reprompt')) return 'bitwarden';
  if (has('grouping', 'extra') || has('profilename')) return 'lastpass';
  if (has('httprealm') || has('formactionorigin') || has('guid', 'timecreated')) return 'firefox';
  if (has('type', 'name', 'email', 'totp', 'vault')) return 'protonpass';
  if (has('title', 'otpauth') && (has('favorite') || has('archived') || has('tags'))) {
    return '1password';
  }
  if (has('title', 'url', 'username', 'password', 'otpauth')) return 'apple';
  if (has('group', 'title', 'username', 'password') || has('account', 'login name')) {
    return 'keepass';
  }
  if (has('name', 'url', 'username', 'password')) return 'chrome';
  if (has('title')) return '1password';
  return null;
}

export function sourceOfJson(data: unknown): Source | null {
  if (!data || typeof data !== 'object') return null;
  if ('accounts' in data) return '1password';
  if ('vaults' in data) return 'protonpass';
  if ('items' in data || 'encrypted' in data) return 'bitwarden';
  return null;
}

export function sourceOfZip(zip: Zip): Source | null {
  if (zip.names.includes('export.data')) return '1password';
  if (zip.names.some((name) => /(^|\/)data\.(json|pgp)$/.test(name) || name.endsWith('.pgp'))) {
    return 'protonpass';
  }
  return null;
}

/** The app a file most likely comes from; null when nothing fits. */
export function detect(bytes: Uint8Array): Source | null {
  const kind = kindOf(bytes);
  switch (kind) {
    case 'kdbx':
      return 'keepass';
    case 'pgp':
      return 'protonpass';
    case 'xml':
      return /<KeePassFile[\s>]/.test(text(bytes.subarray(0, 4096))) ? 'keepass' : null;
    case 'zip':
      try {
        return sourceOfZip(new Zip(bytes));
      } catch {
        return null;
      }
    case 'json':
      try {
        return sourceOfJson(JSON.parse(text(bytes)));
      } catch {
        return null;
      }
    case 'csv':
      return sourceOfCsv(csvColumns(text(bytes)));
  }
}
