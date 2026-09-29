/**
 * KeePass and KeePassXC: the XML inside a KDBX file (and KeePass's XML export), and the CSV
 * exports of both.
 *
 * Field mapping after Bitwarden's importers (bitwarden/clients,
 * libs/importer/src/importers/keepass2-xml-importer.ts and keepassx-csv-importer.ts, GPL-3.0):
 * groups become folders by path without the root group, Title/UserName/Password/URL/Notes go
 * where they belong, other fields become custom fields, protected ones hidden. Beyond that:
 * additional URLs, the TOTP fields of KeePassXC, KeePass and KeeTrayTOTP, old passwords from an
 * entry's history, and the recycle bin left out.
 */

import { t } from '../i18n';
import { base32, fromBase64, fromHex, ImportError } from './bytes';
import { blank, Collector, some } from './collect';
import type { CsvTable } from './csv';
import { FieldType, type ExportItem } from './types';

const children = (parent: Element, name: string) =>
  Array.from(parent.children).filter((child) => child.nodeName === name);
const child = (parent: Element, name: string) => children(parent, name)[0];
const textOf = (parent: Element | undefined, name: string) =>
  (parent && child(parent, name)?.textContent) ?? '';

/** KDBX 4 keeps times as seconds since the year 1 (base64, 8 bytes); KDBX 3.1 as ISO text. */
function time(value: string): string | null {
  if (!value) return null;
  try {
    if (/^\d{4}-\d\d-\d\d/.test(value)) return new Date(value).toISOString();
    const bytes = fromBase64(value);
    if (bytes.length !== 8) return null;
    const seconds = new DataView(bytes.buffer).getBigInt64(0, true);
    return new Date(Number(seconds - 62135596800n) * 1000).toISOString();
  } catch {
    return null;
  }
}

type Strings = Map<string, { value: string; hidden: boolean }>;

/** A TOTP as the vault reads it: an otpauth:// address, or just the secret when it is standard. */
function totpFrom(
  secret: string,
  { period = 30, digits = 6, algorithm = 'SHA1', label = '' } = {},
): string {
  const clean = secret.replace(/[\s=]/g, '').toUpperCase();
  if (period === 30 && digits === 6 && algorithm === 'SHA1') return clean;
  const query = new URLSearchParams({
    secret: clean,
    period: String(period),
    digits: String(digits),
  });
  if (algorithm !== 'SHA1') query.set('algorithm', algorithm);
  return `otpauth://totp/${encodeURIComponent(label || 'TOTP')}?${query}`;
}

/**
 * The TOTP of an entry, and the fields it came from. KeePassXC keeps it in `otp` (an otpauth://
 * address, or "key=…&step=…&size=…" from older versions), KeePass 2.47+ in TimeOtp-* fields,
 * KeeTrayTOTP in "TOTP Seed" and "TOTP Settings" ("30;6", or "30;S" for Steam).
 */
export function keepassTotp(
  strings: Strings,
  label: string,
): { totp: string; used: string[] } | null {
  const get = (name: string) => strings.get(name)?.value.trim() ?? '';
  const otp = get('otp');
  if (otp) {
    if (/^otpauth:\/\//i.test(otp)) return { totp: otp, used: ['otp'] };
    const params = new URLSearchParams(otp);
    const key = params.get('key');
    if (key) {
      const digits = params.get('size');
      const steam = params.get('encoder') === 'steam' || digits === 'S';
      return {
        totp: steam
          ? `steam://${key}`
          : totpFrom(key, {
              period: Number(params.get('step') ?? 30),
              digits: Number(digits ?? 6),
              label,
            }),
        used: ['otp'],
      };
    }
  }
  const seed = get('TOTP Seed');
  if (seed) {
    const [period = '30', digits = '6'] = get('TOTP Settings').split(';');
    return {
      totp:
        digits === 'S'
          ? `steam://${seed}`
          : totpFrom(seed, { period: Number(period) || 30, digits: Number(digits) || 6, label }),
      used: ['TOTP Seed', 'TOTP Settings'],
    };
  }
  const encodings: [string, (value: string) => Uint8Array | null][] = [
    ['TimeOtp-Secret-Base32', () => null],
    ['TimeOtp-Secret', (value) => new TextEncoder().encode(value)],
    ['TimeOtp-Secret-Hex', (value) => fromHex(value)],
    ['TimeOtp-Secret-Base64', (value) => fromBase64(value)],
  ];
  for (const [name, decode] of encodings) {
    const value = get(name);
    if (!value) continue;
    const bytes = decode(value);
    const secret = name === 'TimeOtp-Secret-Base32' ? value : bytes ? base32(bytes) : null;
    if (!secret) continue;
    const algorithm =
      get('TimeOtp-Algorithm')
        .replace(/^HMAC-/i, '')
        .replace('-', '') || 'SHA1';
    return {
      totp: totpFrom(secret, {
        period: Number(get('TimeOtp-Period')) || 30,
        digits: Number(get('TimeOtp-Length')) || 6,
        algorithm: algorithm.toUpperCase(),
        label,
      }),
      used: [name, 'TimeOtp-Length', 'TimeOtp-Period', 'TimeOtp-Algorithm'],
    };
  }
  return null;
}

const STANDARD = ['Title', 'UserName', 'Password', 'URL', 'Notes'];

function readEntry(collector: Collector, entry: Element): ExportItem {
  const strings: Strings = new Map();
  for (const string of children(entry, 'String')) {
    const value = child(string, 'Value');
    const text = value?.textContent ?? '';
    if (blank(text)) continue;
    const hidden =
      value?.getAttribute('Protected')?.toLowerCase() === 'true' ||
      value?.getAttribute('ProtectInMemory')?.toLowerCase() === 'true';
    strings.set(textOf(string, 'Key'), { value: text, hidden });
  }
  const get = (name: string) => strings.get(name)?.value ?? null;
  const item = collector.login(get('Title'));
  const login = item.login;
  login.username = some(get('UserName'));
  login.password = some(get('Password'));
  collector.uris(item, get('URL'));
  collector.appendNote(item, get('Notes'));

  const used = new Set(STANDARD);
  for (const name of strings.keys()) {
    if (/^KP2A_URL(_\d+)?$/.test(name)) {
      collector.uris(item, get(name));
      used.add(name);
    }
  }
  const totp = keepassTotp(strings, item.name);
  if (totp) {
    login.totp = totp.totp;
    totp.used.forEach((name) => used.add(name));
  }
  for (const [name, { value, hidden }] of strings) {
    if (used.has(name)) continue;
    collector.field(item, name, value, hidden ? FieldType.Hidden : undefined);
  }

  const tags = textOf(entry, 'Tags');
  if (!blank(tags)) collector.extra(item, 'Tags', tags.split(/[;,]\s*/).join(', '));
  const times = child(entry, 'Times');
  if (textOf(times, 'Expires').toLowerCase() === 'true') {
    const expires = time(textOf(times, 'ExpiryTime'));
    if (expires) collector.extra(item, t('Läuft ab'), expires.slice(0, 10), FieldType.Text);
  }
  const attachments = children(entry, 'Binary').length;
  if (attachments) collector.attachment(attachments);

  // Older passwords, newest first, from the entry's earlier versions.
  const history = child(entry, 'History');
  if (history) {
    const old: { password: string; lastUsedDate: string }[] = [];
    for (const version of children(history, 'Entry').reverse()) {
      const password = children(version, 'String').find((s) => textOf(s, 'Key') === 'Password');
      const value = password ? textOf(password, 'Value') : '';
      if (blank(value) || value === login.password || old.some((h) => h.password === value)) {
        continue;
      }
      const changed = time(textOf(child(version, 'Times'), 'LastModificationTime'));
      old.push({ password: value, lastUsedDate: changed ?? new Date().toISOString() });
    }
    if (old.length) item.passwordHistory = old.slice(0, 5);
  }
  return item;
}

/** The entries of KeePass's XML (from a KDBX file or KeePass's XML export). */
export function readKeepassXml(doc: Document, collector: Collector) {
  const root = doc.querySelector('KeePassFile > Root');
  const top = root && child(root, 'Group');
  if (!top) throw new ImportError(t('Die KeePass-Datei enthält keine Gruppen.'));
  const meta = doc.querySelector('KeePassFile > Meta');
  const empty = 'AAAAAAAAAAAAAAAAAAAAAA==';
  const recycleBin =
    textOf(meta ?? undefined, 'RecycleBinEnabled').toLowerCase() !== 'false'
      ? textOf(meta ?? undefined, 'RecycleBinUUID')
      : '';
  const templates = textOf(meta ?? undefined, 'EntryTemplatesGroup');
  let skipped = 0;

  const walk = (group: Element, path: string | null) => {
    const uuid = textOf(group, 'UUID');
    if (path !== null && uuid && uuid !== empty && (uuid === recycleBin || uuid === templates)) {
      skipped += Array.from(group.getElementsByTagName('Entry')).filter(
        (entry) => entry.parentElement?.nodeName !== 'History',
      ).length;
      return;
    }
    for (const entry of children(group, 'Entry')) {
      const title = children(entry, 'String').find((s) => textOf(s, 'Key') === 'Title');
      collector.entry(title && textOf(title, 'Value'), () =>
        collector.add(readEntry(collector, entry), path),
      );
    }
    for (const sub of children(group, 'Group')) {
      const name = textOf(sub, 'Name').trim() || '-';
      walk(sub, path ? `${path}/${name}` : name);
    }
  };
  walk(top, null);
  if (skipped > 0) {
    collector.warn(
      t('{n} Einträge aus dem Papierkorb oder den Vorlagen bleiben weg.', { n: skipped }),
    );
  }
}

/**
 * KeePassXC's CSV ("Group","Title","Username","Password","URL","Notes","TOTP",…) and KeePass 2's
 * ("Account","Login Name","Password","Web Site","Comments").
 */
export function readKeepassCsv(table: CsvTable, collector: Collector) {
  const keepassXc = table.has('Title', 'Username', 'Password');
  const keepass2 = table.has('Account', 'Login Name', 'Password');
  if (!keepassXc && !keepass2) {
    throw new ImportError(
      t('Das sieht nicht nach einem CSV-Export von KeePass oder KeePassXC aus.'),
    );
  }
  const known = keepassXc
    ? [
        'Group',
        'Title',
        'Username',
        'Password',
        'URL',
        'Notes',
        'TOTP',
        'Icon',
        'Last Modified',
        'Created',
      ]
    : ['Account', 'Login Name', 'Password', 'Web Site', 'Comments'];
  for (const row of table.rows) {
    const item = collector.login(table.get(row, 'Title', 'Account'));
    item.login.username = some(table.get(row, 'Username', 'Login Name'));
    item.login.password = some(table.get(row, 'Password'));
    collector.uris(item, table.get(row, 'URL', 'Web Site'));
    collector.appendNote(item, table.get(row, 'Notes', 'Comments'));
    const totp = table.get(row, 'TOTP');
    if (totp) {
      const strings: Strings = new Map([['otp', { value: totp, hidden: true }]]);
      item.login.totp = keepassTotp(strings, item.name)?.totp ?? totp;
    }
    for (const [name, value] of table.rest(row, known)) collector.extra(item, name, value);
    // KeePassXC writes the root group's name in front of every path.
    const group = table.get(row, 'Group').replace(/\\/g, '/').split('/').slice(1).join('/');
    collector.add(item, group || null);
  }
}
