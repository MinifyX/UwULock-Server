/**
 * What all importers share: items and folders in the shape of Bitwarden's JSON export, and the
 * rule that nothing is dropped — a value without a place of its own becomes a custom field, or
 * goes into the notes when it is long or has several lines.
 *
 * Logic after Bitwarden's base importer (bitwarden/clients,
 * libs/importer/src/importers/base-importer.ts, GPL-3.0): processKvp, processFolder, fixUri,
 * nameFromUrl, convertToNoteIfNeeded, getFullName.
 */

import { t } from '../i18n';
import { securityOf, WIFI_FIELD, WIFI_MARKER, WIFI_TYPE } from '../wifi';
import {
  FieldType,
  ItemType,
  type BitwardenExport,
  type ExportCard,
  type ExportField,
  type ExportFolder,
  type ExportIdentity,
  type ExportItem,
} from './types';

/** A field name that sounds like a secret: its value goes into a hidden field. */
const SECRET =
  /\b(pin|cvv|cvc|otp|totp|puk)\b|pass|pwd|secret|geheim|kennwort|token|key|schlüssel|seed|recovery|private|backup.?code|security.?code|sicherheitscode|wiederherstellung/i;

export function secretLooking(name: string): boolean {
  return SECRET.test(name);
}

export const blank = (value: string | null | undefined): value is null | undefined | '' =>
  value == null || value.trim() === '';

/** `value`, or null when there is nothing in it. */
export function some(value: string | null | undefined): string | null {
  return blank(value) ? null : value;
}

/** Schemes that run or show something in place of a page: never kept as an item's address. */
const UNSAFE_SCHEMES = ['javascript:', 'vbscript:', 'data:', 'file:', 'blob:'];

/** Whether `uri` has a scheme from `UNSAFE_SCHEMES`, as a browser would read it. */
export function unsafeUri(uri: string): boolean {
  // Browsers skip line breaks and tabs inside an address, and spaces and controls around it.
  // eslint-disable-next-line no-control-regex
  const plain = uri.replace(/[\x00-\x20\x7f]/g, '').toLowerCase();
  return UNSAFE_SCHEMES.some((scheme) => plain.startsWith(scheme));
}

/** An address as the vault keeps it: with a scheme, "example.com" becomes https://example.com. */
export function fixUri(uri: string): string | null {
  const trimmed = uri.trim();
  if (!trimmed) return null;
  if (!trimmed.includes('://') && trimmed.includes('.') && !/\s/.test(trimmed)) {
    return `https://${trimmed}`.slice(0, 1000);
  }
  return trimmed.slice(0, 1000);
}

/** The host of an address without "www.", for items that have no name of their own. */
export function nameFromUrl(url: string): string | null {
  try {
    const host = new URL(fixUri(url) ?? '').hostname;
    return host ? host.replace(/^www\./, '') : null;
  } catch {
    return null;
  }
}

/** "Mika Maria Muster" → first, middle, last; two parts are first and last. */
export function splitName(full: string): [string | null, string | null, string | null] {
  const parts = full.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return [null, null, null];
  if (parts.length === 1) return [parts[0]!, null, null];
  if (parts.length === 2) return [parts[0]!, null, parts[1]!];
  return [parts[0]!, parts[1]!, parts.slice(2).join(' ')];
}

/** A card's brand from its number, as Bitwarden's apps name brands. */
export function cardBrand(number: string | null): string | null {
  const digits = (number ?? '').replace(/\D/g, '');
  if (!digits) return null;
  const brands: [RegExp, string][] = [
    [/^4/, 'Visa'],
    [/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/, 'Mastercard'],
    [/^3[47]/, 'Amex'],
    [/^(6011|65|64[4-9]|622)/, 'Discover'],
    [/^3(0[0-5]|[68])/, 'Diners Club'],
    [/^35/, 'JCB'],
    [/^(5018|5020|5038|6304|6759|676[1-3])/, 'Maestro'],
    [/^62/, 'UnionPay'],
    [/^220[0-4]/, 'Mir'],
  ];
  return brands.find(([pattern]) => pattern.test(digits))?.[1] ?? null;
}

const emptyCard = (): ExportCard => ({
  cardholderName: null,
  brand: null,
  number: null,
  expMonth: null,
  expYear: null,
  code: null,
});

const emptyIdentity = (): ExportIdentity => ({
  title: null,
  firstName: null,
  middleName: null,
  lastName: null,
  address1: null,
  address2: null,
  address3: null,
  city: null,
  state: null,
  postalCode: null,
  country: null,
  company: null,
  email: null,
  phone: null,
  ssn: null,
  username: null,
  passportNumber: null,
  licenseNumber: null,
});

/** A Wi-Fi network as another app has it; `security` in that app's words. */
export type WifiEntry = {
  ssid?: string | null;
  password?: string | null;
  security?: string | null;
  hidden?: boolean;
  eap?: string | null;
  phase2?: string | null;
  identity?: string | null;
  anonymous?: string | null;
  ca?: string | null;
};

/** Whether the item carries UwULock's Wi-Fi marker (docs/wifi.md). */
export function hasWifiMarker(item: ExportItem): boolean {
  // Bitwarden's JSON, read as it is, may have no fields or fields without a value.
  return (item.fields ?? []).some(
    (field) =>
      field?.name === WIFI_MARKER &&
      typeof field.value === 'string' &&
      field.value.trim().toLowerCase() === WIFI_TYPE,
  );
}

export class Collector {
  private folders: ExportFolder[] = [];
  private folderIds = new Map<string, string>();
  private items: ExportItem[] = [];
  private extras = new Set<ExportItem>();
  private attachments = 0;
  private warnings: string[] = [];
  private entries = 0;
  private skipped: string[] = [];

  /**
   * Reads one entry of the file with `read`. When that breaks on a value, the entry is left out
   * and the preview names it by its title (or its place in the file), never by the value.
   */
  entry(title: unknown, read: () => void) {
    const index = ++this.entries;
    const extras = this.extras.size;
    const attachments = this.attachments;
    try {
      read();
    } catch {
      // What the broken entry had noted so far goes with it.
      [...this.extras].slice(extras).forEach((item) => this.extras.delete(item));
      this.attachments = attachments;
      const name = typeof title === 'string' ? title.trim().slice(0, 80) : '';
      this.skipped.push(name || `#${index}`);
    }
  }

  item(type: ItemType, name?: string | null): ExportItem {
    const item: ExportItem = {
      type,
      name: name?.trim() ?? '',
      notes: null,
      favorite: false,
      reprompt: 0,
      folderId: null,
      fields: [],
    };
    this.retype(item, type);
    return item;
  }

  /** Makes `item` a `type`, with that type's empty part. */
  retype(item: ExportItem, type: ItemType) {
    item.type = type;
    if (type === ItemType.Login)
      item.login ??= { username: null, password: null, totp: null, uris: [] };
    if (type === ItemType.Note) item.secureNote = { type: 0 };
    if (type === ItemType.Card) item.card ??= emptyCard();
    if (type === ItemType.Identity) item.identity ??= emptyIdentity();
  }

  login(name?: string | null) {
    const item = this.item(ItemType.Login, name);
    return item as ExportItem & { login: NonNullable<ExportItem['login']> };
  }

  add(item: ExportItem, folder?: string | null) {
    item.folderId = folder ? this.folder(folder) : null;
    this.items.push(item);
  }

  /**
   * The id of the folder `name`; "A/B" (or "A\B") is B inside A, and A is made too, as
   * Bitwarden's apps show nested folders.
   */
  folder(name: string): string | null {
    const clean = name
      .replace(/\\/g, '/')
      .split('/')
      .map((part) => part.trim())
      .filter(Boolean)
      .join('/');
    if (!clean) return null;
    const parts = clean.split('/');
    for (let i = 1; i <= parts.length; i++) {
      const path = parts.slice(0, i).join('/');
      if (!this.folderIds.has(path)) {
        const id = `folder-${this.folders.length + 1}`;
        this.folderIds.set(path, id);
        this.folders.push({ id, name: path });
      }
    }
    return this.folderIds.get(clean)!;
  }

  uris(item: ExportItem, ...uris: (string | null | undefined)[]) {
    if (!item.login) return;
    for (const uri of uris) {
      // javascript:, data: and the like: kept, as text, but not as an address to open.
      if (uri && unsafeUri(uri)) {
        this.extra(item, 'URL', uri.trim(), FieldType.Text);
        continue;
      }
      const fixed = uri ? fixUri(uri) : null;
      if (fixed && !item.login.uris.some((known) => known.uri === fixed)) {
        item.login.uris.push({ uri: fixed, match: null });
      }
    }
  }

  appendNote(item: ExportItem, text: string | null | undefined) {
    if (blank(text)) return;
    const clean = text.replace(/\r\n?/g, '\n').trimEnd();
    item.notes = item.notes ? `${item.notes}\n${clean}` : clean;
  }

  /**
   * A custom field the source had as one. Long values and values with several lines go into
   * the notes, as "name: value".
   */
  field(item: ExportItem, name: string, value: string | null | undefined, type?: FieldType) {
    if (blank(value)) return;
    const kind = type ?? (secretLooking(name) ? FieldType.Hidden : FieldType.Text);
    if (kind !== FieldType.Hidden && (value.length > 200 || /[\r\n]/.test(value.trim()))) {
      this.appendNote(item, `${name}: ${value.replace(/\r\n?/g, '\n')}`);
      return;
    }
    item.fields.push({ name, value, type: kind });
  }

  /** A value the vault has no place for: kept as a custom field, and the preview says so. */
  extra(item: ExportItem, name: string, value: string | null | undefined, type?: FieldType) {
    if (blank(value)) return;
    this.extras.add(item);
    this.field(item, name, value, type);
  }

  /**
   * Makes `item` a Wi-Fi network: a secure note with the marker and the network's fields in
   * front of the fields it has (docs/wifi.md). A security the contract has no name for stays
   * as a field of its own, and the network gets the likeliest one.
   */
  wifi(item: ExportItem, entry: WifiEntry) {
    this.retype(item, ItemType.Note);
    const security = securityOf(entry.security) ?? (blank(entry.password) ? 'None' : 'WPA2');
    if (!blank(entry.security) && !securityOf(entry.security)) {
      this.extra(item, `${WIFI_FIELD.security} (${t('Original')})`, entry.security);
    }
    const ssid = some(entry.ssid) ?? item.name;
    const own: ExportField[] = [
      { name: WIFI_MARKER, value: WIFI_TYPE, type: FieldType.Text },
      { name: WIFI_FIELD.ssid, value: ssid, type: FieldType.Text },
      { name: WIFI_FIELD.password, value: entry.password ?? '', type: FieldType.Hidden },
      { name: WIFI_FIELD.security, value: security, type: FieldType.Text },
      {
        name: WIFI_FIELD.hidden,
        value: entry.hidden ? 'true' : 'false',
        type: FieldType.Boolean,
      },
    ];
    if (security.endsWith('-Enterprise')) {
      const enterprise = [
        [WIFI_FIELD.eap, entry.eap],
        [WIFI_FIELD.phase2, entry.phase2],
        [WIFI_FIELD.identity, entry.identity],
        [WIFI_FIELD.anonymous, entry.anonymous],
        [WIFI_FIELD.ca, entry.ca],
      ] as const;
      for (const [name, value] of enterprise) {
        if (!blank(value)) own.push({ name, value: value.trim(), type: FieldType.Text });
      }
    }
    // A field of the contract the item had already (from the file) gives way to the network's.
    const names = new Set(own.map((field) => field.name));
    item.fields = [...own, ...item.fields.filter((field) => !names.has(field.name))];
    if (!item.name.trim()) item.name = ssid ?? '';
  }

  /**
   * An item that came with UwULock's Wi-Fi marker (a KeePass entry, a Bitwarden CSV row, or one
   * an importer made): a proper network, its password in the network's field, and the fields in
   * the contract's order and kinds.
   */
  private wifiFromMarker(item: ExportItem) {
    const get = (name: string) => item.fields.find((field) => field.name === name)?.value;
    const login = item.login;
    const password = get(WIFI_FIELD.password) ?? login?.password ?? null;
    if (login && password === login.password) login.password = null;
    this.wifi(item, {
      ssid: get(WIFI_FIELD.ssid),
      password,
      security: get(WIFI_FIELD.security),
      hidden: get(WIFI_FIELD.hidden)?.trim().toLowerCase() === 'true',
      eap: get(WIFI_FIELD.eap),
      phase2: get(WIFI_FIELD.phase2),
      identity: get(WIFI_FIELD.identity),
      anonymous: get(WIFI_FIELD.anonymous),
      ca: get(WIFI_FIELD.ca),
    });
  }

  attachment(count = 1) {
    this.attachments += count;
  }

  warn(text: string) {
    if (!this.warnings.includes(text)) this.warnings.push(text);
  }

  result(): { data: BitwardenExport; warnings: string[] } {
    for (const item of this.items) {
      if (hasWifiMarker(item)) this.wifiFromMarker(item);
      if (!item.name.trim()) item.name = '--';
      // A card or a note with a password or an address from the source: kept, as fields.
      if (item.type !== ItemType.Login && item.login) {
        const { username, password, totp, uris } = item.login;
        if (username !== item.identity?.username) this.extra(item, t('Benutzername'), username);
        this.extra(item, t('Passwort'), password, FieldType.Hidden);
        this.extra(item, 'TOTP', totp, FieldType.Hidden);
        uris.forEach((uri) => this.extra(item, 'URL', uri.uri, FieldType.Text));
      }
      const login = item.login;
      if (
        item.type === ItemType.Login &&
        login &&
        blank(login.username) &&
        blank(login.password) &&
        blank(login.totp) &&
        login.uris.length === 0
      ) {
        this.retype(item, ItemType.Note);
      }
      if (item.type !== ItemType.Login) delete item.login;
      if (item.type !== ItemType.Note) delete item.secureNote;
      if (item.type !== ItemType.Card) delete item.card;
      if (item.type !== ItemType.Identity) delete item.identity;
      if (blank(item.notes)) item.notes = null;
      if (item.passwordHistory?.length === 0) delete item.passwordHistory;
    }
    const warnings = [...this.warnings];
    if (this.extras.size > 0) {
      warnings.push(
        t(
          '{n} Einträge mit Feldern ohne eigenen Platz: als eigene Felder oder Notizen übernommen.',
          {
            n: this.extras.size,
          },
        ),
      );
    }
    if (this.skipped.length > 0) {
      const shown = this.skipped.slice(0, 10).join(', ');
      const more = this.skipped.length - 10;
      warnings.push(
        t('{n} Einträge ließen sich nicht lesen und bleiben weg: {names}', {
          n: this.skipped.length,
          names: more > 0 ? `${shown} ${t('… und {n} weitere', { n: more })}` : shown,
        }),
      );
    }
    if (this.attachments > 0) {
      warnings.push(
        t(
          '{n} Anhänge kommen nicht mit. Speichere sie aus der alten App und hänge sie danach wieder an.',
          { n: this.attachments },
        ),
      );
    }
    // Only folders something is in, or that something is in below them: the used ones and
    // every folder on their paths.
    const used = new Set(this.items.map((item) => item.folderId));
    const keep = new Set<string>();
    for (const folder of this.folders) {
      if (!used.has(folder.id)) continue;
      const parts = folder.name.split('/');
      for (let i = 1; i <= parts.length; i++) keep.add(parts.slice(0, i).join('/'));
    }
    const folders = this.folders.filter((folder) => keep.has(folder.name));
    return { data: { encrypted: false, folders, items: this.items }, warnings };
  }
}
