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
import {
  FieldType,
  ItemType,
  type BitwardenExport,
  type ExportCard,
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

export class Collector {
  private folders: ExportFolder[] = [];
  private folderIds = new Map<string, string>();
  private items: ExportItem[] = [];
  private extras = new Set<ExportItem>();
  private attachments = 0;
  private warnings: string[] = [];

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

  attachment(count = 1) {
    this.attachments += count;
  }

  warn(text: string) {
    if (!this.warnings.includes(text)) this.warnings.push(text);
  }

  result(): { data: BitwardenExport; warnings: string[] } {
    for (const item of this.items) {
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
    if (this.attachments > 0) {
      warnings.push(
        t(
          '{n} Anhänge kommen nicht mit. Speichere sie aus der alten App und hänge sie danach wieder an.',
          { n: this.attachments },
        ),
      );
    }
    // Only folders something is in, or that something is in below them.
    const used = new Set(this.items.map((item) => item.folderId));
    const names = new Set(
      this.folders.filter((folder) => used.has(folder.id)).map((folder) => folder.name),
    );
    const folders = this.folders.filter((folder) =>
      [...names].some((name) => name === folder.name || name.startsWith(`${folder.name}/`)),
    );
    return { data: { encrypted: false, folders, items: this.items }, warnings };
  }
}
