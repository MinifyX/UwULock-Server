/**
 * 1Password: the .1pux export (a zip with export.data: accounts → vaults → items, each with a
 * category, login fields and sections of typed fields) and the CSV exports (1Password 8's
 * "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes", and the older ones with
 * columns of their own).
 *
 * Field mapping after Bitwarden's importers (bitwarden/clients, libs/importer/src/importers/
 * onepassword/onepassword-1pux-importer.ts and onepassword-*-csv-importer.ts, GPL-3.0):
 * categories to item types, section fields by id to the card or identity, TOTP fields to the
 * login, everything else to custom fields. Unlike Bitwarden, vaults (when there are several)
 * become folders, tags stay as a field, and bank accounts become notes, not cards.
 */

import { t } from '../i18n';
import { ImportError, text } from './bytes';
import { blank, cardBrand, Collector, some, splitName } from './collect';
import type { CsvTable } from './csv';
import { FieldType, ItemType, type ExportItem } from './types';
import type { Archive } from './zip';

const Category = {
  Login: '001',
  CreditCard: '002',
  SecureNote: '003',
  Identity: '004',
  Password: '005',
  Document: '006',
  SoftwareLicense: '100',
  BankAccount: '101',
  Database: '102',
  DriversLicense: '103',
  OutdoorLicense: '104',
  Membership: '105',
  Passport: '106',
  RewardsProgram: '107',
  SocialSecurityNumber: '108',
  WirelessRouter: '109',
  Server: '110',
  EmailAccount: '111',
  ApiCredential: '112',
  MedicalRecord: '113',
  SshKey: '114',
} as const;

type Value = {
  string?: string;
  concealed?: string;
  totp?: string;
  url?: string;
  phone?: string;
  menu?: string;
  gender?: string;
  reference?: string;
  creditCardNumber?: string;
  creditCardType?: string;
  date?: number;
  monthYear?: number;
  email?: { email_address?: string; provider?: string | null };
  address?: { street?: string; city?: string; country?: string; zip?: string; state?: string };
  sshKey?: {
    privateKey?: string;
    metadata?: { privateKey?: string; publicKey?: string; fingerprint?: string };
  };
};

type Field = { title?: string; id?: string; value?: Value };

type Item1pux = {
  uuid?: string;
  favIndex?: number;
  state?: string;
  categoryUuid?: string;
  overview?: { title?: string; url?: string; urls?: { url?: string }[]; tags?: string[] };
  details?: {
    loginFields?: { value?: string; name?: string; fieldType?: string; designation?: string }[];
    notesPlain?: string;
    sections?: { title?: string; fields?: Field[] }[];
    passwordHistory?: { value?: string; time?: number }[];
    documentAttributes?: { fileName?: string };
    password?: string;
  };
};

type ExportData = {
  accounts?: { vaults?: { attrs?: { name?: string }; items?: Item1pux[] }[] }[];
};

/** A section field's value as text. */
function valueText(value: Value): string {
  if (value.date != null) return new Date(value.date * 1000).toISOString().slice(0, 10);
  if (value.monthYear != null) {
    const digits = String(value.monthYear);
    return `${digits.slice(4, 6)}/${digits.slice(0, 4)}`;
  }
  if (value.email) return value.email.email_address ?? '';
  if (value.address) {
    const a = value.address;
    return [a.street, [a.zip, a.city].filter(Boolean).join(' '), a.state, a.country]
      .filter((part) => !blank(part))
      .join(', ');
  }
  const first = Object.values(value).find((v) => typeof v === 'string');
  return typeof first === 'string' ? first : '';
}

function itemType(category: string | undefined): ItemType {
  switch (category) {
    case Category.CreditCard:
      return ItemType.Card;
    case Category.Identity:
    case Category.DriversLicense:
    case Category.OutdoorLicense:
    case Category.Membership:
    case Category.Passport:
    case Category.RewardsProgram:
    case Category.SocialSecurityNumber:
      return ItemType.Identity;
    case Category.SecureNote:
    case Category.SoftwareLicense:
    case Category.BankAccount:
    case Category.EmailAccount:
    case Category.MedicalRecord:
    case Category.Document:
      return ItemType.Note;
    case Category.SshKey:
      return ItemType.SshKey;
    default:
      return ItemType.Login;
  }
}

/** Puts a section field where it belongs; false when it has no place and becomes a field. */
function place(item: ExportItem, category: string | undefined, field: Field, value: string) {
  const id = field.id ?? '';
  const title = field.title ?? '';
  const v = field.value!;
  const login = item.login;
  if (item.type === ItemType.Login && login) {
    const api = category === Category.ApiCredential;
    if (!login.username && title === 'username') login.username = value;
    else if (!login.password && (title === 'password' || (api && title === 'credential')))
      login.password = value;
    else if (!login.totp && (id.startsWith('TOTP_') || v.totp != null)) login.totp = value;
    else if (
      login.uris.length === 0 &&
      ((category === Category.Server && id === 'url') || (api && title === 'hostname'))
    )
      login.uris.push({ uri: value, match: null });
    else return false;
    return true;
  }
  const card = item.card;
  if (item.type === ItemType.Card && card) {
    if (!card.number && id === 'ccnum') {
      card.number = value;
      card.brand = cardBrand(value);
    } else if (!card.code && id === 'cvv') card.code = value;
    else if (!card.cardholderName && id === 'cardholder') card.cardholderName = value;
    else if (!card.expMonth && id === 'expiry' && v.monthYear != null) {
      const digits = String(v.monthYear);
      card.expYear = digits.slice(0, 4);
      card.expMonth = String(Number(digits.slice(4, 6)));
    } else if (id !== 'type') return false; // The type follows from the number.
    return true;
  }
  const identity = item.identity;
  if (item.type === ItemType.Identity && identity) {
    const set = (key: keyof typeof identity, candidates: string[]) => {
      if (identity[key] || !candidates.includes(id)) return false;
      identity[key] = value;
      return true;
    };
    const fullName = (candidates: string[]) => {
      if (identity.firstName || !candidates.includes(id)) return false;
      [identity.firstName, identity.middleName, identity.lastName] = splitName(value);
      return true;
    };
    if (v.address && !identity.address1) {
      identity.address1 = some(v.address.street);
      identity.city = some(v.address.city);
      identity.postalCode = some(v.address.zip);
      identity.state = some(v.address.state);
      identity.country = some(v.address.country?.toUpperCase());
      return true;
    }
    if (set('firstName', ['firstname']) || set('lastName', ['lastname'])) return true;
    if (set('middleName', ['initial']) || set('company', ['company'])) return true;
    if (set('phone', ['defphone']) || set('username', ['username'])) return true;
    if (!identity.email && (v.email || id === 'email')) {
      identity.email = value;
      return true;
    }
    switch (category) {
      case Category.DriversLicense:
        return (
          fullName(['fullname']) ||
          set('licenseNumber', ['number']) ||
          set('country', ['country']) ||
          set('state', ['state']) ||
          set('address1', ['address'])
        );
      case Category.OutdoorLicense:
        return fullName(['name']) || set('country', ['country']) || set('state', ['state']);
      case Category.Membership:
        return fullName(['member_name']) || set('company', ['org_name']) || set('phone', ['phone']);
      case Category.Passport:
        return (
          fullName(['fullname']) ||
          set('passportNumber', ['number']) ||
          set('country', ['issuing_country'])
        );
      case Category.RewardsProgram:
        return fullName(['member_name']) || set('company', ['company_name']);
      case Category.SocialSecurityNumber:
        return fullName(['name']) || set('ssn', ['number']);
    }
  }
  return false;
}

function read1puxItem(collector: Collector, entry: Item1pux): ExportItem {
  const category = entry.categoryUuid;
  const details = entry.details ?? {};
  const overview = entry.overview ?? {};
  const item = collector.item(itemType(category), overview.title);
  collector.retype(item, ItemType.Login);
  item.type = itemType(category);
  item.favorite = entry.favIndex === 1;
  const urls = (overview.urls ?? []).map((u) => u.url);
  collector.uris(item, ...(urls.length ? urls : [overview.url]));

  for (const field of details.loginFields ?? []) {
    const value = field.value ?? '';
    if (field.designation === 'username' && value) {
      collector.retype(item, ItemType.Login);
      item.login!.username = value;
    } else if (field.designation === 'password' && value) {
      collector.retype(item, ItemType.Login);
      item.login!.password = value;
    } else if (field.fieldType === 'C') {
      // A ticked box on the website's form; an empty one is nothing worth keeping.
      if (value) collector.field(item, field.name ?? '', 'true', FieldType.Boolean);
    } else {
      const hidden = field.fieldType === 'P' ? FieldType.Hidden : undefined;
      collector.field(item, field.name ?? '', value, hidden);
    }
  }
  if (category === Category.Password && details.password) item.login!.password = details.password;

  const history = (details.passwordHistory ?? [])
    .filter((h) => !blank(h.value) && h.time != null)
    .sort((a, b) => b.time! - a.time!)
    .slice(0, 5)
    .map((h) => ({
      password: h.value!,
      lastUsedDate: new Date(String(h.time).length >= 13 ? h.time! : h.time! * 1000).toISOString(),
    }));
  if (history.length) item.passwordHistory = history;

  for (const section of details.sections ?? []) {
    for (const field of section.fields ?? []) {
      const v = field.value;
      if (!v) continue;
      if (v.sshKey && item.type === ItemType.SshKey) {
        const meta = v.sshKey.metadata ?? {};
        if (meta.privateKey && meta.publicKey && meta.fingerprint) {
          item.sshKey = {
            privateKey: meta.privateKey,
            publicKey: meta.publicKey,
            keyFingerprint: meta.fingerprint,
          };
          continue;
        }
      }
      const value = valueText(v);
      if (blank(value)) continue;
      if (place(item, category, field, value)) continue;
      const name = field.title || section.title || '';
      if (field.title === 'password' && item.passwordHistory?.some((h) => h.password === value)) {
        continue;
      }
      const hidden = v.concealed != null || v.sshKey != null ? FieldType.Hidden : undefined;
      collector.field(item, name, value, hidden);
      if (v.email?.provider) collector.field(item, 'provider', v.email.provider);
    }
  }
  if (item.type === ItemType.SshKey && !item.sshKey) collector.retype(item, ItemType.Note);
  if (details.documentAttributes) collector.attachment();

  const tags = overview.tags ?? [];
  if (tags.length) collector.extra(item, 'Tags', tags.join(', '));
  collector.appendNote(item, details.notesPlain);
  return item;
}

export async function read1pux(zip: Archive, collector: Collector) {
  if (!zip.names.includes('export.data')) {
    throw new ImportError(t('Das ist keine 1PUX-Datei von 1Password (export.data fehlt).'));
  }
  const data = JSON.parse(text(await zip.read('export.data'))) as ExportData;
  const vaults = (data.accounts ?? []).flatMap((account) => account.vaults ?? []);
  const several = vaults.length > 1;
  let archived = 0;
  for (const vault of vaults) {
    const folder = several ? (vault.attrs?.name ?? null) : null;
    for (const entry of vault.items ?? []) {
      if (entry.state === 'archived') archived++;
      collector.add(read1puxItem(collector, entry), folder);
    }
  }
  // Documents and files attached to items, stored beside export.data.
  const files = zip.names.filter((name) => name.startsWith('files/') && !name.endsWith('/'));
  const counted = vaults.flatMap((v) => v.items ?? []).filter((i) => i.details?.documentAttributes);
  if (files.length > counted.length) collector.attachment(files.length - counted.length);
  if (archived) {
    collector.warn(t('{n} archivierte Einträge kommen als normale Einträge mit.', { n: archived }));
  }
}

/** Columns of 1Password's CSVs that are its own bookkeeping. */
const BOOKKEEPING = ['uuid', 'ainfo', 'autosubmit', 'ps', 'scope', 'created date', 'modified date'];

export function read1PasswordCsv(table: CsvTable, collector: Collector) {
  if (!table.has('title')) {
    throw new ImportError(t('Das sieht nicht nach einem CSV-Export von 1Password aus.'));
  }
  const used = new Set([
    'title',
    'url',
    'urls',
    'website',
    'username',
    'password',
    'otpauth',
    'one-time password',
    'favorite',
    'archived',
    'tags',
    'notes',
    'notesplain',
    'type',
    ...BOOKKEEPING,
  ]);
  let archived = 0;
  for (const row of table.rows) {
    const kind = table.get(row, 'type').toLowerCase();
    const type =
      kind === 'credit card'
        ? ItemType.Card
        : kind === 'identity'
          ? ItemType.Identity
          : ItemType.Login;
    const item = collector.item(type, table.get(row, 'title'));
    collector.retype(item, ItemType.Login);
    item.type = type;
    const login = item.login!;
    login.username = some(table.get(row, 'username'));
    login.password = some(table.get(row, 'password'));
    login.totp = some(table.get(row, 'otpauth', 'one-time password'));
    collector.uris(item, ...table.get(row, 'urls', 'url', 'website').split(/\r?\n/));
    item.favorite = ['true', '1', 'yes'].includes(table.get(row, 'favorite').toLowerCase());
    if (['true', '1', 'yes'].includes(table.get(row, 'archived').toLowerCase())) archived++;
    collector.appendNote(item, table.get(row, 'notesPlain'));
    collector.appendNote(item, table.get(row, 'notes'));
    const tags = table.get(row, 'tags');
    if (tags) collector.extra(item, 'Tags', tags);

    for (const [name, value] of table.rest(row, [...used])) {
      const lower = name.toLowerCase();
      const card = item.card;
      const identity = item.identity;
      if (card && !card.number && lower.includes('number') && !lower.includes('verification')) {
        card.number = value;
        card.brand = cardBrand(value);
      } else if (card && !card.code && lower.includes('verification number')) card.code = value;
      else if (card && !card.cardholderName && lower.includes('cardholder'))
        card.cardholderName = value;
      else if (card && !card.expMonth && lower.includes('expiry date')) {
        // "MM/YYYY", or "YYYYMM"
        const match =
          value.match(/^(\d{1,2})\/(?:\d{1,2}\/)?(\d{4})/) ?? value.match(/^(\d{4})(\d{2})$/);
        if (match) {
          const [monthPart, yearPart] =
            match[1]!.length === 4 ? [match[2]!, match[1]!] : [match[1]!, match[2]!];
          card.expMonth = String(Number(monthPart));
          card.expYear = yearPart;
        } else collector.extra(item, name, value);
      } else if (identity && !identity.firstName && lower.includes('first name'))
        identity.firstName = value;
      else if (identity && !identity.middleName && lower.includes('initial'))
        identity.middleName = value;
      else if (identity && !identity.lastName && lower.includes('last name'))
        identity.lastName = value;
      else if (identity && !identity.email && lower.includes('email')) identity.email = value;
      else if (identity && !identity.phone && lower.includes('phone')) identity.phone = value;
      else if (identity && !identity.company && lower.includes('company')) identity.company = value;
      else if (identity && !identity.username && lower.includes('username'))
        identity.username = value;
      else collector.extra(item, name, value);
    }
    if (item.type === ItemType.Identity && login.username && !item.identity!.username) {
      item.identity!.username = login.username;
    }
    collector.add(item);
  }
  if (archived) {
    collector.warn(t('{n} archivierte Einträge kommen als normale Einträge mit.', { n: archived }));
  }
}
