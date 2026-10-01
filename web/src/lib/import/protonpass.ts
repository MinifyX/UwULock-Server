/**
 * Proton Pass: its unencrypted JSON export (data.json, alone or in the zip Proton Pass writes as
 * "Proton Pass/data.json") and its CSV export. Vaults hold items of the types login, alias,
 * note, credit card, identity, SSH key and custom, each with extra fields of its own.
 *
 * Field mapping after Bitwarden's importer (bitwarden/clients,
 * libs/importer/src/importers/protonpass/protonpass-json-importer.ts, GPL-3.0). Unlike Bitwarden,
 * vaults become folders only when there are several.
 */

import { t } from '../i18n';
import { ImportError } from './bytes';
import { blank, cardBrand, Collector, some, splitName } from './collect';
import type { CsvTable } from './csv';
import { FieldType, ItemType, type ExportItem } from './types';

type ExtraField = {
  fieldName?: string;
  type?: 'text' | 'hidden' | 'totp' | 'timestamp';
  data?: { content?: string; totpUri?: string; timestamp?: string | number };
};

type Section = { sectionName?: string; sectionFields?: ExtraField[] };

type Content = Record<string, unknown> & {
  itemEmail?: string;
  itemUsername?: string;
  password?: string;
  urls?: string[];
  totpUri?: string;
  passkeys?: unknown[];
  sections?: Section[];
};

type ProtonItem = {
  state?: number;
  pinned?: boolean;
  aliasEmail?: string | null;
  data?: {
    type?: string;
    metadata?: { name?: string; note?: string };
    extraFields?: ExtraField[];
    content?: Content;
  };
};

export type ProtonExport = {
  encrypted?: boolean;
  vaults?: Record<string, { name?: string; items?: ProtonItem[] }>;
};

const TRASHED = 2;

/**
 * Proton Pass's Wi-Fi security, a number in its export (its `WifiSecurity`: 0 unspecified,
 * 1 WPA, 2 WPA2, 3 WPA3, 4 WEP) or, in some versions, the name.
 */
function wifiSecurity(value: unknown): string | null {
  if (typeof value === 'string') return /^\d+$/.test(value) ? wifiSecurity(Number(value)) : value;
  if (typeof value !== 'number') return null;
  return ({ 1: 'WPA', 2: 'WPA2', 3: 'WPA3', 4: 'WEP' } as Record<number, string>)[value] ?? null;
}

/** Identity fields with a place of their own; every other one becomes a custom field. */
const IDENTITY_KEYS = [
  'fullName',
  'firstName',
  'middleName',
  'lastName',
  'email',
  'phoneNumber',
  'company',
  'socialSecurityNumber',
  'passportNumber',
  'licenseNumber',
  'organization',
  'streetAddress',
  'floor',
  'county',
  'city',
  'stateOrProvince',
  'zipOrPostalCode',
  'countryOrRegion',
];
const IDENTITY_LISTS = [
  'extraPersonalDetails',
  'extraAddressDetails',
  'extraContactDetails',
  'extraWorkDetails',
];

function extraFields(collector: Collector, item: ExportItem, fields: ExtraField[] | undefined) {
  for (const field of fields ?? []) {
    const data = field.data ?? {};
    const value =
      field.type === 'totp'
        ? data.totpUri
        : field.type === 'timestamp'
          ? String(data.timestamp ?? '')
          : data.content;
    const hidden = field.type === 'totp' || field.type === 'hidden';
    collector.field(item, field.fieldName ?? '', value, hidden ? FieldType.Hidden : FieldType.Text);
  }
}

function sections(collector: Collector, item: ExportItem, list: Section[] | undefined) {
  for (const section of list ?? []) extraFields(collector, item, section.sectionFields);
}

function readItem(collector: Collector, entry: ProtonItem): ExportItem | null {
  const data = entry.data ?? {};
  const content: Content = data.content ?? {};
  const str = (key: string) => (typeof content[key] === 'string' ? (content[key] as string) : '');
  const item = collector.login(data.metadata?.name);
  item.favorite = entry.pinned === true;
  collector.appendNote(item, data.metadata?.note);
  const login = item.login;

  switch (data.type) {
    case 'login': {
      collector.uris(item, ...(content.urls ?? []));
      login.username = some(content.itemUsername) ?? some(content.itemEmail);
      if (login.username && login.username !== content.itemEmail) {
        collector.field(item, 'email', content.itemEmail);
      }
      login.password = some(content.password);
      login.totp = some(content.totpUri);
      if (content.passkeys?.length) {
        collector.warn(
          t('Passkeys aus Proton Pass kommen nicht mit; melde dich damit neu an, wo du sie nutzt.'),
        );
      }
      break;
    }
    case 'alias':
      // An address that forwards mail: kept as a login with the address as its user name.
      login.username = some(entry.aliasEmail);
      break;
    case 'note':
      collector.retype(item, ItemType.Note);
      break;
    case 'creditCard': {
      collector.retype(item, ItemType.Card);
      const card = item.card!;
      card.cardholderName = some(str('cardholderName'));
      card.number = some(str('number'));
      card.brand = cardBrand(card.number);
      card.code = some(str('verificationNumber'));
      // "2027-03"
      const expiry = str('expirationDate');
      if (expiry) {
        card.expYear = expiry.slice(0, 4);
        card.expMonth = String(Number(expiry.slice(5, 7))) || null;
      }
      collector.field(item, 'PIN', str('pin'), FieldType.Hidden);
      break;
    }
    case 'identity': {
      collector.retype(item, ItemType.Identity);
      const identity = item.identity!;
      const [first, middle, last] = splitName(str('fullName'));
      const named = str('firstName') || str('middleName') || str('lastName');
      identity.firstName = named ? some(str('firstName')) : first;
      identity.middleName = named ? some(str('middleName')) : middle;
      identity.lastName = named ? some(str('lastName')) : last;
      identity.email = some(str('email'));
      identity.phone = some(str('phoneNumber'));
      identity.company = some(str('company'));
      identity.ssn = some(str('socialSecurityNumber'));
      identity.passportNumber = some(str('passportNumber'));
      identity.licenseNumber = some(str('licenseNumber'));
      identity.address1 = some(str('organization'));
      identity.address2 = some(str('streetAddress'));
      identity.address3 = some(`${str('floor')} ${str('county')}`.trim());
      identity.city = some(str('city'));
      identity.state = some(str('stateOrProvince'));
      identity.postalCode = some(str('zipOrPostalCode'));
      identity.country = some(str('countryOrRegion'));
      for (const [key, value] of Object.entries(content)) {
        if (IDENTITY_KEYS.includes(key)) continue;
        if (IDENTITY_LISTS.includes(key)) extraFields(collector, item, value as ExtraField[]);
        else if (key === 'extraSections') sections(collector, item, value as Section[]);
        else if (typeof value === 'string') collector.extra(item, key, value);
      }
      break;
    }
    case 'sshKey': {
      const [privateKey, publicKey, fingerprint] = [
        str('privateKey'),
        str('publicKey'),
        str('fingerprint'),
      ];
      if (privateKey && publicKey && fingerprint) {
        collector.retype(item, ItemType.SshKey);
        item.sshKey = { privateKey, publicKey, keyFingerprint: fingerprint };
      } else {
        // The vault needs all three; what there is stays, in a note.
        collector.retype(item, ItemType.Note);
        collector.field(item, t('Privater Schlüssel'), privateKey, FieldType.Hidden);
        collector.field(item, t('Öffentlicher Schlüssel'), publicKey, FieldType.Text);
        collector.field(item, t('Fingerabdruck'), fingerprint, FieldType.Text);
      }
      sections(collector, item, content.sections);
      break;
    }
    case 'custom':
      collector.retype(item, ItemType.Note);
      sections(collector, item, content.sections);
      break;
    case 'wifi':
      collector.wifi(item, {
        ssid: str('ssid'),
        password: str('password'),
        security: wifiSecurity(content.security),
      });
      sections(collector, item, content.sections);
      break;
    default:
      return null;
  }
  extraFields(collector, item, data.extraFields);
  return item;
}

export function readProtonJson(data: ProtonExport, collector: Collector) {
  if (data.encrypted) throw encrypted();
  if (!data.vaults || typeof data.vaults !== 'object') {
    throw new ImportError(t('Das sieht nicht nach einem Export von Proton Pass aus.'));
  }
  const vaults = Object.values(data.vaults);
  let trashed = 0;
  let unknown = 0;
  for (const vault of vaults) {
    const folder = vaults.length > 1 ? (vault.name ?? null) : null;
    for (const entry of vault.items ?? []) {
      collector.entry(entry?.data?.metadata?.name, () => {
        if (entry.state === TRASHED) {
          trashed++;
          return;
        }
        const item = readItem(collector, entry);
        if (item) collector.add(item, folder);
        else unknown++;
      });
    }
  }
  if (trashed) {
    collector.warn(t('{n} Einträge aus dem Papierkorb bleiben weg.', { n: trashed }));
  }
  if (unknown) {
    collector.warn(
      t('{n} Einträge einer Art, die UwULock nicht kennt, bleiben weg.', { n: unknown }),
    );
  }
}

export const encrypted = () =>
  new ImportError(
    t(
      'Dieser Export von Proton Pass ist mit PGP verschlüsselt. Exportiere noch einmal ohne Verschlüsselung (JSON oder CSV) und importiere diese Datei.',
    ),
  );

/** Proton Pass's CSV: "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault". */
export function readProtonCsv(table: CsvTable, collector: Collector) {
  if (!table.has('type', 'name', 'url', 'username', 'password', 'note')) {
    throw new ImportError(t('Das sieht nicht nach einem Export von Proton Pass aus.'));
  }
  const vaults = new Set(table.rows.map((row) => table.get(row, 'vault')));
  const known = ['type', 'name', 'url', 'email', 'username', 'password', 'note', 'totp', 'vault'];
  const bookkeeping = ['createTime', 'modifyTime'];
  for (const row of table.rows) {
    const item = collector.login(table.get(row, 'name'));
    const type = table.get(row, 'type');
    collector.appendNote(item, table.get(row, 'note'));
    if (type === 'note') collector.retype(item, ItemType.Note);
    if (type === 'wifi') {
      // The CSV has the network's name only as the item's name.
      collector.wifi(item, {
        ssid: table.get(row, 'name'),
        password: table.get(row, 'password'),
        security: null,
      });
      for (const [name, value] of table.rest(row, [...known, ...bookkeeping])) {
        collector.extra(item, name, value);
      }
      collector.add(item, vaults.size > 1 ? table.get(row, 'vault') || null : null);
      continue;
    }
    const email = table.get(row, 'email');
    item.login.username = some(table.get(row, 'username')) ?? some(email);
    if (item.login.username !== email && !blank(email)) collector.field(item, 'email', email);
    item.login.password = some(table.get(row, 'password'));
    item.login.totp = some(table.get(row, 'totp'));
    collector.uris(item, ...table.get(row, 'url').split(/,\s*/));
    for (const [name, value] of table.rest(row, [...known, ...bookkeeping])) {
      collector.extra(item, name, value);
    }
    collector.add(item, vaults.size > 1 ? table.get(row, 'vault') || null : null);
  }
}
