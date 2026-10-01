/**
 * LastPass's CSV export: "url,username,password,totp,extra,name,grouping,fav". A secure note has
 * the address http://sn; a note with a "NoteType:" line is a form of LastPass's (a card, an
 * address, a passport, …) with one "Key:Value" per line. The form-fill profiles of older exports
 * (profilename, ccnum, firstname, …) become cards and identities.
 *
 * Field mapping after Bitwarden's importer (bitwarden/clients,
 * libs/importer/src/importers/lastpass/lastpass-csv-importer.ts, GPL-3.0).
 */

import { t } from '../i18n';
import { ImportError } from './bytes';
import { cardBrand, Collector, some, splitName } from './collect';
import type { CsvTable } from './csv';
import { ItemType, type ExportCard, type ExportIdentity, type ExportItem } from './types';

const MONTHS = [
  'january',
  'february',
  'march',
  'april',
  'may',
  'june',
  'july',
  'august',
  'september',
  'october',
  'november',
  'december',
];

/** "June" → "6". */
function month(name: string | undefined): string | null {
  const index = MONTHS.indexOf((name ?? '').trim().toLowerCase());
  return index < 0 ? null : String(index + 1);
}

type Mapping<T> = Record<string, keyof T>;

const CARD: Mapping<ExportCard> = {
  Number: 'number',
  'Name on Card': 'cardholderName',
  'Security Code': 'code',
};

const ADDRESS: Mapping<ExportIdentity> = {
  Title: 'title',
  'First Name': 'firstName',
  'Middle Name': 'middleName',
  'Last Name': 'lastName',
  Company: 'company',
  'Address 1': 'address1',
  'Address 2': 'address2',
  'Address 3': 'address3',
  'City / Town': 'city',
  State: 'state',
  'Zip / Postal Code': 'postalCode',
  Country: 'country',
  'Email Address': 'email',
  Username: 'username',
  Phone: 'phone',
};

const PASSPORT: Mapping<ExportIdentity> = { Number: 'passportNumber', Country: 'country' };
const LICENSE: Mapping<ExportIdentity> = {
  Number: 'licenseNumber',
  State: 'state',
  Country: 'country',
  Address: 'address1',
  'City / Town': 'city',
  'Zip / Postal Code': 'postalCode',
};
const SSN: Mapping<ExportIdentity> = { Number: 'ssn' };

/** The "Key:Value" lines of a LastPass form; everything after "Notes:" is the note. */
function formLines(extra: string): { pairs: [string, string][]; notes: string } {
  const pairs: [string, string][] = [];
  const lines = extra.split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const key = line.slice(0, colon);
    if (key === 'Notes') {
      return { pairs, notes: [line.slice(colon + 1), ...lines.slice(i + 1)].join('\n') };
    }
    if (key !== 'NoteType') pairs.push([key, line.slice(colon + 1)]);
  }
  return { pairs, notes: '' };
}

function readForm(collector: Collector, item: ExportItem, extra: string) {
  const type = extra
    .split(/\r\n|\r|\n/, 1)[0]!
    .slice('NoteType:'.length)
    .trim();
  const { pairs, notes } = formLines(extra);
  let mapping: Mapping<ExportCard> | Mapping<ExportIdentity> | null = null;
  let fullName: string | null = null;
  if (type === 'Wi-Fi Password') {
    readWifiForm(collector, item, pairs, notes);
    return;
  }
  if (type === 'Credit Card') {
    collector.retype(item, ItemType.Card);
    mapping = CARD;
  } else if (['Address', 'Passport', "Driver's License", 'Social Security'].includes(type)) {
    collector.retype(item, ItemType.Identity);
    mapping = { Address: ADDRESS, Passport: PASSPORT, "Driver's License": LICENSE }[type] ?? SSN;
  } else {
    collector.retype(item, ItemType.Note);
    collector.extra(item, 'NoteType', type);
  }
  for (const [key, value] of pairs) {
    if (!some(value)) continue;
    if (item.card && key === 'Expiration Date') {
      // "June,2020"
      const [name, year] = value.split(',');
      item.card.expMonth = month(name);
      item.card.expYear = some(year?.trim());
      continue;
    }
    if (item.identity && key === 'Name' && type !== 'Address') {
      fullName = value;
      continue;
    }
    // Only the mapping's own keys: "constructor" or "toString" in a form is just a field.
    const target = mapping && Object.hasOwn(mapping, key) ? mapping[key] : undefined;
    if (target && item.card) (item.card as Record<string, string | null>)[target] = value;
    else if (target && item.identity)
      (item.identity as Record<string, string | null>)[target] = value;
    else collector.extra(item, key, value);
  }
  if (item.card) item.card.brand = cardBrand(item.card.number);
  if (item.identity && fullName) {
    [item.identity.firstName, item.identity.middleName, item.identity.lastName] =
      splitName(fullName);
  }
  collector.appendNote(item, notes);
}

/**
 * LastPass's "Wi-Fi Password" form: SSID, Password and Authentication ("WPA2-PSK", "WEP",
 * "WPA2-Enterprise", …) make the network; Connection Type, Encryption and the rest stay fields.
 */
function readWifiForm(
  collector: Collector,
  item: ExportItem,
  pairs: [string, string][],
  notes: string,
) {
  const network: { ssid?: string; password?: string; security?: string } = {};
  for (const [key, value] of pairs) {
    if (!some(value)) continue;
    if (key === 'SSID' && network.ssid === undefined) network.ssid = value;
    else if (key === 'Password' && network.password === undefined) network.password = value;
    else if (key === 'Authentication' && network.security === undefined) network.security = value;
    else if (key !== 'Language') collector.field(item, key, value);
  }
  collector.wifi(item, network);
  collector.appendNote(item, notes);
}

function profileCard(table: CsvTable, row: string[], item: ExportItem) {
  const card = item.card!;
  card.cardholderName = some(table.get(row, 'ccname'));
  card.number = some(table.get(row, 'ccnum'));
  card.code = some(table.get(row, 'cccsc'));
  card.brand = cardBrand(card.number);
  // "2025-06"
  const [year, monthNumber] = table.get(row, 'ccexp').split('-');
  if (year && monthNumber) {
    card.expYear = year;
    card.expMonth = String(Number(monthNumber));
  }
}

export function readLastPassCsv(table: CsvTable, collector: Collector) {
  const profiles = table.has('profilename');
  if (!profiles && !table.has('url', 'username', 'password', 'extra', 'name')) {
    throw new ImportError(t('Das sieht nicht nach einem CSV-Export von LastPass aus.'));
  }
  for (const row of table.rows) {
    const grouping = table
      .get(row, 'grouping')
      // eslint-disable-next-line no-control-regex
      .replace(/[\x00-\x1f\x7f-\x9f]/g, '');
    const folder = grouping && grouping !== '(none)' ? grouping : null;

    if (profiles) {
      const name = table.get(row, 'profilename');
      const person = ['title', 'firstname', 'lastname', 'address1', 'phone', 'username', 'email'];
      const hasPerson = person.some((column) => table.get(row, column));
      if (hasPerson) {
        const item = collector.item(ItemType.Identity, name);
        const identity = item.identity!;
        const map: [keyof ExportIdentity, string][] = [
          ['title', 'title'],
          ['firstName', 'firstname'],
          ['middleName', 'middlename'],
          ['lastName', 'lastname'],
          ['username', 'username'],
          ['company', 'company'],
          ['ssn', 'ssn'],
          ['address1', 'address1'],
          ['address2', 'address2'],
          ['address3', 'address3'],
          ['city', 'city'],
          ['state', 'state'],
          ['postalCode', 'zip'],
          ['country', 'country'],
          ['email', 'email'],
          ['phone', 'phone'],
        ];
        for (const [target, column] of map) identity[target] = some(table.get(row, column));
        collector.appendNote(item, table.get(row, 'notes'));
        collector.add(item, folder);
      }
      if (!hasPerson || table.get(row, 'ccnum')) {
        const card = collector.item(ItemType.Card, name);
        profileCard(table, row, card);
        if (!hasPerson) collector.appendNote(card, table.get(row, 'notes'));
        collector.add(card, folder);
      }
      continue;
    }

    const url = table.get(row, 'url');
    const item = collector.login(table.get(row, 'name'));
    item.favorite = table.get(row, 'fav') === '1';
    const extra = table.get(row, 'extra');
    if (url === 'http://sn') {
      if (extra.startsWith('NoteType:')) readForm(collector, item, extra);
      else {
        collector.retype(item, ItemType.Note);
        collector.appendNote(item, extra);
      }
    } else {
      item.login.username = some(table.get(row, 'username'));
      item.login.password = some(table.get(row, 'password'));
      item.login.totp = some(table.get(row, 'totp'));
      collector.uris(item, url);
      collector.appendNote(item, extra);
    }
    collector.add(item, folder);
  }
}
