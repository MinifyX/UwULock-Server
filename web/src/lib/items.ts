/**
 * The names the vault's kinds and fields go by, in one place: the details and
 * the editor have to agree on them, and `field:`/`identity:` names are what
 * Rust expects when a single value is asked for.
 */

import type { FieldKind, ItemKind } from './api';
import { N_ } from './i18n';

export const KIND_LABEL: Record<ItemKind, string> = {
  login: N_('Login'),
  card: N_('Karte'),
  identity: N_('Identität'),
  note: N_('Sichere Notiz'),
  'ssh-key': N_('SSH-Schlüssel'),
};

/** The identity's fields, in the order they are shown. */
export const IDENTITY_FIELDS: { name: string; sensitive: boolean }[] = [
  { name: 'title', sensitive: false },
  { name: 'firstName', sensitive: false },
  { name: 'middleName', sensitive: false },
  { name: 'lastName', sensitive: false },
  { name: 'username', sensitive: false },
  { name: 'company', sensitive: false },
  { name: 'email', sensitive: false },
  { name: 'phone', sensitive: false },
  { name: 'address1', sensitive: false },
  { name: 'address2', sensitive: false },
  { name: 'address3', sensitive: false },
  { name: 'postalCode', sensitive: false },
  { name: 'city', sensitive: false },
  { name: 'state', sensitive: false },
  { name: 'country', sensitive: false },
  { name: 'ssn', sensitive: true },
  { name: 'passportNumber', sensitive: true },
  { name: 'licenseNumber', sensitive: true },
];

export const IDENTITY_LABEL: Record<string, string> = {
  title: N_('Anrede'),
  firstName: N_('Vorname'),
  middleName: N_('Zweiter Vorname'),
  lastName: N_('Nachname'),
  username: N_('Benutzername'),
  company: N_('Firma'),
  email: N_('E-Mail'),
  phone: N_('Telefon'),
  address1: N_('Adresse'),
  address2: N_('Adresse 2'),
  address3: N_('Adresse 3'),
  postalCode: N_('Postleitzahl'),
  city: N_('Ort'),
  state: N_('Bundesland'),
  country: N_('Land'),
  ssn: N_('Sozialversicherungsnummer'),
  passportNumber: N_('Reisepassnummer'),
  licenseNumber: N_('Führerscheinnummer'),
};

export const FIELD_KIND_LABEL: Record<FieldKind, string> = {
  text: N_('Text'),
  hidden: N_('Versteckt'),
  boolean: N_('Ja/Nein'),
  linked: N_('Verknüpft'),
};

/** How Bitwarden decides an address belongs to a site. `null` is the account's default. */
export const MATCH_LABEL: Record<number, string> = {
  0: N_('Domain'),
  1: N_('Host'),
  2: N_('Beginnt mit'),
  3: N_('Genau'),
  4: N_('Regulärer Ausdruck'),
  5: N_('Nie'),
};

/** The card brands Bitwarden knows. Anything else stays as it is. */
export const CARD_BRANDS = [
  'Visa',
  'Mastercard',
  'American Express',
  'Discover',
  'Diners Club',
  'JCB',
  'Maestro',
  'UnionPay',
  'RuPay',
];
