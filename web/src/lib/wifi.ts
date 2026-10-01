/**
 * Wi-Fi networks: UwULock's own item type on top of Bitwarden's secure note. The network lives
 * in custom fields with fixed English names, so Bitwarden's apps show a note with fields and
 * every UwULock app shows a Wi-Fi network (docs/wifi.md has the contract):
 *
 *   uwulock:type (text) = wifi · SSID (text) · Password (hidden) · Security (text) ·
 *   Hidden network (boolean) · for Enterprise only: EAP method, Phase 2, Identity,
 *   Anonymous identity, CA certificate (text)
 *
 * The WebAssembly module recognises the marker and lists the item with the kind `wifi`; the
 * page reads and writes the fields here. Fields that are not part of the contract stay as they
 * are, in their order, after the network's own.
 */

import type { Draft, FieldKind, ItemDetail } from './api';

export const WIFI_MARKER = 'uwulock:type';
export const WIFI_TYPE = 'wifi';

/** The field names. Stable and never translated: other apps read them. */
export const WIFI_FIELD = {
  ssid: 'SSID',
  password: 'Password',
  security: 'Security',
  hidden: 'Hidden network',
  eap: 'EAP method',
  phase2: 'Phase 2',
  identity: 'Identity',
  anonymous: 'Anonymous identity',
  ca: 'CA certificate',
} as const;

export const SECURITIES = [
  'WPA3',
  'WPA2/WPA3',
  'WPA2',
  'WPA',
  'WEP',
  'None',
  'WPA2-Enterprise',
  'WPA3-Enterprise',
] as const;
export type Security = (typeof SECURITIES)[number];

export const EAP_METHODS = ['PEAP', 'TTLS', 'TLS', 'PWD'] as const;
export const PHASE2_METHODS = ['MSCHAPV2', 'PAP', 'GTC', 'none'] as const;

export const isEnterprise = (security: string) => security.endsWith('-Enterprise');

/** The text fields of the contract, besides SSID and Security: only for Enterprise. */
export const ENTERPRISE_KEYS = ['eap', 'phase2', 'identity', 'anonymous', 'ca'] as const;
type TextKey = 'ssid' | 'security' | (typeof ENTERPRISE_KEYS)[number];

type DetailField = NonNullable<ItemDetail['fields']>[number];

/** A network as the details have it: values, and which field each came from. */
export type WifiView = Record<TextKey, string> & {
  hidden: boolean;
  /** The password's field, for showing and copying it by index (`field:<n>`). */
  password: DetailField | null;
  /** Where each of the network's fields is in the item, the marker's under `marker`. */
  from: Partial<Record<TextKey | 'hidden' | 'password' | 'marker', number>>;
  /** Every other field, in its order. */
  others: DetailField[];
};

/** Reads a network out of an item's fields. The first field of each name counts. */
export function readWifi(fields: DetailField[]): WifiView {
  const view: WifiView = {
    ssid: '',
    security: '',
    eap: '',
    phase2: '',
    identity: '',
    anonymous: '',
    ca: '',
    hidden: false,
    password: null,
    from: {},
    others: [],
  };
  const taken = new Set<number>();
  const find = (name: string) =>
    fields.find((field) => field.name === name && !taken.has(field.index));
  const take = (key: keyof WifiView['from'], name: string) => {
    const field = find(name);
    if (!field) return null;
    taken.add(field.index);
    view.from[key] = field.index;
    return field;
  };
  const marker = fields.find(
    (field) =>
      field.name === WIFI_MARKER &&
      field.kind === 'text' &&
      field.value?.trim().toLowerCase() === WIFI_TYPE,
  );
  if (marker) {
    taken.add(marker.index);
    view.from.marker = marker.index;
  }
  view.ssid = take('ssid', WIFI_FIELD.ssid)?.value ?? '';
  view.security = take('security', WIFI_FIELD.security)?.value?.trim() ?? '';
  view.password = take('password', WIFI_FIELD.password);
  const hidden = take('hidden', WIFI_FIELD.hidden);
  view.hidden = hidden?.value?.trim().toLowerCase() === 'true';
  // An Enterprise field on a network that is not Enterprise is someone else's: it stays a
  // field of its own.
  if (isEnterprise(view.security)) {
    for (const key of ENTERPRISE_KEYS) view[key] = take(key, WIFI_FIELD[key])?.value ?? '';
  }
  view.others = fields.filter((field) => !taken.has(field.index));
  return view;
}

/** What the editor has of a network. A password it never saw is `null`. */
export type WifiInput = Record<TextKey, string> & {
  hidden: boolean;
  password: string | null;
  from: WifiView['from'];
};

type DraftField = Draft['fields'][number];

/**
 * The item's fields for a network: the contract's first, in its order, then `others` as they
 * are. Enterprise fields only for Enterprise, and only with a value.
 */
export function wifiFields(input: WifiInput, others: DraftField[]): DraftField[] {
  const field = (
    key: keyof WifiView['from'],
    name: string,
    kind: FieldKind,
    value: string | null,
  ): DraftField => ({ name, kind, value, from: input.from[key] ?? null });
  const fields = [
    field('marker', WIFI_MARKER, 'text', WIFI_TYPE),
    field('ssid', WIFI_FIELD.ssid, 'text', input.ssid),
    field('password', WIFI_FIELD.password, 'hidden', input.password),
    field('security', WIFI_FIELD.security, 'text', input.security),
    field('hidden', WIFI_FIELD.hidden, 'boolean', input.hidden ? 'true' : 'false'),
  ];
  if (isEnterprise(input.security)) {
    for (const key of ENTERPRISE_KEYS) {
      if (input[key].trim()) fields.push(field(key, WIFI_FIELD[key], 'text', input[key].trim()));
    }
  }
  return [...fields, ...others];
}

/** A value inside a `WIFI:` code: `\ ; , : "` get a backslash. */
export function escapeQr(value: string): string {
  return value.replace(/[\\;,:"]/g, (char) => `\\${char}`);
}

/**
 * The text of the QR code that phones join a network with:
 * `WIFI:T:WPA;S:<ssid>;P:<password>;H:true;;`, and for Enterprise
 * `WIFI:T:WPA2-EAP;S:…;E:<eap>;PH2:<phase 2>;A:<anonymous>;I:<identity>;P:<password>;;`.
 * Parts without a value are left out. An SSID that reads as hex is quoted, or a phone would
 * take it for bytes.
 */
export function wifiQr(network: {
  ssid: string;
  password: string;
  security: string;
  hidden: boolean;
  eap?: string;
  phase2?: string;
  identity?: string;
  anonymous?: string;
}): string {
  const security = network.security;
  const enterprise = isEnterprise(security);
  const type = enterprise
    ? 'WPA2-EAP'
    : security === 'None'
      ? 'nopass'
      : security === 'WEP'
        ? 'WEP'
        : 'WPA';
  const ssid = /^(?:[0-9a-f]{2})+$/i.test(network.ssid)
    ? `"${escapeQr(network.ssid)}"`
    : escapeQr(network.ssid);
  const parts = [`T:${type}`, `S:${ssid}`];
  const add = (key: string, value: string | undefined) => {
    if (value && value.trim()) parts.push(`${key}:${escapeQr(value)}`);
  };
  if (enterprise) {
    add('E', network.eap);
    add('PH2', network.phase2 === 'none' ? '' : network.phase2);
    add('A', network.anonymous);
    add('I', network.identity);
  }
  if (type !== 'nopass') add('P', network.password);
  if (network.hidden) parts.push('H:true');
  return `WIFI:${parts.join(';')};;`;
}

/**
 * One of the contract's securities for whatever another app calls it ("WPA2 Personal",
 * "wpa2p", "WPA2-PSK", "Open", …), or `null` when it is none of them.
 */
export function securityOf(text: string | null | undefined): Security | null {
  const raw = (text ?? '').trim();
  const exact = SECURITIES.find((s) => s.toLowerCase() === raw.toLowerCase());
  if (exact) return exact;
  const plain = raw.toLowerCase().replace(/[\s_-]+/g, '');
  if (!plain) return null;
  if (['none', 'open', 'nopass', 'nosecurity', 'unsecured', 'unencrypted', 'off'].includes(plain))
    return 'None';
  const enterprise = /enterprise|eap|802\.?1x|^wpa[23]?e$/.test(plain);
  const wpa3 = plain.includes('wpa3');
  const wpa2 = plain.includes('wpa2');
  if (enterprise) return wpa3 && !wpa2 ? 'WPA3-Enterprise' : 'WPA2-Enterprise';
  if (wpa2 && wpa3) return 'WPA2/WPA3';
  if (wpa3) return 'WPA3';
  if (wpa2) return 'WPA2';
  if (plain.includes('wpa')) return 'WPA';
  if (plain.includes('wep')) return 'WEP';
  return null;
}
