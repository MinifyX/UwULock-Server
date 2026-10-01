import { describe, expect, it } from 'vitest';
import type { FieldKind, ItemDetail } from './api';
import { escapeQr, readWifi, securityOf, wifiFields, wifiQr, type WifiInput } from './wifi';

type DetailField = NonNullable<ItemDetail['fields']>[number];

/** The fields as the details hand them out: hidden ones without their value. */
function detailFields(fields: [string, string, FieldKind][]): DetailField[] {
  return fields.map(([name, value, kind], index) => ({
    index,
    name,
    kind,
    value: kind === 'hidden' ? null : value,
    hasValue: value !== '',
  }));
}

const enterprise = detailFields([
  ['Router admin', 'http://192.0.2.1', 'text'],
  ['uwulock:type', 'wifi', 'text'],
  ['SSID', 'campus', 'text'],
  ['Password', 'secret', 'hidden'],
  ['Security', 'WPA2-Enterprise', 'text'],
  ['Hidden network', 'true', 'boolean'],
  ['EAP method', 'PEAP', 'text'],
  ['Phase 2', 'MSCHAPV2', 'text'],
  ['Identity', 'nyu@example.com', 'text'],
  ['Anonymous identity', 'anonymous@example.com', 'text'],
  ['CA certificate', 'radius.example.com', 'text'],
  ['PIN', '1234', 'hidden'],
]);

/** What the editor sends for the network it read, nothing changed. */
function unchanged(fields: DetailField[]): WifiInput {
  const view = readWifi(fields);
  return {
    ssid: view.ssid,
    security: view.security,
    hidden: view.hidden,
    eap: view.eap,
    phase2: view.phase2,
    identity: view.identity,
    anonymous: view.anonymous,
    ca: view.ca,
    password: null,
    from: view.from,
  };
}

const others = (fields: DetailField[]) =>
  readWifi(fields).others.map((f) => ({
    name: f.name,
    kind: f.kind,
    value: f.kind === 'hidden' ? null : f.value,
    from: f.index,
  }));

describe('a Wi-Fi network in fields', () => {
  it('reads the contract and leaves the rest as other fields', () => {
    const view = readWifi(enterprise);
    expect(view).toMatchObject({
      ssid: 'campus',
      security: 'WPA2-Enterprise',
      hidden: true,
      eap: 'PEAP',
      phase2: 'MSCHAPV2',
      identity: 'nyu@example.com',
      anonymous: 'anonymous@example.com',
      ca: 'radius.example.com',
    });
    expect(view.password?.index).toBe(3);
    expect(view.from).toMatchObject({ marker: 1, ssid: 2, password: 3, security: 4, hidden: 5 });
    expect(view.others.map((f) => f.name)).toEqual(['Router admin', 'PIN']);
  });

  it('goes back unchanged: same values, the password kept by its field, others in order', () => {
    const fields = wifiFields(unchanged(enterprise), others(enterprise));
    expect(fields.map((f) => [f.name, f.kind, f.value, f.from])).toEqual([
      ['uwulock:type', 'text', 'wifi', 1],
      ['SSID', 'text', 'campus', 2],
      ['Password', 'hidden', null, 3],
      ['Security', 'text', 'WPA2-Enterprise', 4],
      ['Hidden network', 'boolean', 'true', 5],
      ['EAP method', 'text', 'PEAP', 6],
      ['Phase 2', 'text', 'MSCHAPV2', 7],
      ['Identity', 'text', 'nyu@example.com', 8],
      ['Anonymous identity', 'text', 'anonymous@example.com', 9],
      ['CA certificate', 'text', 'radius.example.com', 10],
      ['Router admin', 'text', 'http://192.0.2.1', 0],
      ['PIN', 'hidden', null, 11],
    ]);
    // And read again, it is the same network.
    const again = detailFields(
      fields.map((f) => [f.name ?? '', f.value ?? 'kept', f.kind] as [string, string, FieldKind]),
    );
    expect(readWifi(again)).toMatchObject({ ssid: 'campus', eap: 'PEAP', hidden: true });
  });

  it('keeps the Enterprise fields only for Enterprise', () => {
    const input = { ...unchanged(enterprise), security: 'WPA2' };
    const names = wifiFields(input, []).map((f) => f.name);
    expect(names).toEqual(['uwulock:type', 'SSID', 'Password', 'Security', 'Hidden network']);
  });

  it('leaves Enterprise-looking fields of a personal network alone, as other fields', () => {
    const fields = detailFields([
      ['uwulock:type', 'wifi', 'text'],
      ['SSID', 'home', 'text'],
      ['Security', 'WPA3', 'text'],
      ['Identity', 'not ours', 'text'],
    ]);
    const view = readWifi(fields);
    expect(view.identity).toBe('');
    expect(view.others.map((f) => f.name)).toEqual(['Identity']);
    const written = wifiFields(unchanged(fields), others(fields));
    expect(written.at(-1)).toMatchObject({ name: 'Identity', value: 'not ours', from: 3 });
  });

  it('makes a new network with a password the editor typed', () => {
    const input: WifiInput = {
      ssid: 'new',
      security: 'WPA3',
      hidden: false,
      eap: 'PEAP',
      phase2: 'MSCHAPV2',
      identity: '',
      anonymous: '',
      ca: '',
      password: 'pw',
      from: {},
    };
    expect(wifiFields(input, [])).toEqual([
      { name: 'uwulock:type', kind: 'text', value: 'wifi', from: null },
      { name: 'SSID', kind: 'text', value: 'new', from: null },
      { name: 'Password', kind: 'hidden', value: 'pw', from: null },
      { name: 'Security', kind: 'text', value: 'WPA3', from: null },
      { name: 'Hidden network', kind: 'boolean', value: 'false', from: null },
    ]);
  });
});

describe('the QR code', () => {
  it('escapes backslash, semicolon, comma, colon and quote', () => {
    expect(escapeQr('a\\b;c,d:e"f')).toBe('a\\\\b\\;c\\,d\\:e\\"f');
  });

  it('writes WPA, WEP and open networks as phones read them', () => {
    const base = { ssid: 'uwu;net', password: 'p:w"1', hidden: false };
    expect(wifiQr({ ...base, security: 'WPA2' })).toBe('WIFI:T:WPA;S:uwu\\;net;P:p\\:w\\"1;;');
    expect(wifiQr({ ...base, security: 'WPA3', hidden: true })).toBe(
      'WIFI:T:WPA;S:uwu\\;net;P:p\\:w\\"1;H:true;;',
    );
    expect(wifiQr({ ...base, security: 'WEP' })).toMatch(/^WIFI:T:WEP;/);
    expect(wifiQr({ ...base, security: 'None' })).toBe('WIFI:T:nopass;S:uwu\\;net;;');
  });

  it('writes Enterprise with method, phase 2 and identities', () => {
    expect(
      wifiQr({
        ssid: 'campus',
        password: 'pw',
        security: 'WPA2-Enterprise',
        hidden: false,
        eap: 'PEAP',
        phase2: 'MSCHAPV2',
        identity: 'nyu@example.com',
        anonymous: 'anonymous@example.com',
      }),
    ).toBe(
      'WIFI:T:WPA2-EAP;S:campus;E:PEAP;PH2:MSCHAPV2;A:anonymous@example.com;I:nyu@example.com;P:pw;;',
    );
    expect(
      wifiQr({
        ssid: 'campus',
        password: 'pw',
        security: 'WPA3-Enterprise',
        hidden: false,
        eap: 'TLS',
        phase2: 'none',
      }),
    ).toBe('WIFI:T:WPA2-EAP;S:campus;E:TLS;P:pw;;');
  });

  it('quotes an SSID that would read as hex', () => {
    expect(wifiQr({ ssid: 'CAFE', password: '', security: 'None', hidden: false })).toBe(
      'WIFI:T:nopass;S:"CAFE";;',
    );
  });
});

describe('securities from other apps', () => {
  it.each([
    ['WPA2', 'WPA2'],
    ['wpa2/wpa3', 'WPA2/WPA3'],
    ['WPA2 Personal', 'WPA2'],
    ['wpa2p', 'WPA2'],
    ['WPA2-PSK', 'WPA2'],
    ['wpa3p', 'WPA3'],
    ['WPA2 Enterprise', 'WPA2-Enterprise'],
    ['wpa2e', 'WPA2-Enterprise'],
    ['wpa3e', 'WPA3-Enterprise'],
    ['WPA', 'WPA'],
    ['WEP', 'WEP'],
    ['none', 'None'],
    ['Open', 'None'],
    ['No Security', 'None'],
  ])('%s is %s', (text, security) => {
    expect(securityOf(text)).toBe(security);
  });

  it('knows nothing else', () => {
    expect(securityOf('')).toBeNull();
    expect(securityOf('quantum')).toBeNull();
  });
});
