import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readImport, summarize } from './index';
import type { ExportItem, Source } from './types';

const fixture = (name: string) =>
  new Uint8Array(readFileSync(join(process.cwd(), 'src/lib/import/fixtures', name)));
const bytes = (text: string) => new TextEncoder().encode(text);

async function read(name: string, source: Source | 'auto' = 'auto', content = fixture(name)) {
  const parsed = await readImport({ name, bytes: content }, source);
  const byName = (item: string) => {
    const found = parsed.data.items.find((i) => i.name === item);
    if (!found) throw new Error(`no item ${item}`);
    return found;
  };
  return { parsed, byName };
}

/** The item's fields as [name, value, type], in their order. */
const fields = (item: ExportItem) => item.fields.map((f) => [f.name, f.value, f.type]);

describe('Wi-Fi networks from other apps', () => {
  it('1Password: a Wireless Router becomes a network, the base station stays in fields', async () => {
    for (const file of ['1password-wifi.1pux', '1password-wifi.json']) {
      const { parsed, byName } = await read(file, '1password');
      const home = byName('Zuhause');
      expect(home).toMatchObject({ type: 2, favorite: true, notes: 'Router im Flur' });
      expect(home.login).toBeUndefined();
      expect(fields(home)).toEqual([
        ['uwulock:type', 'wifi', 0],
        ['SSID', 'uwu-net', 0],
        ['Password', 'correct; horse', 1],
        ['Security', 'WPA2', 0],
        ['Hidden network', 'false', 2],
        ['base station name', 'Fritz', 0],
        ['base station password', 'admin-pass', 1],
        ['server / IP address', '192.0.2.1', 0],
        ['attached storage password', 'disk-pass', 1],
        ['Tags', 'home', 0],
      ]);
      // No name of its own: the SSID; an open network has no password to keep.
      const guests = byName('Gäste');
      expect(fields(guests).slice(1, 4)).toEqual([
        ['SSID', 'Gäste', 0],
        ['Password', '', 1],
        ['Security', 'None', 0],
      ]);
      expect(summarize(parsed)).toMatchObject({ wifi: 2, notes: 0, logins: 0 });
    }
  });

  it('1Password’s older CSV: the wireless columns, the row’s password as the base station’s', async () => {
    const csv =
      'title,type,username,password,network name,wireless security,wireless network password\n' +
      'Router,Wireless Router,,admin-pass,uwu-net,WPA2 Personal,wifi-pass\n';
    const { byName } = await read('export.csv', '1password', bytes(csv));
    const router = byName('Router');
    expect(router.type).toBe(2);
    expect(fields(router).slice(0, 4)).toEqual([
      ['uwulock:type', 'wifi', 0],
      ['SSID', 'uwu-net', 0],
      ['Password', 'wifi-pass', 1],
      ['Security', 'WPA2', 0],
    ]);
    expect(router.fields.find((f) => f.value === 'admin-pass')?.type).toBe(1);
  });

  it('Proton Pass: its wifi items, with their security, from JSON and CSV', async () => {
    const { parsed, byName } = await read('protonpass-wifi.json');
    expect(fields(byName('Büro'))).toEqual([
      ['uwulock:type', 'wifi', 0],
      ['SSID', 'office-5g', 0],
      ['Password', 'pp-wifi', 1],
      ['Security', 'WPA3', 0],
      ['Hidden network', 'false', 2],
      ['Raum', '2.14', 0],
    ]);
    expect(byName('Büro').notes).toBe('Nur im 2. Stock');
    expect(fields(byName('Altes Netz'))[3]).toEqual(['Security', 'WEP', 0]);
    expect(parsed.warnings).toEqual([]);

    const csv = await read('protonpass-wifi.csv');
    const net = csv.byName('uwu-net');
    expect(net).toMatchObject({ type: 2, notes: 'Router im Flur' });
    expect(fields(net).slice(1, 4)).toEqual([
      ['SSID', 'uwu-net', 0],
      ['Password', 'pp-wifi', 1],
      ['Security', 'WPA2', 0],
    ]);
    expect(csv.byName('Beispiel').type).toBe(1);
  });

  it('LastPass: the Wi-Fi Password form, with Enterprise', async () => {
    const { byName } = await read('lastpass-wifi.csv');
    const home = byName('Zuhause');
    expect(home).toMatchObject({ type: 2, notes: 'Router im Flur' });
    expect(fields(home)).toEqual([
      ['uwulock:type', 'wifi', 0],
      ['SSID', 'uwu-net', 0],
      ['Password', 'lp-wifi', 1],
      ['Security', 'WPA2', 0],
      ['Hidden network', 'false', 2],
      ['Connection Type', 'ESS', 0],
      ['Connection Mode', 'auto', 0],
      ['Encryption', 'AES', 0],
    ]);
    expect(fields(byName('Campus'))[3]).toEqual(['Security', 'WPA2-Enterprise', 0]);
  });

  it('KeePass: an entry with UwULock’s marker, its password moved into the network', async () => {
    const { byName } = await read('keepass-wifi.xml', 'keepass');
    const home = byName('Zuhause');
    expect(home.type).toBe(2);
    expect(home.login).toBeUndefined();
    expect(fields(home)).toEqual([
      ['uwulock:type', 'wifi', 0],
      ['SSID', 'uwu-net', 0],
      ['Password', 'kp-wifi', 1],
      ['Security', 'WPA3', 0],
      ['Hidden network', 'true', 2],
      ['Router', 'http://192.0.2.1', 0],
    ]);
    expect(byName('Mail').login!.password).toBe('x');
  });

  it('Bitwarden’s JSON with the marker goes to the vault as it is, counted as a network', async () => {
    const { parsed } = await read('bitwarden-wifi.json');
    expect(parsed.submit.text).toBe(new TextDecoder().decode(fixture('bitwarden-wifi.json')));
    const summary = summarize(parsed);
    expect(summary).toMatchObject({ wifi: 1, notes: 1 });
    expect(summary.items.map((i) => [i.name, i.wifi])).toEqual([
      ['Campus', true],
      ['Notiz', false],
    ]);
  });

  it('keeps a security it has no name for as a field of its own', async () => {
    const data = {
      vaults: {
        a: {
          items: [
            {
              data: {
                metadata: { name: 'Lab' },
                type: 'wifi',
                content: { ssid: 'lab', password: 'pw', security: 'WAPI-PSK' },
              },
            },
          ],
        },
      },
    };
    const { byName } = await read('x.json', 'protonpass', bytes(JSON.stringify(data)));
    const lab = byName('Lab');
    expect(lab.fields.find((f) => f.name === 'Security')?.value).toBe('WPA2');
    expect(lab.fields.some((f) => f.value === 'WAPI-PSK')).toBe(true);
  });
});
