import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { t } from '../i18n';
import { androidApp } from './browsers';
import { Collector } from './collect';
import { detect, readImport, summarize } from './index';
import { checkFileSize, MAX_FILE_BYTES, MAX_ZIP_ENTRIES } from './limits';
import type { ExportItem, Parsed, Source } from './types';

const fixture = (name: string) =>
  new Uint8Array(readFileSync(join(process.cwd(), 'src/lib/import/fixtures', name)));
const bytes = (text: string) => new TextEncoder().encode(text);

async function read(name: string, source: Source | 'auto' = 'auto', content = fixture(name)) {
  const parsed = await readImport({ name, bytes: content }, source);
  const folders = new Map(parsed.data.folders.map((f) => [f.id, f.name]));
  const byName = (item: string) => {
    const found = parsed.data.items.find((i) => i.name === item);
    if (!found) throw new Error(`no item ${item}`);
    return found;
  };
  const folderOf = (item: ExportItem) => (item.folderId ? folders.get(item.folderId) : null);
  return { parsed, byName, folderOf };
}

const field = (item: ExportItem, name: string) => item.fields.find((f) => f.name === name);
const uris = (item: ExportItem) => item.login!.uris.map((u) => u.uri);
const extras = (parsed: Parsed, n: number) =>
  expect(parsed.warnings).toContain(
    t('{n} Einträge mit Feldern ohne eigenen Platz: als eigene Felder oder Notizen übernommen.', {
      n,
    }),
  );

describe('recognising a file', () => {
  it.each([
    ['argon2id-chacha20.kdbx', 'keepass'],
    ['keepassxc.csv', 'keepass'],
    ['keepass2.csv', 'keepass'],
    ['1password.1pux', '1password'],
    ['1password.csv', '1password'],
    ['chrome.csv', 'chrome'],
    ['firefox.csv', 'firefox'],
    ['apple.csv', 'apple'],
    ['protonpass.json', 'protonpass'],
    ['protonpass.zip', 'protonpass'],
    ['protonpass.csv', 'protonpass'],
    ['lastpass.csv', 'lastpass'],
  ])('%s is from %s', (name, source) => {
    expect(detect(fixture(name))).toBe(source);
  });

  it('knows Bitwarden’s exports, and gives up on anything else', () => {
    expect(detect(bytes('{"encrypted":false,"folders":[],"items":[]}'))).toBe('bitwarden');
    expect(detect(bytes('folder,favorite,type,name,notes,fields,reprompt,login_uri\n'))).toBe(
      'bitwarden',
    );
    expect(detect(bytes('Spalte A,Spalte B\n1,2\n'))).toBeNull();
  });

  it('asks for the app when it can’t tell', async () => {
    await expect(readImport({ name: 'x.csv', bytes: bytes('a,b\n1,2\n') }, 'auto')).rejects.toThrow(
      t('UwULock erkennt nicht, aus welcher App diese Datei kommt. Wähl die App bitte aus.'),
    );
  });
});

describe('browsers', () => {
  it('Chrome: names, Android apps, quotes and notes', async () => {
    const { parsed, byName } = await read('chrome.csv');
    expect(byName('Beispiel').login).toMatchObject({
      username: 'nyu@example.com',
      password: 'pa,ss"word',
    });
    const app = byName('com.example.app');
    expect(uris(app)).toEqual(['androidapp://com.example.app']);
    expect(app.notes).toBe('Zeile 1\nZeile 2');
    expect(parsed.warnings).toEqual([]);
  });

  it('Firefox: name from the host, the realm kept, its own account left out', async () => {
    const { parsed, byName } = await read('firefox.csv');
    expect(parsed.data.items.map((i) => i.name)).toEqual(['example.org', 'intranet.example.net']);
    const intranet = byName('intranet.example.net');
    expect(intranet.login!.password).toBe('basic-pass');
    expect(field(intranet, 'httpRealm')?.value).toBe('Intranet');
    extras(parsed, 1);
  });

  it('Apple Passwords: TOTP and notes, a name from the address when there is none', async () => {
    const { byName } = await read('apple.csv');
    const item = byName('example.com (nyu)');
    expect(item.login!.totp).toContain('otpauth://totp/');
    expect(item.notes).toBe('Notiz');
    expect(byName('shop.example.net').login!.username).toBe('mika');
  });
});

describe('KeePass CSV', () => {
  it('KeePassXC: groups below the root as folders, TOTP', async () => {
    const { parsed, byName, folderOf } = await read('keepassxc.csv');
    expect(parsed.data.folders.map((f) => f.name)).toEqual(['Privat', 'Privat/Banken']);
    expect(folderOf(byName('Router'))).toBeNull();
    const bank = byName('Bank');
    expect(folderOf(bank)).toBe('Privat/Banken');
    expect(bank.login!.totp).toBe('otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQ&period=30&digits=6');
    expect(uris(bank)).toEqual(['https://bank.example.org']);
    expect(bank.notes).toBe('Zeile 1\nZeile 2');
  });

  it('KeePass 2', async () => {
    const { byName } = await read('keepass2.csv');
    expect(byName('Mail')).toMatchObject({
      notes: 'Notiz',
      login: { username: 'nyu@example.com', password: 'mail-pass' },
    });
  });

  it('KeePass’s XML export', async () => {
    const xml = `<?xml version="1.0" encoding="utf-8"?><KeePassFile><Meta></Meta><Root><Group><Name>Root</Name>
      <Entry><String><Key>Title</Key><Value>Mail</Value></String>
      <String><Key>Password</Key><Value ProtectInMemory="True">x</Value></String>
      <String><Key>Geheim</Key><Value ProtectInMemory="True">y</Value></String></Entry>
      </Group></Root></KeePassFile>`;
    const { byName } = await read('export.xml', 'keepass', bytes(xml));
    expect(byName('Mail').login!.password).toBe('x');
    expect(field(byName('Mail'), 'Geheim')?.type).toBe(1);
  });
});

describe('1Password', () => {
  it('1PUX: categories, sections, TOTP, vaults as folders', async () => {
    const { parsed, byName, folderOf } = await read('1password.1pux');
    expect(parsed.format).toBe('1PUX');
    expect(parsed.data.folders.map((f) => f.name)).toEqual(['Privat', 'Geteilt']);

    const login = byName('Beispiel');
    expect(folderOf(login)).toBe('Privat');
    expect(login.favorite).toBe(true);
    expect(login.login).toMatchObject({
      username: 'nyu@example.com',
      password: '1p-pass',
      totp: 'otpauth://totp/Beispiel?secret=JBSWY3DPEHPK3PXP',
    });
    expect(uris(login)).toEqual(['https://example.com']);
    expect(field(login, 'Wiederherstellungscode')).toMatchObject({ value: 'rc-1234', type: 1 });
    expect(field(login, 'Seit')?.value).toBe('2023-11-14');
    expect(field(login, 'country')?.value).toBe('DE');
    expect(field(login, 'remember')).toBeUndefined();
    expect(field(login, 'Tags')?.value).toBe('privat');
    expect(login.passwordHistory?.[0]?.password).toBe('1p-old');
    expect(login.notes).toBe('Notiz zum Login');

    expect(byName('Reisekarte')).toMatchObject({
      type: 3,
      card: {
        cardholderName: 'Nyu Beispiel',
        number: '4111111111111111',
        brand: 'Visa',
        code: '123',
        expMonth: '6',
        expYear: '2030',
      },
    });
    expect(field(byName('Reisekarte'), 'PIN')?.type).toBe(1);
    expect(byName('Ich')).toMatchObject({
      type: 4,
      identity: {
        firstName: 'Nyu',
        lastName: 'Beispiel',
        email: 'nyu@example.com',
        address1: 'Musterweg 1',
        postalCode: '12345',
        city: 'Musterstadt',
        country: 'DE',
      },
    });
    expect(field(byName('Ich'), 'Beruf')?.value).toBe('Entwicklerin');
    expect(byName('Notiz')).toMatchObject({ type: 2, notes: 'Nur Text' });
    expect(byName('Vertrag').type).toBe(2);
    expect(byName('Altes Passwort')).toMatchObject({
      type: 1,
      login: { password: 'nur-ein-passwort' },
    });
    expect(folderOf(byName('Altes Passwort'))).toBe('Geteilt');
    expect(byName('Server-Schlüssel')).toMatchObject({
      type: 5,
      sshKey: { publicKey: 'ssh-ed25519 AAAA', keyFingerprint: 'SHA256:abcdefghijklmnop' },
    });
    expect(parsed.warnings).toContain(
      t('{n} archivierte Einträge kommen als normale Einträge mit.', { n: 1 }),
    );
    expect(parsed.warnings).toContain(
      t(
        '{n} Anhänge kommen nicht mit. Speichere sie aus der alten App und hänge sie danach wieder an.',
        {
          n: 1,
        },
      ),
    );
  });

  it('1Password 8’s CSV', async () => {
    const { parsed, byName } = await read('1password.csv');
    const item = byName('Beispiel');
    expect(item.favorite).toBe(true);
    expect(item.login!.totp).toContain('JBSWY3DPEHPK3PXP');
    expect(field(item, 'Tags')?.value).toBe('privat,web');
    expect(item.notes).toBe('Notiz');
    expect(parsed.warnings).toContain(
      t('{n} archivierte Einträge kommen als normale Einträge mit.', { n: 1 }),
    );
  });
});

describe('Proton Pass', () => {
  it('reads the JSON inside the zip: every item type, vaults as folders, trash left out', async () => {
    const { parsed, byName, folderOf } = await read('protonpass.zip');
    expect(parsed.data.folders.map((f) => f.name)).toEqual(['Persönlich', 'Arbeit']);
    expect(parsed.data.items.map((i) => i.name)).not.toContain('Gelöscht');

    const login = byName('Beispiel');
    expect(login.favorite).toBe(true);
    expect(login.login).toMatchObject({ username: 'nyu', password: 'pp-pass' });
    expect(login.login!.totp).toContain('JBSWY3DPEHPK3PXP');
    expect(uris(login)).toEqual(['https://example.com', 'https://login.example.com']);
    expect(field(login, 'email')?.value).toBe('nyu@example.com');
    expect(field(login, 'Sicherheitsfrage')?.type).toBe(1);
    expect(field(login, 'Zweiter Faktor')).toMatchObject({ type: 1 });
    expect(login.notes).toBe('Notiz zum Login');

    expect(byName('Reisekarte').card).toMatchObject({
      expMonth: '6',
      expYear: '2030',
      brand: 'Visa',
    });
    expect(field(byName('Reisekarte'), 'PIN')).toMatchObject({ value: '4321', type: 1 });
    const me = byName('Ich');
    expect(me.identity).toMatchObject({
      firstName: 'Nyu',
      middleName: 'Maria',
      lastName: 'Beispiel',
      address2: 'Musterweg 1',
      address3: '2',
      passportNumber: 'P123',
      company: 'Beispiel GmbH',
    });
    expect(field(me, 'jobTitle')?.value).toBe('Entwicklerin');
    expect(field(me, 'Lieblingsfarbe')?.value).toBe('Blau');
    expect(field(me, 'Mitgliedsnummer')?.type).toBe(1);

    const alias = byName('Newsletter-Alias');
    expect(folderOf(alias)).toBe('Arbeit');
    expect(alias.login!.username).toBe('alias.1234@example.net');
    expect(byName('WLAN')).toMatchObject({ type: 2, notes: 'Gastnetz' });
    expect(byName('Server-Schlüssel').type).toBe(5);
    expect(byName('Konto').type).toBe(2);
    expect(field(byName('Konto'), 'IBAN')?.value).toBe('DE00000000000000000000');
    expect(parsed.warnings).toContain(t('{n} Einträge aus dem Papierkorb bleiben weg.', { n: 1 }));
  });

  it('reads the JSON alone and the CSV', async () => {
    const json = await read('protonpass.json');
    expect(json.parsed.data.items).toHaveLength(7);
    const { byName, folderOf } = await read('protonpass.csv');
    expect(byName('Beispiel').login).toMatchObject({ username: 'nyu', password: 'pp-pass' });
    expect(byName('Notiz')).toMatchObject({ type: 2, notes: 'Nur Text' });
    expect(folderOf(byName('Alias'))).toBe('Arbeit');
    expect(byName('Alias').login!.username).toBe('alias@example.net');
  });

  it('turns away encrypted exports with a hint', async () => {
    const hint = t(
      'Dieser Export von Proton Pass ist mit PGP verschlüsselt. Exportiere noch einmal ohne Verschlüsselung (JSON oder CSV) und importiere diese Datei.',
    );
    const pgp = bytes('-----BEGIN PGP MESSAGE-----\n\nwcBMA0\n-----END PGP MESSAGE-----\n');
    await expect(read('data.pgp', 'auto', pgp)).rejects.toThrow(hint);
    await expect(
      read('x.json', 'protonpass', bytes('{"encrypted":true,"vaults":{}}')),
    ).rejects.toThrow(hint);
  });
});

describe('LastPass', () => {
  it('logins, secure notes, forms as cards and identities, folders with backslashes', async () => {
    const { parsed, byName, folderOf } = await read('lastpass.csv');
    const login = byName('Beispiel');
    expect(login.favorite).toBe(true);
    expect(folderOf(login)).toBe('Privat/Web');
    expect(login.login).toMatchObject({ password: 'lp-pass', totp: 'JBSWY3DPEHPK3PXP' });
    expect(login.notes).toBe('Notiz');

    const card = byName('Reisekarte');
    expect(card).toMatchObject({
      type: 3,
      card: {
        cardholderName: 'Nyu Beispiel',
        number: '4111111111111111',
        code: '123',
        expMonth: '6',
        expYear: '2030',
        brand: 'Visa',
      },
      notes: 'Karte fürs Reisen\nzweite Zeile',
    });
    expect(folderOf(card)).toBe('Finanzen');
    expect(byName('Adresse')).toMatchObject({
      type: 4,
      identity: { title: 'dr', firstName: 'Nyu', lastName: 'Beispiel', postalCode: '12345' },
    });
    expect(byName('Notiz')).toMatchObject({ type: 2, notes: 'Einfach eine Notiz', folderId: null });
    const account = byName('Konto');
    expect(account.type).toBe(2);
    expect(field(account, 'Bank Name')?.value).toBe('Beispielbank');
    expect(parsed.data.folders.map((f) => f.name)).toEqual(['Privat', 'Privat/Web', 'Finanzen']);
  });
});

describe('Bitwarden', () => {
  it('passes its JSON through unchanged, and turns away encrypted exports', async () => {
    const text = JSON.stringify({
      encrypted: false,
      folders: [{ id: 'f1', name: 'Privat' }],
      items: [{ type: 1, name: 'Mail', folderId: 'f1', login: { username: 'nyu' } }],
    });
    const { parsed } = await read('export.json', 'auto', bytes(text));
    expect(parsed.submit).toEqual({ format: 'json', text });
    expect(summarize(parsed).items).toEqual([
      { name: 'Mail', type: 1, detail: 'nyu', folder: 'Privat', totp: false },
    ]);
    await expect(read('x.json', 'bitwarden', bytes('{"encrypted":true}'))).rejects.toThrow(
      t(
        'Dieser Export ist verschlüsselt. Exportiere noch einmal als JSON ohne Passwort und importiere diese Datei.',
      ),
    );
  });

  it('shows its CSV in the preview and hands the file to the vault as it is', async () => {
    const text =
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nPrivat,1,login,Mail,,,0,https://mail.example.com,nyu,pw,\n';
    const { parsed } = await read('export.csv', 'auto', bytes(text));
    expect(parsed.submit).toEqual({ format: 'csv', text });
    expect(summarize(parsed)).toMatchObject({ logins: 1, folders: ['Privat'] });
  });
});

describe('the preview', () => {
  it('counts the kinds of items and marks TOTPs', async () => {
    const { parsed } = await read('protonpass.json');
    const summary = summarize(parsed);
    expect(summary).toMatchObject({ logins: 2, notes: 2, cards: 1, identities: 1, sshKeys: 1 });
    expect(summary.items.find((i) => i.name === 'Beispiel')).toMatchObject({
      detail: 'nyu',
      folder: 'Persönlich',
      totp: true,
    });
  });

  it('says which file doesn’t fit the chosen app', async () => {
    await expect(read('chrome.csv', 'firefox')).rejects.toThrow(
      t('Das sieht nicht nach einem Passwort-Export von Firefox aus.'),
    );
    await expect(read('protonpass.zip', 'lastpass')).rejects.toThrow(
      t('Diese Datei ist kein Export, den UwULock von {app} kennt.', { app: 'LastPass' }),
    );
  });
});

/** 1Password's export.data with the given items in one vault, as the importer takes it alone. */
const onePux = (items: unknown[]) =>
  bytes(JSON.stringify({ accounts: [{ vaults: [{ attrs: { name: 'Privat' }, items }] }] }));

describe('hardening', () => {
  it('turns away files and zips beyond the limits', async () => {
    expect(() => checkFileSize(MAX_FILE_BYTES)).not.toThrow();
    expect(() => checkFileSize(MAX_FILE_BYTES + 1)).toThrow(
      t('Die Datei ist zu groß für den Import (mehr als {size} MiB).', { size: 256 }),
    );
    // A zip whose end record lists one entry too many.
    const zip = new Uint8Array(4 + 22);
    zip.set([0x50, 0x4b, 3, 4]);
    const view = new DataView(zip.buffer);
    view.setUint32(4, 0x06054b50, true);
    view.setUint16(4 + 10, MAX_ZIP_ENTRIES + 1, true);
    await expect(read('x.zip', '1password', zip)).rejects.toThrow(
      t('Die ZIP-Datei hat mehr als {n} Einträge, das importiert UwULock nicht.', {
        n: MAX_ZIP_ENTRIES,
      }),
    );
  });

  it('reads the Android app of an address without a regex, and fast', () => {
    expect(androidApp('android://aBc-Hash==@com.example.app/')).toBe('com.example.app');
    expect(androidApp('android://x@y@com.example.app')).toBe('com.example.app');
    expect(androidApp('android://x@com.example.app/z')).toBeNull();
    expect(androidApp('https://example.com/@x')).toBeNull();
    expect(androidApp(`android://${'@'.repeat(200_000)}/x`)).toBeNull();
  });

  it('keeps many folders, and only those in use, in linear time', () => {
    const collector = new Collector();
    collector.folder('Leer');
    for (let i = 0; i < 20_000; i++) collector.add(collector.login(`n${i}`), `Oben/F${i}`);
    const { data } = collector.result();
    expect(data.folders.length).toBe(20_001);
    expect(data.folders[0]!.name).toBe('Oben');
    expect(data.folders.some((f) => f.name === 'Leer')).toBe(false);
  });

  it('skips an entry with a broken value and names it, without the value', async () => {
    const { parsed } = await read(
      'export.data',
      '1password',
      onePux([
        { categoryUuid: '001', overview: { title: 'Gut' }, details: { password: 'x' } },
        {
          categoryUuid: '003',
          overview: { title: 'Kaputt' },
          details: { sections: [{ fields: [{ title: 'Datum', value: { date: 1e20 } }] }] },
        },
      ]),
    );
    expect(parsed.data.items.map((i) => i.name)).toEqual(['Gut']);
    expect(parsed.warnings).toContain(
      t('{n} Einträge ließen sich nicht lesen und bleiben weg: {names}', {
        n: 1,
        names: 'Kaputt',
      }),
    );
    await expect(read('export.data', '1password', bytes('{"accounts":5}'))).rejects.toThrow(
      t('Die Datei ließ sich nicht lesen: Sie ist beschädigt oder anders aufgebaut als erwartet.'),
    );
  });

  it('keeps a 1PUX authenticator key in a section hidden, or as the TOTP', async () => {
    const { byName } = await read(
      'export.data',
      '1password',
      onePux([
        {
          categoryUuid: '001',
          overview: { title: 'Zwei' },
          details: {
            loginFields: [{ designation: 'username', value: 'nyu' }],
            sections: [
              {
                title: 'OTP',
                fields: [
                  { title: 'Erster', id: 'TOTP_a', value: { totp: 'JBSWY3DPEHPK3PXP' } },
                  { title: 'Zweiter', id: 'b', value: { totp: 'GEZDGNBVGY3TQOJQ' } },
                ],
              },
            ],
          },
        },
        {
          categoryUuid: '003',
          overview: { title: 'Notiz' },
          details: {
            sections: [{ fields: [{ title: 'Code', value: { totp: 'JBSWY3DPEHPK3PXP' } }] }],
          },
        },
      ]),
    );
    expect(byName('Zwei').login!.totp).toBe('JBSWY3DPEHPK3PXP');
    expect(field(byName('Zwei'), 'Zweiter')).toEqual({
      name: 'Zweiter',
      value: 'GEZDGNBVGY3TQOJQ',
      type: 1,
    });
    expect(field(byName('Notiz'), 'Code')?.type).toBe(1);
  });

  it('looks up only LastPass’s own form fields', async () => {
    const text =
      'url,username,password,totp,extra,name,grouping,fav\n' +
      'http://sn,,,,"NoteType:Credit Card\nconstructor:abc\nNumber:4111111111111111",Karte,,0\n';
    const { byName } = await read('lastpass.csv', 'lastpass', bytes(text));
    expect(byName('Karte').card!.number).toBe('4111111111111111');
    expect(field(byName('Karte'), 'constructor')?.value).toBe('abc');
  });

  it('keeps addresses with a scheme that runs something as text, not as addresses', async () => {
    const text =
      'name,url,username,password\n' +
      'Skript,javascript:alert(1),nyu,pw\n' +
      'Daten," DATA:text/html,x",nyu,pw\n' +
      'Web,https://example.com,nyu,pw\n';
    const { byName } = await read('chrome.csv', 'chrome', bytes(text));
    expect(uris(byName('Skript'))).toEqual([]);
    expect(field(byName('Skript'), 'URL')).toEqual({
      name: 'URL',
      value: 'javascript:alert(1)',
      type: 0,
    });
    expect(uris(byName('Daten'))).toEqual([]);
    expect(field(byName('Daten'), 'URL')?.value).toBe('DATA:text/html,x');
    expect(uris(byName('Web'))).toEqual(['https://example.com']);
  });
});
