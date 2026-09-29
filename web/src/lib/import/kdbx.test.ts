import { argon2Sync, createCipheriv, createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { t } from '../i18n';
import { concat, ImportError, inflate, sha256 } from './bytes';
import { keyFileKey, openKdbx, parseXml } from './kdbx';
import { readImport } from './index';
import { MAX_AES_KDF_ROUNDS } from './limits';
import type { ExportItem, KdbxKdf } from './types';

const fixture = (name: string) =>
  new Uint8Array(readFileSync(join(process.cwd(), 'src/lib/import/fixtures', name)));

/** The key derivations from Node, standing in for the WebAssembly module. */
const nodeKdf: KdbxKdf = {
  argon2(id, version, key, salt, memoryKiB, iterations, lanes) {
    expect(version).toBe(0x13);
    const algorithm = id ? 'argon2id' : 'argon2d';
    const params = { message: key, nonce: salt, parallelism: lanes, tagLength: 32 };
    return new Uint8Array(
      argon2Sync(algorithm, { ...params, memory: memoryKiB, passes: iterations }),
    );
  },
  aesKdf(key, seed, rounds) {
    const cipher = createCipheriv('aes-256-ecb', seed, null).setAutoPadding(false);
    let block = Buffer.from(key);
    for (let i = 0; i < rounds; i++) block = cipher.update(block);
    return new Uint8Array(createHash('sha256').update(block).digest());
  },
};

const PASSWORD = 'nyu-test-passwort';

async function open(name: string, password = PASSWORD, keyFile?: Uint8Array) {
  const parsed = await readImport({ name, bytes: fixture(name) }, 'auto', {
    credentials: { password, keyFile },
    kdf: nodeKdf,
  });
  const folders = new Map(parsed.data.folders.map((f) => [f.id, f.name]));
  const byName = (item: string) => parsed.data.items.find((i) => i.name === item)!;
  const folderOf = (item: ExportItem) => (item.folderId ? folders.get(item.folderId) : null);
  return { parsed, byName, folderOf };
}

const field = (item: ExportItem, name: string) => item.fields.find((f) => f.name === name);

const damagedText = () => t('Die KeePass-Datei ist beschädigt oder unvollständig.');
const tooCostlyText = () =>
  t(
    'Die Schlüsselableitung dieser KeePass-Datei ist aufwendiger, als UwULock beim Import zulässt. Stell sie in KeePassXC oder KeePass bei den Datenbank-Einstellungen niedriger, speichere und importiere die Datei noch einmal.',
  );

/** Key derivations that must not run: the file is to be turned away before. */
const refusingKdf: KdbxKdf = {
  argon2: () => {
    throw new Error('Argon2 ran');
  },
  aesKdf: () => {
    throw new Error('AES-KDF ran');
  },
};

/** Where each header field's data starts in a KDBX file, and where the header ends. */
function headerOf(bytes: Uint8Array) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const major = view.getUint16(10, true);
  const fields = new Map<number, number>();
  for (let at = 12; ;) {
    const id = bytes[at]!;
    const length = major >= 4 ? view.getUint32(at + 1, true) : view.getUint16(at + 1, true);
    at += major >= 4 ? 5 : 3;
    fields.set(id, at);
    at += length;
    if (id === 0) return { view, fields, end: at };
  }
}

const nodeSha256 = (...parts: Uint8Array[]) =>
  new Uint8Array(
    createHash('sha256')
      .update(concat(...parts))
      .digest(),
  );

/**
 * A KDBX 3.1 file around the XML `xml` makes of the header's hash (base64): AES-KDF with one
 * round, AES-256, no gzip, protected values in the clear.
 */
function kdbx3(xml: (headerHash: string) => string): Uint8Array {
  const u16 = (value: number) => new Uint8Array(new Uint16Array([value]).buffer);
  const u32 = (value: number) => new Uint8Array(new Uint32Array([value]).buffer);
  const field = (id: number, data: Uint8Array) =>
    concat(new Uint8Array([id]), u16(data.length), data);
  const [masterSeed, transformSeed, iv, start] = [32, 32, 16, 32].map(
    (n) => new Uint8Array(randomBytes(n)),
  ) as [Uint8Array, Uint8Array, Uint8Array, Uint8Array];
  const header = concat(
    u32(0x9aa2d903),
    u32(0xb54bfb67),
    u16(1),
    u16(3),
    field(2, Uint8Array.from(Buffer.from('31c1f2e6bf714350be5805216afc5aff', 'hex'))),
    field(3, u32(0)),
    field(4, masterSeed),
    field(5, transformSeed),
    field(6, concat(u32(1), u32(0))),
    field(7, iv),
    field(8, new Uint8Array(32)),
    field(9, start),
    field(10, u32(0)),
    field(0, new TextEncoder().encode('\r\n\r\n')),
  );
  const data = new TextEncoder().encode(xml(Buffer.from(nodeSha256(header)).toString('base64')));
  const plain = concat(start, u32(0), nodeSha256(data), u32(data.length), data);
  const payload = concat(plain, u32(1), new Uint8Array(32), u32(0));
  const composite = nodeSha256(nodeSha256(new TextEncoder().encode(PASSWORD)));
  const transformed = nodeKdf.aesKdf(composite, transformSeed, 1) as Uint8Array;
  const cipher = createCipheriv('aes-256-cbc', nodeSha256(masterSeed, transformed), iv);
  return concat(header, cipher.update(payload), cipher.final());
}

const keepassXml = (hash: string) =>
  `<?xml version="1.0" encoding="utf-8"?><KeePassFile><Meta><HeaderHash>${hash}</HeaderHash></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID><Name>Root</Name><Entry><String><Key>Title</Key><Value>Drucker</Value></String><String><Key>Password</Key><Value>print-pass</Value></String></Entry></Group></Root></KeePassFile>`;

describe('KeePass files', () => {
  it('opens KDBX 4.0 with Argon2id and ChaCha20', async () => {
    const { parsed, byName, folderOf } = await open('argon2id-chacha20.kdbx');
    expect(parsed.format).toBe('KDBX 4.0');
    expect(parsed.data.folders.map((f) => f.name)).toEqual(['Privat', 'Privat/Banken']);
    expect(parsed.data.items.map((i) => i.name).sort()).toEqual([
      'Bank',
      'Mail',
      'Router',
      'WLAN-Notiz',
    ]);

    const mail = byName('Mail');
    expect(folderOf(mail)).toBe('Privat');
    expect(mail.login).toMatchObject({
      username: 'nyu@example.com',
      password: 'mail-pass-1',
      totp: 'otpauth://totp/Mail:nyu@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Mail',
    });
    expect(mail.login!.uris.map((u) => u.uri)).toEqual([
      'https://mail.example.com',
      'https://webmail.example.net',
    ]);
    expect(mail.notes).toBe('Zweite Zeile\nfolgt hier');
    expect(field(mail, 'PIN')).toEqual({ name: 'PIN', value: '1234', type: 1 });
    expect(field(mail, 'Kundennummer')).toEqual({ name: 'Kundennummer', value: 'K-1001', type: 0 });
    expect(field(mail, 'Tags')?.value).toBe('privat, wichtig');
    expect(field(mail, 'otp')).toBeUndefined();

    const bank = byName('Bank');
    expect(folderOf(bank)).toBe('Privat/Banken');
    expect(bank.login!.uris[0]!.uri).toBe('https://bank.example.org');
    expect(bank.login!.totp).toBe('otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQ&period=60&digits=6');
    expect(bank.passwordHistory?.map((h) => h.password)).toEqual(['bank-pass-old']);
    expect(bank.fields).toEqual([]);

    expect(folderOf(byName('Router'))).toBeNull();
    expect(byName('WLAN-Notiz')).toMatchObject({ type: 2, notes: 'Gastnetz: nyu-gast' });
    expect(parsed.warnings).toEqual([
      t('{n} Einträge aus dem Papierkorb oder den Vorlagen bleiben weg.', { n: 1 }),
      t('{n} Einträge mit Feldern ohne eigenen Platz: als eigene Felder oder Notizen übernommen.', {
        n: 1,
      }),
      t(
        '{n} Anhänge kommen nicht mit. Speichere sie aus der alten App und hänge sie danach wieder an.',
        { n: 1 },
      ),
    ]);
    expect(JSON.parse(parsed.submit.text)).toEqual(parsed.data);
  });

  it('opens KDBX 4.1 with AES-KDF, AES-256 and a key file', async () => {
    const { parsed, byName, folderOf } = await open(
      'aeskdf-aes-keyfile.kdbx',
      PASSWORD,
      fixture('aeskdf-aes.keyx'),
    );
    expect(parsed.format).toBe('KDBX 4.1');
    const vpn = byName('VPN');
    expect(folderOf(vpn)).toBe('Arbeit');
    expect(vpn.login!.totp).toBe('otpauth://totp/VPN?secret=JBSWY3DPEHPK3PXP&period=30&digits=8');
    expect(vpn.fields).toEqual([{ name: 'API-Token', value: 'tok-5678', type: 1 }]);
  });

  it('opens KDBX 3.1 with Salsa20 for the protected values', async () => {
    const { parsed, byName, folderOf } = await open('kdbx3-aes.kdbx');
    expect(parsed.format).toBe('KDBX 3.1');
    const forum = byName('Forum');
    expect(folderOf(forum)).toBe('Alt');
    expect(forum.login).toMatchObject({ username: 'nyu', password: 'forum-pass' });
    expect(field(forum, 'Sicherheitsfrage')).toMatchObject({ value: 'Blau', type: 1 });
    expect(byName('Drucker').login!.password).toBe('print-pass');
  });

  it('says so when the password or the key file is wrong', async () => {
    const wrong = t('Das Passwort oder die Schlüsseldatei stimmt nicht.');
    await expect(open('argon2id-chacha20.kdbx', 'falsch')).rejects.toThrow(wrong);
    await expect(open('kdbx3-aes.kdbx', 'falsch')).rejects.toThrow(wrong);
    await expect(open('aeskdf-aes-keyfile.kdbx')).rejects.toThrow(wrong);
    await expect(
      open('aeskdf-aes-keyfile.kdbx', PASSWORD, new TextEncoder().encode('anderer Schlüssel')),
    ).rejects.toThrow(wrong);
  });

  it('notices a changed header and a cut-off file', async () => {
    const damaged = t('Die KeePass-Datei ist beschädigt oder unvollständig.');
    const changed = fixture('argon2id-chacha20.kdbx');
    changed[40] = changed[40]! ^ 1;
    await expect(openKdbx(changed, { password: PASSWORD }, nodeKdf)).rejects.toThrow(damaged);
    const cut = fixture('argon2id-chacha20.kdbx').subarray(0, 900);
    await expect(openKdbx(cut, { password: PASSWORD }, nodeKdf)).rejects.toThrow(damaged);
  });

  it('compares the header hash of KDBX 3.1', async () => {
    const good = await openKdbx(kdbx3(keepassXml), { password: PASSWORD }, nodeKdf);
    expect(good.version).toBe('KDBX 3.1');
    expect(good.doc.querySelector('Entry Value')?.textContent).toBe('Drucker');
    const other = btoa(String.fromCharCode(...new Uint8Array(32)));
    await expect(
      openKdbx(
        kdbx3(() => keepassXml(other)),
        { password: PASSWORD },
        nodeKdf,
      ),
    ).rejects.toThrow(damagedText());
  });

  it('turns away key derivations above the ceilings before running them', async () => {
    // Argon2: 2 GiB of memory, or a million passes over the fixture's memory.
    for (const [name, value] of [
      ['M', 2n ** 31n],
      ['I', 1_000_000n],
    ] as const) {
      const bytes = fixture('argon2id-chacha20.kdbx');
      const { view, fields, end } = headerOf(bytes);
      const entry = [0x05, 1, 0, 0, 0, name.charCodeAt(0), 8, 0, 0, 0];
      let at = fields.get(11)!;
      while (!entry.every((byte, i) => bytes[at + i] === byte)) at++;
      view.setBigUint64(at + entry.length, value, true);
      bytes.set(nodeSha256(bytes.subarray(0, end)), end);
      await expect(openKdbx(bytes, { password: PASSWORD }, refusingKdf)).rejects.toThrow(
        tooCostlyText(),
      );
    }
    // AES-KDF of KDBX 3.1, with a round too many.
    const legacy = fixture('kdbx3-aes.kdbx');
    const { view, fields } = headerOf(legacy);
    view.setBigUint64(fields.get(6)!, BigInt(MAX_AES_KDF_ROUNDS + 1), true);
    await expect(openKdbx(legacy, { password: PASSWORD }, refusingKdf)).rejects.toThrow(
      tooCostlyText(),
    );
  });

  it('turns away KeePass 1 files with a hint', async () => {
    const kdb = new Uint8Array(124);
    new DataView(kdb.buffer).setUint32(0, 0x9aa2d903, true);
    new DataView(kdb.buffer).setUint32(4, 0xb54bfb65, true);
    const error = await openKdbx(kdb, { password: PASSWORD }, nodeKdf).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ImportError);
    expect((error as Error).message).toContain('KeePass 1');
  });
});

describe('key files', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => i * 7);
  const hexKey = Array.from(key, (b) => b.toString(16).padStart(2, '0')).join('');

  it('read XML version 2.0 with its check hash, and 1.0 with base64', async () => {
    expect(await keyFileKey(fixture('aeskdf-aes.keyx'))).toEqual(
      await sha256(new TextEncoder().encode('uwulock import test key file')),
    );
    const v1 = `<?xml version="1.0"?><KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>${btoa(
      String.fromCharCode(...key),
    )}</Data></Key></KeyFile>`;
    expect(await keyFileKey(new TextEncoder().encode(v1))).toEqual(key);
    const bad = `<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash="00000000">${hexKey}</Data></Key></KeyFile>`;
    await expect(keyFileKey(new TextEncoder().encode(bad))).rejects.toThrow(
      t('Die Schlüsseldatei ist beschädigt.'),
    );
  });

  it('read XML version 2.0 without a check hash, and want 32 bytes in both versions', async () => {
    const v2 = (data: string, hash = '') =>
      new TextEncoder().encode(
        `<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data${hash}>${data}</Data></Key></KeyFile>`,
      );
    expect(await keyFileKey(v2(hexKey))).toEqual(key);
    const broken = t('Die Schlüsseldatei ist beschädigt.');
    await expect(keyFileKey(v2(hexKey.slice(0, 32)))).rejects.toThrow(broken);
    const short = btoa(String.fromCharCode(...key.subarray(0, 16)));
    const v1 = `<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>${short}</Data></Key></KeyFile>`;
    await expect(keyFileKey(new TextEncoder().encode(v1))).rejects.toThrow(broken);
  });

  it('take 32 bytes as they are, 64 hex digits as bytes, and hash anything else', async () => {
    expect(await keyFileKey(key)).toEqual(key);
    expect(await keyFileKey(new TextEncoder().encode(hexKey))).toEqual(key);
    const other = concat(key, key, key);
    expect(await keyFileKey(other)).toEqual(
      new Uint8Array(createHash('sha256').update(other).digest()),
    );
  });
});

describe('XML and unpacking', () => {
  it('turns away a DOCTYPE anywhere in the prolog, before parsing', () => {
    const root = '<KeePassFile><Root/></KeePassFile>';
    expect(parseXml(`<?xml version="1.0"?>${root}`)?.documentElement.nodeName).toBe('KeePassFile');
    const padding = `<!--${' '.repeat(10_000)}<x -->`;
    const doctype = '<!DOCTYPE KeePassFile [<!ENTITY a "aaaa">]>';
    expect(parseXml(`<?xml version="1.0"?>${padding}${doctype}${root}`)).toBeNull();
    expect(parseXml(`<?xml version="1.0"?><?pi x?>${doctype}${root}`)).toBeNull();
    expect(parseXml('<KeePassFile>')).toBeNull();
  });

  it('stops unpacking at the limit', async () => {
    const packed = new Uint8Array(gzipSync(new Uint8Array(100_000)));
    const tooMuch = () => new ImportError('too much');
    await expect(inflate(packed, 'gzip', 50_000, tooMuch)).rejects.toThrow('too much');
    expect((await inflate(packed, 'gzip', 100_000, tooMuch)).length).toBe(100_000);
  });
});
