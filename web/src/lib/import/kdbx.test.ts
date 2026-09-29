import { argon2Sync, createCipheriv, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { t } from '../i18n';
import { concat, ImportError, sha256 } from './bytes';
import { keyFileKey, openKdbx } from './kdbx';
import { readImport } from './index';
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

  it('take 32 bytes as they are, 64 hex digits as bytes, and hash anything else', async () => {
    expect(await keyFileKey(key)).toEqual(key);
    expect(await keyFileKey(new TextEncoder().encode(hexKey))).toEqual(key);
    const other = concat(key, key, key);
    expect(await keyFileKey(other)).toEqual(
      new Uint8Array(createHash('sha256').update(other).digest()),
    );
  });
});
