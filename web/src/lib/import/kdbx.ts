/**
 * Opens KeePass files (KDBX 4.0, 4.1 and 3.1) in the browser and gives their XML.
 *
 * KDBX 4: a header of typed fields, with the key derivation's parameters as a small typed
 * dictionary; the header's SHA-256 (is the file whole?) and its HMAC-SHA-256 (is the key
 * right?); then the payload in blocks, each with its own HMAC, encrypted with AES-256-CBC or
 * ChaCha20 and usually gzipped; inside, a second header with the key for protected values, and
 * the XML. KDBX 3.1: the header also holds that key, the payload starts with bytes from the
 * header (is the key right?) and its blocks carry SHA-256 hashes instead.
 *
 * The key derivations (Argon2d, Argon2id, AES-KDF) are too slow for JavaScript and come in as
 * `kdf`: the WebAssembly module in the web vault, Node's crypto in the tests.
 */

import { t } from '../i18n';
import {
  aesCbcDecrypt,
  concat,
  equal,
  fromBase64,
  fromHex,
  hex,
  hmacSha256,
  ImportError,
  inflate,
  Reader,
  sha256,
  sha512,
  u32le,
  u64le,
  utf8,
} from './bytes';
import { ChaCha20, Salsa20 } from './stream';
import type { Credentials, KdbxKdf } from './types';

const SIGNATURE_1 = 0x9aa2d903;
const SIGNATURE_2 = 0xb54bfb67;
/** KeePass 1's .kdb, and the pre-release of KeePass 2. */
const OLD_SIGNATURES = [0xb54bfb65, 0xb54bfb66];

const CIPHER_AES256 = '31c1f2e6bf714350be5805216afc5aff';
const CIPHER_CHACHA20 = 'd6038a2b8b6f4cb5a524339a31dbb59a';
const CIPHER_TWOFISH = 'ad68f29f576f4bb9a36ad47af965346c';

const KDF_AES = ['c9d9f39a628a4460bf740d08c18a4fea', '7c02bb8279a74ac0927d114a00648238'];
const KDF_ARGON2D = 'ef636ddf8c29444b91f7a9a403e30a0c';
const KDF_ARGON2ID = '9e298b1956db4773b23dfc3ec6f0a1e6';

const SALSA20_NONCE = new Uint8Array([0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a]);

const damaged = () => new ImportError(t('Die KeePass-Datei ist beschädigt oder unvollständig.'));
const wrongKey = () => new ImportError(t('Das Passwort oder die Schlüsseldatei stimmt nicht.'));

export function isKdbx(bytes: Uint8Array): boolean {
  if (bytes.length < 12) return false;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, true) === SIGNATURE_1;
}

/**
 * A key file's 32 bytes: KeePass's XML key file (version 1.0 with base64, 2.0 with hex and a
 * check hash), 32 bytes as they are, 64 hex digits, or else the SHA-256 of whatever the file is.
 */
export async function keyFileKey(bytes: Uint8Array): Promise<Uint8Array> {
  let text: string | null = null;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes).replace(/^\uFEFF/, '');
  } catch {
    // Binary: not XML, not hex.
  }
  if (text !== null && text.trimStart().startsWith('<')) {
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    const version = doc.querySelector('KeyFile > Meta > Version')?.textContent?.trim() ?? '';
    const data = doc.querySelector('KeyFile > Key > Data');
    if (data && !doc.querySelector('parsererror')) {
      if (version.startsWith('1.')) return fromBase64(data.textContent ?? '');
      if (version.startsWith('2.')) {
        const key = fromHex(data.textContent ?? '');
        const check = fromHex(data.getAttribute('Hash') ?? '');
        if (!key || (check && !equal((await sha256(key)).subarray(0, 4), check))) {
          throw new ImportError(t('Die Schlüsseldatei ist beschädigt.'));
        }
        return key;
      }
    }
  }
  if (bytes.length === 32) return bytes;
  if (bytes.length === 64 && text !== null) {
    const key = fromHex(text);
    if (key) return key;
  }
  return sha256(bytes);
}

/** SHA-256 over the hashes of what opens the file: the password, the key file, or both. */
export async function compositeKey(credentials: Credentials): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  if (credentials.password || !credentials.keyFile) {
    parts.push(await sha256(new TextEncoder().encode(credentials.password)));
  }
  if (credentials.keyFile) parts.push(await keyFileKey(credentials.keyFile));
  return sha256(...parts);
}

type Variant = number | boolean | string | Uint8Array;

/** KDBX 4's typed dictionary, for the key derivation's parameters. */
function variantDictionary(bytes: Uint8Array): Map<string, Variant> {
  const reader = new Reader(bytes, damaged);
  const out = new Map<string, Variant>();
  const version = reader.u16();
  if (version >> 8 > 1) throw damaged();
  for (;;) {
    const type = reader.u8();
    if (type === 0) break;
    const name = utf8(reader.take(reader.u32()));
    const value = new Reader(reader.take(reader.u32()), damaged);
    switch (type) {
      case 0x04:
      case 0x0c:
        out.set(name, value.u32());
        break;
      case 0x05:
      case 0x0d:
        out.set(name, value.u64());
        break;
      case 0x08:
        out.set(name, value.u8() !== 0);
        break;
      case 0x18:
        out.set(name, utf8(value.bytes));
        break;
      default:
        out.set(name, value.bytes);
    }
  }
  return out;
}

async function derive(
  params: Map<string, Variant>,
  composite: Uint8Array,
  kdf: KdbxKdf,
): Promise<Uint8Array> {
  const uuid = params.get('$UUID');
  const id = uuid instanceof Uint8Array ? hex(uuid) : '';
  const bytes = (name: string) => {
    const value = params.get(name);
    if (!(value instanceof Uint8Array)) throw damaged();
    return value;
  };
  const number = (name: string) => {
    const value = params.get(name);
    if (typeof value !== 'number') throw damaged();
    return value;
  };
  if (KDF_AES.includes(id)) return kdf.aesKdf(composite, bytes('S'), number('R'));
  if (id === KDF_ARGON2D || id === KDF_ARGON2ID) {
    for (const extra of ['K', 'A']) {
      const value = params.get(extra);
      if (value instanceof Uint8Array && value.length > 0) {
        throw new ImportError(
          t('Diese KeePass-Datei nutzt Argon2 mit Zusatzdaten, das kann UwULock nicht öffnen.'),
        );
      }
    }
    return kdf.argon2(
      id === KDF_ARGON2ID,
      number('V'),
      composite,
      bytes('S'),
      Math.floor(number('M') / 1024),
      number('I'),
      number('P'),
    );
  }
  throw new ImportError(
    t('Diese KeePass-Datei nutzt eine Schlüsselableitung, die UwULock nicht kennt.'),
  );
}

async function decrypt(cipher: string, key: Uint8Array, iv: Uint8Array, data: Uint8Array) {
  if (cipher === CIPHER_AES256) {
    try {
      return await aesCbcDecrypt(key, iv, data);
    } catch {
      // Bad padding: in KDBX 3.1 the only sign of a wrong key this early.
      throw wrongKey();
    }
  }
  if (cipher === CIPHER_CHACHA20) return new ChaCha20(key, iv).process(data);
  if (cipher === CIPHER_TWOFISH) {
    throw new ImportError(
      t(
        'Diese KeePass-Datei ist mit Twofish verschlüsselt, das kann UwULock nicht öffnen. Stell in KeePassXC oder KeePass bei den Datenbank-Einstellungen AES-256 oder ChaCha20 ein, speichere und importiere die Datei noch einmal.',
      ),
    );
  }
  throw new ImportError(
    t('Diese KeePass-Datei nutzt eine Verschlüsselung, die UwULock nicht kennt.'),
  );
}

/** The key stream that hides protected values (passwords and the like) inside the XML. */
async function innerStream(id: number, key: Uint8Array): Promise<ChaCha20 | Salsa20 | null> {
  if (id === 0) return null;
  if (id === 2) return new Salsa20(await sha256(key), SALSA20_NONCE);
  if (id === 3) {
    const hash = await sha512(key);
    return new ChaCha20(hash.subarray(0, 32), hash.subarray(32, 44));
  }
  throw new ImportError(
    t('Diese KeePass-Datei nutzt eine Verschlüsselung, die UwULock nicht kennt.'),
  );
}

export type Kdbx = { doc: Document; version: string };

/** Opens a KeePass file: its XML, with every protected value decrypted in place. */
export async function openKdbx(
  file: Uint8Array,
  credentials: Credentials,
  kdf: KdbxKdf,
): Promise<Kdbx> {
  const reader = new Reader(file, damaged);
  if (reader.u32() !== SIGNATURE_1) throw new ImportError(t('Das ist keine KeePass-Datei.'));
  const signature = reader.u32();
  if (OLD_SIGNATURES.includes(signature)) {
    throw new ImportError(
      t(
        'Das ist eine Datei von KeePass 1 (.kdb). Öffne sie in KeePassXC oder KeePass 2, speichere sie als KDBX und importiere dann diese Datei.',
      ),
    );
  }
  if (signature !== SIGNATURE_2) throw new ImportError(t('Das ist keine KeePass-Datei.'));
  const minor = reader.u16();
  const major = reader.u16();
  if (major !== 3 && major !== 4) {
    throw new ImportError(
      t(
        'Diese KeePass-Datei hat Version {version}, UwULock kennt 3.1 und 4.x. Speichere sie in KeePassXC oder KeePass noch einmal und importiere dann diese Datei.',
        { version: `${major}.${minor}` },
      ),
    );
  }

  const fields = new Map<number, Uint8Array>();
  for (;;) {
    const id = reader.u8();
    const data = reader.take(major >= 4 ? reader.u32() : reader.u16());
    if (id === 0) break;
    fields.set(id, data);
  }
  const header = file.subarray(0, reader.at);
  const field = (id: number) => {
    const data = fields.get(id);
    if (!data) throw damaged();
    return data;
  };
  const cipher = hex(field(2));
  const compressed = new Reader(field(3), damaged).u32() === 1;
  const masterSeed = field(4);
  const iv = field(7);
  const composite = await compositeKey(credentials);

  let payload: Uint8Array;
  let stream: ChaCha20 | Salsa20 | null;
  if (major === 4) {
    if (!equal(reader.take(32), await sha256(header))) throw damaged();
    const headerHmac = reader.take(32);
    const transformed = await derive(variantDictionary(field(11)), composite, kdf);
    const hmacBase = await sha512(masterSeed, transformed, new Uint8Array([1]));
    const blockKey = (index: bigint) => sha512(u64le(index), hmacBase);
    const expected = await hmacSha256(await blockKey(0xffffffffffffffffn), header);
    if (!equal(headerHmac, expected)) throw wrongKey();

    const blocks: Uint8Array[] = [];
    for (let index = 0n; ; index++) {
      const hmac = reader.take(32);
      const size = reader.u32();
      const data = reader.take(size);
      const check = await hmacSha256(await blockKey(index), u64le(index), u32le(size), data);
      if (!equal(hmac, check)) throw damaged();
      if (size === 0) break;
      blocks.push(data);
    }
    const key = await sha256(masterSeed, transformed);
    let plain = await decrypt(cipher, key, iv, concat(...blocks));
    if (compressed) plain = await inflate(plain, 'gzip').catch(() => Promise.reject(damaged()));

    const inner = new Reader(plain, damaged);
    let streamId = 0;
    let streamKey: Uint8Array = new Uint8Array();
    for (;;) {
      const id = inner.u8();
      const data = inner.take(inner.u32());
      if (id === 0) break;
      if (id === 1) streamId = new Reader(data, damaged).u32();
      if (id === 2) streamKey = data;
    }
    stream = await innerStream(streamId, streamKey);
    payload = plain.subarray(inner.at);
  } else {
    const rounds = new Reader(field(6), damaged).u64();
    const transformed = await kdf.aesKdf(composite, field(5), rounds);
    const key = await sha256(masterSeed, transformed);
    const plain = await decrypt(cipher, key, iv, file.subarray(reader.at));
    if (!equal(plain.subarray(0, 32), field(9))) throw wrongKey();
    const blocks = new Reader(plain.subarray(32), damaged);
    const parts: Uint8Array[] = [];
    for (;;) {
      blocks.u32();
      const hash = blocks.take(32);
      const data = blocks.take(blocks.u32());
      if (data.length === 0) break;
      if (!equal(hash, await sha256(data))) throw damaged();
      parts.push(data);
    }
    payload = concat(...parts);
    if (compressed) payload = await inflate(payload, 'gzip').catch(() => Promise.reject(damaged()));
    stream = await innerStream(new Reader(field(10), damaged).u32(), field(8));
  }

  const xml = utf8(payload);
  if (/<!DOCTYPE|<!ENTITY/i.test(xml.slice(0, 2000))) throw damaged();
  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  if (doc.querySelector('parsererror') || doc.documentElement.nodeName !== 'KeePassFile') {
    throw damaged();
  }
  // One key stream for all protected values, in the order they stand in the file.
  for (const element of Array.from(doc.getElementsByTagName('*'))) {
    if (element.getAttribute('Protected')?.toLowerCase() !== 'true') continue;
    const hidden = fromBase64(element.textContent ?? '');
    const plain = stream ? stream.process(hidden) : hidden;
    if (element.nodeName === 'Value') element.textContent = utf8(plain);
  }
  return { doc, version: `KDBX ${major}.${minor}` };
}
