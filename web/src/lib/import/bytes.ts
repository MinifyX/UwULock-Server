/**
 * Small helpers on bytes for the importers: reading numbers, hashing with WebCrypto, and
 * inflating with the browser's own DecompressionStream (gzip for KeePass, raw deflate for zips).
 */

/** Something the user can act on, in their language; `errorText` shows it as it is. */
export class ImportError extends Error {
  readonly kind = 'invalid';
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function fromHex(text: string): Uint8Array | null {
  const clean = text.replace(/\s+/g, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function fromBase64(text: string): Uint8Array {
  const binary = atob(text.replace(/\s+/g, ''));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 base32 without padding: how authenticator secrets are written. */
export function base32(bytes: Uint8Array): string {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

export function utf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/** Text of a file: UTF-8, without a byte order mark. */
export function text(bytes: Uint8Array): string {
  return utf8(bytes).replace(/^\uFEFF/, '');
}

/** A fresh ArrayBuffer-backed copy, as WebCrypto's types want it. */
function buffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buffer(concat(...parts))));
}

export async function sha512(...parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-512', buffer(concat(...parts))));
}

export async function hmacSha256(key: Uint8Array, ...parts: Uint8Array[]): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey(
    'raw',
    buffer(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, buffer(concat(...parts))));
}

/** AES-256-CBC with PKCS#7 padding; a wrong key usually shows as bad padding. */
export async function aesCbcDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey('raw', buffer(key), 'AES-CBC', false, ['decrypt']);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-CBC', iv: buffer(iv) }, imported, buffer(data)),
  );
}

/** gzip (KeePass) or raw deflate (zip entries), by the browser. */
export async function inflate(
  data: Uint8Array,
  format: 'gzip' | 'deflate-raw',
): Promise<Uint8Array> {
  const stream = new DecompressionStream(format);
  const writer = stream.writable.getWriter();
  // Not awaited: the reader below has to drain the output, or a large input stalls.
  writer.write(buffer(data)).catch(() => {});
  writer.close().catch(() => {});
  const reader = stream.readable.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return concat(...parts);
}

/** Little-endian reading, with a clear error when the file ends early. */
export class Reader {
  private view: DataView;
  at = 0;

  constructor(
    readonly bytes: Uint8Array,
    private truncated: () => Error,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get left(): number {
    return this.bytes.length - this.at;
  }

  private need(count: number) {
    if (count < 0 || this.at + count > this.bytes.length) throw this.truncated();
  }

  u8(): number {
    this.need(1);
    return this.view.getUint8(this.at++);
  }

  u16(): number {
    this.need(2);
    const value = this.view.getUint16(this.at, true);
    this.at += 2;
    return value;
  }

  u32(): number {
    this.need(4);
    const value = this.view.getUint32(this.at, true);
    this.at += 4;
    return value;
  }

  /** A 64-bit number, as far as a double holds it exactly. */
  u64(): number {
    const low = this.u32();
    const high = this.u32();
    return high * 2 ** 32 + low;
  }

  take(count: number): Uint8Array {
    this.need(count);
    const out = this.bytes.subarray(this.at, this.at + count);
    this.at += count;
    return out;
  }
}

export function u32le(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

export function u64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}
