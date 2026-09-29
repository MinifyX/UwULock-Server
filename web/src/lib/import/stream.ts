/**
 * The stream ciphers of KeePass files: ChaCha20 (RFC 8439) for KDBX 4's payload and protected
 * values, Salsa20 for KDBX 3.1's protected values. WebCrypto has neither.
 *
 * Both keep their place in the key stream between calls: a file's protected values are one
 * stream, read value by value in document order.
 */

const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

function words(bytes: Uint8Array, count: number): number[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return Array.from({ length: count }, (_, i) => view.getUint32(i * 4, true));
}

const rotl = (x: number, n: number) => (x << n) | (x >>> (32 - n));

abstract class StreamCipher {
  protected state: Uint32Array;
  private block = new Uint8Array(64);
  private used = 64;

  constructor(state: number[]) {
    this.state = Uint32Array.from(state);
  }

  protected abstract rounds(x: Uint32Array): void;
  protected abstract advance(): void;

  private next() {
    const x = this.state.slice();
    this.rounds(x);
    const view = new DataView(this.block.buffer);
    for (let i = 0; i < 16; i++) view.setUint32(i * 4, (x[i]! + this.state[i]!) >>> 0, true);
    this.advance();
    this.used = 0;
  }

  /** `data` XOR the next bytes of the key stream. */
  process(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      if (this.used === 64) this.next();
      out[i] = data[i]! ^ this.block[this.used++]!;
    }
    return out;
  }
}

export class ChaCha20 extends StreamCipher {
  /** A 32-byte key, a 12-byte nonce, and the block counter to start at. */
  constructor(key: Uint8Array, nonce: Uint8Array, counter = 0) {
    if (key.length !== 32 || nonce.length !== 12) throw new Error('ChaCha20: key or nonce size');
    super([...SIGMA, ...words(key, 8), counter, ...words(nonce, 3)]);
  }

  protected rounds(x: Uint32Array) {
    const quarter = (a: number, b: number, c: number, d: number) => {
      x[a] = (x[a]! + x[b]!) | 0;
      x[d] = rotl(x[d]! ^ x[a]!, 16);
      x[c] = (x[c]! + x[d]!) | 0;
      x[b] = rotl(x[b]! ^ x[c]!, 12);
      x[a] = (x[a]! + x[b]!) | 0;
      x[d] = rotl(x[d]! ^ x[a]!, 8);
      x[c] = (x[c]! + x[d]!) | 0;
      x[b] = rotl(x[b]! ^ x[c]!, 7);
    };
    for (let i = 0; i < 10; i++) {
      quarter(0, 4, 8, 12);
      quarter(1, 5, 9, 13);
      quarter(2, 6, 10, 14);
      quarter(3, 7, 11, 15);
      quarter(0, 5, 10, 15);
      quarter(1, 6, 11, 12);
      quarter(2, 7, 8, 13);
      quarter(3, 4, 9, 14);
    }
  }

  protected advance() {
    this.state[12] = (this.state[12]! + 1) >>> 0;
  }
}

export class Salsa20 extends StreamCipher {
  /** A 32-byte key and an 8-byte nonce; the block counter starts at 0. */
  constructor(key: Uint8Array, nonce: Uint8Array) {
    if (key.length !== 32 || nonce.length !== 8) throw new Error('Salsa20: key or nonce size');
    const k = words(key, 8);
    const n = words(nonce, 2);
    super([
      SIGMA[0]!,
      ...k.slice(0, 4),
      SIGMA[1]!,
      ...n,
      0,
      0,
      SIGMA[2]!,
      ...k.slice(4),
      SIGMA[3]!,
    ]);
  }

  protected rounds(x: Uint32Array) {
    const quarter = (a: number, b: number, c: number, d: number) => {
      x[b] = x[b]! ^ rotl((x[a]! + x[d]!) | 0, 7);
      x[c] = x[c]! ^ rotl((x[b]! + x[a]!) | 0, 9);
      x[d] = x[d]! ^ rotl((x[c]! + x[b]!) | 0, 13);
      x[a] = x[a]! ^ rotl((x[d]! + x[c]!) | 0, 18);
    };
    for (let i = 0; i < 10; i++) {
      quarter(0, 4, 8, 12);
      quarter(5, 9, 13, 1);
      quarter(10, 14, 2, 6);
      quarter(15, 3, 7, 11);
      quarter(0, 1, 2, 3);
      quarter(5, 6, 7, 4);
      quarter(10, 11, 8, 9);
      quarter(15, 12, 13, 14);
    }
  }

  protected advance() {
    this.state[8] = (this.state[8]! + 1) >>> 0;
    if (this.state[8] === 0) this.state[9] = (this.state[9]! + 1) >>> 0;
  }
}
