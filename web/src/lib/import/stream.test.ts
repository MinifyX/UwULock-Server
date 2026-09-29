import { describe, expect, it } from 'vitest';
import { hex } from './bytes';
import { ChaCha20, Salsa20 } from './stream';

const counting = (n: number) => Uint8Array.from({ length: n }, (_, i) => i);
const fromHex = (text: string) => Uint8Array.from(text.match(/../g)!, (h) => parseInt(h, 16));

describe('the stream ciphers', () => {
  it('ChaCha20 gives RFC 8439’s example (section 2.4.2)', () => {
    const nonce = fromHex('000000000000004a00000000');
    const text = new TextEncoder().encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    );
    expect(hex(new ChaCha20(counting(32), nonce, 1).process(text))).toBe(
      '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d',
    );
  });

  it('keep their place in the key stream between calls', () => {
    const whole = new ChaCha20(counting(32), counting(12)).process(new Uint8Array(150));
    const cipher = new ChaCha20(counting(32), counting(12));
    const pieces = [3, 61, 1, 85].map((n) => cipher.process(new Uint8Array(n)));
    expect(hex(Uint8Array.from(pieces.flatMap((p) => [...p])))).toBe(hex(whole));
  });

  it('Salsa20 matches another implementation (PyCryptodome)', () => {
    const cipher = new Salsa20(counting(32), counting(8));
    const out = [cipher.process(new Uint8Array(30)), cipher.process(new Uint8Array(50))];
    expect(hex(out[0]!) + hex(out[1]!)).toBe(
      '2ead0f5f185729ced672b3a928e454f72fdb44a87b9cd8d219e4ec14aef9c6bc77bf057f5659d7753848f8d3fe769ca5fdd8057d46326990e5f136e2fcb7bb7ca13a2b59d9047b8dbeb93ec4b78ce1a5',
    );
  });
});
