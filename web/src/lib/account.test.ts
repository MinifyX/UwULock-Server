import { describe, expect, it } from 'vitest';
import { DEFAULT_KDFS, kdfOf, kdfText } from './account';

describe('key derivation settings', () => {
  it('go to the WebAssembly module and back unchanged', () => {
    for (const kdf of Object.values(DEFAULT_KDFS)) expect(kdfOf(kdfText(kdf))).toEqual(kdf);
  });

  it('read the server’s prelogin', () => {
    expect(kdfOf('{"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":4}')).toEqual({
      kind: 'argon2id',
      iterations: 3,
      memory: 64,
      parallelism: 4,
    });
    expect(kdfOf('{"kdf":0,"kdfIterations":600000}')).toEqual({
      kind: 'pbkdf2',
      iterations: 600000,
    });
  });
});
