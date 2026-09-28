import { describe, expect, it } from 'vitest';
import {
  complexityScore,
  DEFAULT_KDFS,
  kdfForMinimum,
  kdfOf,
  kdfText,
  passwordProblem,
  type MinimumKdf,
} from './account';

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

describe('the master password rules', () => {
  it('turn bits into a zxcvbn-like score', () => {
    expect([0, 9.9, 10, 19.9, 20, 26.5, 26.6, 33.1, 33.2, 80].map(complexityScore)).toEqual([
      0, 0, 1, 1, 2, 2, 3, 3, 4, 4,
    ]);
  });

  it('refuse a short or a weak password, and nothing else', () => {
    const rules = { minLength: 14, minComplexity: 3 };
    expect(passwordProblem('a'.repeat(13), 90, rules)).not.toBeNull();
    expect(passwordProblem('a'.repeat(14), 25, rules)).not.toBeNull();
    expect(passwordProblem('a'.repeat(14), 34, rules)).toBeNull();
    expect(passwordProblem('a'.repeat(12), 1, { minLength: 12, minComplexity: 0 })).toBeNull();
  });
});

describe('a key derivation that meets the minimum', () => {
  const bitwarden: MinimumKdf = {
    pbkdf2Iterations: 600_000,
    argon2Memory: 64,
    argon2Iterations: 3,
    argon2Parallelism: 4,
  };

  it('is Bitwarden’s Argon2id default when that is enough', () => {
    expect(kdfForMinimum({ kind: 'pbkdf2', iterations: 100_000 }, bitwarden)).toEqual(
      DEFAULT_KDFS.argon2id,
    );
  });

  it('is raised to a stricter minimum', () => {
    const strict = { ...bitwarden, argon2Memory: 128, argon2Iterations: 2, argon2Parallelism: 8 };
    expect(kdfForMinimum(DEFAULT_KDFS.argon2id, strict)).toEqual({
      kind: 'argon2id',
      memory: 128,
      iterations: 3,
      parallelism: 8,
    });
  });

  it('keeps PBKDF2 when asked to, with enough rounds', () => {
    const old = { kind: 'pbkdf2', iterations: 100_000 } as const;
    expect(kdfForMinimum(old, bitwarden, true)).toEqual({ kind: 'pbkdf2', iterations: 600_000 });
    expect(kdfForMinimum(old, { ...bitwarden, pbkdf2Iterations: 900_000 }, true)).toEqual({
      kind: 'pbkdf2',
      iterations: 900_000,
    });
  });
});
