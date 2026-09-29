/**
 * KeePass's key derivations for the web vault: Argon2d, Argon2id and AES-KDF in the WebAssembly
 * module (web/wasm/src/kdbx.rs). They run on the page's thread; with the parameters KeePassXC
 * picks by default that takes a second or two.
 */

import { call } from '../web/core';
import type { KdbxKdf } from './types';

export const wasmKdf: KdbxKdf = {
  argon2: (id, version, key, salt, memoryKiB, iterations, lanes) =>
    call((core) => core.kdbxArgon2(id, version, key, salt, memoryKiB, iterations, lanes)),
  aesKdf: (key, seed, rounds) => call((core) => core.kdbxAesKdf(key, seed, rounds)),
};
