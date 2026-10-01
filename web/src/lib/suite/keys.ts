/**
 * SSH keys for UwUSSH's `key` records, made and read in the WebAssembly module
 * (`uwulock_core::suite::openssh`): a new Ed25519 key as OpenSSH text, and what a pasted key is.
 */

import { call, callJson } from '../web/core';

export type GeneratedKey = {
  privateKey: string;
  publicKey: string;
  keyType: string;
  fingerprint: string;
};

export type KeyInfo = {
  keyType: string;
  publicKey: string;
  fingerprint: string;
  comment: string;
  encrypted: boolean;
};

/** A new Ed25519 key; with a passphrase its private half is encrypted like ssh-keygen's. */
export const generateKey = (comment: string, passphrase: string) =>
  callJson<GeneratedKey>((core) => core.sshGenerateKey(comment, passphrase));

/** An OpenSSH private key's public half, read without its passphrase. */
export const inspectPrivateKey = (text: string) =>
  callJson<KeyInfo>((core) => core.sshInspectPrivateKey(text));

export const inspectPublicKey = (line: string) =>
  callJson<KeyInfo>((core) => core.sshInspectPublicKey(line));

export const passphraseOpens = (text: string, passphrase: string) =>
  call((core) => core.sshPassphraseOpens(text, passphrase));
