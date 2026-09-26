/**
 * The account, beyond the vault: registering, and everything in the settings that changes how
 * the account is unlocked or who can get in. The crypto for it runs in the WebAssembly module;
 * the server only ever gets hashes and wrapped keys.
 */

import { currentProfile, lock, logout, prelogin } from './api';
import { call, callJson } from './web/core';
import { deviceId, request } from './web/http';

export type AccountInfo = {
  admin: boolean;
  language: 'de' | 'en';
  mail: boolean;
  passwordHints: boolean;
  rememberTwoFactor: boolean;
  hasHint: boolean;
  twoFactor: number[];
  created: string;
  lastLogin: string | null;
};

export type Kdf =
  | { kind: 'pbkdf2'; iterations: number }
  | { kind: 'argon2id'; iterations: number; memory: number; parallelism: number };

/** Bitwarden's defaults for each: what a new account gets. */
export const DEFAULT_KDFS: Record<Kdf['kind'], Kdf> = {
  argon2id: { kind: 'argon2id', iterations: 3, memory: 64, parallelism: 4 },
  pbkdf2: { kind: 'pbkdf2', iterations: 600_000 },
};

/** The KDF the way the prelogin writes it, which is what the module reads. */
export function kdfText(kdf: Kdf): string {
  return kdf.kind === 'pbkdf2'
    ? JSON.stringify({ kdf: 0, kdfIterations: kdf.iterations })
    : JSON.stringify({
        kdf: 1,
        kdfIterations: kdf.iterations,
        kdfMemory: kdf.memory,
        kdfParallelism: kdf.parallelism,
      });
}

export function kdfOf(text: string): Kdf {
  const value = JSON.parse(text) as Record<string, number>;
  return value.kdf === 1
    ? {
        kind: 'argon2id',
        iterations: value.kdfIterations ?? 3,
        memory: value.kdfMemory ?? 64,
        parallelism: value.kdfParallelism ?? 4,
      }
    : { kind: 'pbkdf2', iterations: value.kdfIterations ?? 600_000 };
}

/** The KDF as the server's requests spell it. */
function kdfBody(kdf: Kdf) {
  return kdf.kind === 'pbkdf2'
    ? { kdfType: 0, iterations: kdf.iterations, memory: null, parallelism: null }
    : {
        kdfType: 1,
        iterations: kdf.iterations,
        memory: kdf.memory,
        parallelism: kdf.parallelism,
      };
}

export const account = () => request<AccountInfo>('/uwu/v1/account');

export const setLanguage = (language: 'de' | 'en') =>
  request('/uwu/v1/account/language', { method: 'PUT', body: { language } });

// ── Registering ───────────────────────────────────────────

export type Invitation = { email: string; expires: string; language: string };

export const invitation = (token: string) =>
  request<Invitation>('/uwu/v1/invitation', { method: 'POST', body: { token }, auth: false });

/**
 * A new account from an invitation: an RSA key pair from the browser's own crypto, the user key
 * and everything wrapped in the module, then `register/finish` with the invitation's token.
 */
export async function register(input: {
  token: string;
  email: string;
  name: string;
  password: string;
  hint: string;
  kdf: Kdf;
}): Promise<void> {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-1',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  const base64 = (buffer: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
  const publicKey = base64(await crypto.subtle.exportKey('spki', pair.publicKey));
  const privateKey = base64(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const made = await callJson<{ hash: string; key: string; encryptedPrivateKey: string }>((core) =>
    core.newAccount(input.email, input.password, kdfText(input.kdf), privateKey),
  );
  const kdf = kdfBody(input.kdf);
  await request('/identity/accounts/register/finish', {
    auth: false,
    body: {
      email: input.email,
      name: input.name.trim() || null,
      masterPasswordHash: made.hash,
      masterPasswordHint: input.hint.trim() || null,
      key: made.key,
      kdf: kdf.kdfType,
      kdfIterations: kdf.iterations,
      kdfMemory: kdf.memory,
      kdfParallelism: kdf.parallelism,
      keys: { publicKey, encryptedPrivateKey: made.encryptedPrivateKey },
      emailVerificationToken: input.token,
    },
  });
}

/** How strong a password is, in bits, the way the generator counts. */
export const strength = (password: string) => call((core) => core.entropyBits(password));

// ── Changing how the account is unlocked ──────────────────

type Rewrapped = {
  currentHash: string;
  newHash: string;
  newKey: string;
  email: string;
  kdf: { kdfType: number; iterations: number; memory: number | null; parallelism: number | null };
};

/** Every one of these ends every session, this one too: afterwards, log in again. */
async function endSession() {
  await lock();
  await logout();
}

export async function changePassword(current: string, next: string, hint: string) {
  const r = await callJson<Rewrapped>((core) => core.changePassword(current, next));
  await request('/api/accounts/password', {
    body: {
      masterPasswordHash: r.currentHash,
      newMasterPasswordHash: r.newHash,
      masterPasswordHint: hint.trim() || null,
      key: r.newKey,
    },
  });
  await endSession();
}

export async function changeKdf(password: string, kdf: Kdf) {
  const r = await callJson<Rewrapped>((core) => core.changeKdf(password, kdfText(kdf)));
  await request('/api/accounts/kdf', {
    body: {
      masterPasswordHash: r.currentHash,
      authenticationData: {
        salt: r.email,
        kdf: r.kdf,
        masterPasswordAuthenticationHash: r.newHash,
      },
      unlockData: { salt: r.email, kdf: r.kdf, masterKeyWrappedUserKey: r.newKey },
    },
  });
  await endSession();
}

/** Step one of a new address: a code goes to it. */
export async function requestEmailChange(password: string, email: string) {
  const hash = await call((core) => core.passwordHash(password));
  await request('/api/accounts/email-token', {
    body: { masterPasswordHash: hash, newEmail: email.trim() },
  });
}

/** Step two: with the code, the account moves; the address is the key's salt, so it is new too. */
export async function changeEmail(password: string, email: string, code: string) {
  const r = await callJson<Rewrapped>((core) => core.changeEmail(password, email));
  await request('/api/accounts/email', {
    body: {
      masterPasswordHash: r.currentHash,
      newEmail: r.email,
      newMasterPasswordHash: r.newHash,
      key: r.newKey,
      token: code.trim(),
    },
  });
  await endSession();
}

/** A new user key for everything in the vault. */
export async function rotateKeys(password: string) {
  const profile = currentProfile();
  const keys = profile?.accountKeys as Record<string, Record<string, string>> | null | undefined;
  const publicKey = keys?.publicKeyEncryptionKeyPair?.publicKey;
  if (!publicKey) throw { kind: 'invalid', message: 'This account has no key pair.' };
  const body = await callJson<unknown>((core) => core.rotate(password, publicKey));
  await request('/api/accounts/key-management/rotate-user-account-keys', { body });
  await endSession();
}

/** "Log out everywhere": every device, this one too. */
export async function logOutEverywhere(password: string) {
  const hash = await call((core) => core.passwordHash(password));
  await request('/api/accounts/security-stamp', { body: { masterPasswordHash: hash } });
  await endSession();
}

export async function deleteAccount(password: string) {
  const hash = await call((core) => core.passwordHash(password));
  await request('/api/accounts', { method: 'DELETE', body: { masterPasswordHash: hash } });
  await endSession();
}

export async function saveName(name: string) {
  await request('/api/accounts/profile', { method: 'PUT', body: { name: name.trim() || null } });
}

export async function passwordHintByMail(email: string) {
  await request('/api/accounts/password-hint', { auth: false, body: { email: email.trim() } });
}

export { prelogin };

// ── Two-step login ────────────────────────────────────────

/** The hash for the server, after the module checked the password. */
export const secret = async (password: string) => ({
  masterPasswordHash: await call((core) => core.passwordHash(password)),
});

export const authenticatorKey = async (password: string) =>
  request<{ enabled: boolean; key: string }>('/api/two-factor/get-authenticator', {
    body: await secret(password),
  });

export const enableAuthenticator = async (password: string, key: string, code: string) =>
  request('/api/two-factor/authenticator', {
    method: 'PUT',
    body: { ...(await secret(password)), key, token: code.trim() },
  });

export const sendSetupCode = async (password: string, email: string) =>
  request('/api/two-factor/send-email', {
    body: { ...(await secret(password)), email: email.trim() },
  });

export const enableEmailCodes = async (password: string, email: string, code: string) =>
  request('/api/two-factor/email', {
    method: 'PUT',
    body: { ...(await secret(password)), email: email.trim(), token: code.trim() },
  });

export const disableTwoFactor = async (password: string, kind: number) =>
  request('/api/two-factor/disable', { body: { ...(await secret(password)), type: kind } });

export const recoveryCode = async (password: string) =>
  request<{ code: string | null }>('/api/two-factor/get-recover', {
    body: await secret(password),
  });

// ── Devices ───────────────────────────────────────────────

export type Device = {
  id: string;
  name: string;
  type: number;
  typeName: string;
  created: string;
  lastSeen: string;
  lastIp: string | null;
  current: boolean;
  remembered: boolean;
};

export const devices = () => request<Device[]>('/uwu/v1/devices');

export const forgetDevice = (id: string) =>
  request(`/uwu/v1/devices/${encodeURIComponent(id)}`, { method: 'DELETE' });

export const thisDevice = () => deviceId();

// ── Import and export ─────────────────────────────────────

export async function exportVault(format: 'json' | 'csv', password: string): Promise<Blob> {
  await call((core) => core.passwordHash(password));
  const text = await call((core) => core.exportVault(format));
  return new Blob([text], { type: format === 'json' ? 'application/json' : 'text/csv' });
}

export async function importVault(format: 'json' | 'csv', text: string): Promise<number> {
  const body = await callJson<{ count: number }>((core) =>
    core.importVault(format, text, new Date().toISOString()),
  );
  await request('/api/ciphers/import', { body });
  return body.count;
}
