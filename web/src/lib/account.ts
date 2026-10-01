/**
 * The account, beyond the vault: registering, and everything in the settings that changes how
 * the account is unlocked or who can get in. The crypto for it runs in the WebAssembly module;
 * the server only ever gets hashes and wrapped keys.
 */

import { currentProfile, lock, logout, prelogin } from './api';
import type { BreachSwitches } from './breaches';
import { t } from './i18n';
import { call, callJson } from './web/core';
import { openExtras } from './requests';
import { type SendDomain } from './links';
import { ApiError, deviceId, request } from './web/http';

export type AccountInfo = {
  admin: boolean;
  language: 'de' | 'en';
  mail: boolean;
  passwordHints: boolean;
  rememberTwoFactor: boolean;
  hibp: boolean;
  /** The breach sources the server offers (§15); missing on servers before 0.7. */
  breaches?: BreachSwitches;
  /** Whether this account agreed to the check of its addresses; null when that is off. */
  emailBreachCheck?: { optedIn: boolean; since: string | null } | null;
  maxFileMb: number;
  /** Whether this account may invite people (in the settings, under Invite). */
  mayInvite: boolean;
  hasHint: boolean;
  twoFactor: number[];
  created: string;
  lastLogin: string | null;
  /** The server's rules as they apply to this account (§20). */
  policy?: {
    twoFactorRequired: boolean;
    /** From then on only the web vault lets an account without two-step login in. */
    twoFactorDeadline: string | null;
    /** The deadline has passed. */
    twoFactorEnforced: boolean;
    kdfBelowMinimum: boolean;
    minimumKdf: MinimumKdf;
  };
  securityNoticesUnseen?: number;
  /** False for an account made through SSO until its master password is set. */
  hasMasterPassword?: boolean;
  /** This session's login came through SSO. */
  sso?: boolean;
  /** The admin portal takes only sessions from an SSO login. */
  adminNeedsSso?: boolean;
  /** Whether this account may make a family, and how large one may be (§16.4). */
  families?: { mayCreate: boolean; maxMembers: number; owned: number; perUser: number };
  /** The send domain new Sends get (§14.2); null: the main host. */
  sendDomainId?: string | null;
  /** Whether masked addresses are connected to UwUMail (§13.2). */
  maskedConnected?: boolean;
  /** Travel mode (§9): while it is on, two-step login cannot be changed. */
  travel?: { enabled: boolean };
};

export type MinimumKdf = {
  pbkdf2Iterations: number;
  argon2Memory: number;
  argon2Iterations: number;
  argon2Parallelism: number;
};

/** The rules for a new master password: `minComplexity` is a zxcvbn score, 0 (none) to 4. */
export type PasswordRules = { minLength: number; minComplexity: number; enforceOnLogin?: boolean };

/** The server's own look (§14.4): UwULock's unless an admin changed it. */
export type Branding = {
  name: string;
  color: string;
  custom: boolean;
  logoLight: string | null;
  logoDark: string | null;
  favicon: string | null;
};

/** What the server tells anybody before a login; only what the web vault uses of it. */
export type ServerInfo = {
  /** What the server has and has switched on: `send-emails`, `twofa-directory`, … */
  features?: string[];
  /** Every feature switch (docs/features.md) and whether it works: see `lib/switches.ts`. */
  switches?: Record<string, boolean>;
  mail?: boolean;
  branding?: Branding;
  policies?: { masterPassword?: PasswordRules };
  /** Logging in through an OpenID Connect provider (§19): `label` goes on the button. */
  sso?: { enabled: boolean; only: boolean; identifier: string; label: string };
  /** The admin's send domains (§14.1), without the main host. */
  sendDomains?: SendDomain[];
};

export const serverInfo = () => request<ServerInfo>('/uwu/v1/info', { auth: false });

/** Without a word from the server: what Bitwarden's clients ask anyway. */
export const DEFAULT_RULES: PasswordRules = { minLength: 12, minComplexity: 0 };

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

/** The send domain new Sends and file requests get at first; null: the main host. */
export const setDefaultSendDomain = (sendDomainId: string | null) =>
  request('/uwu/v1/account/send-domain', { method: 'PUT', body: { sendDomainId } });

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
  /** A family's invitation instead of the server's (docs/uwu-api.md §16.2). */
  family?: { token: string; memberId: string };
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
      ...(input.family
        ? { orgInviteToken: input.family.token, organizationUserId: input.family.memberId }
        : { emailVerificationToken: input.token }),
    },
  });
}

/**
 * The first master password of an account made through SSO (docs/uwu-api.md §19.2 step 6): keys
 * made here as for a registration, sent with the session of the SSO login.
 */
export async function setInitialPassword(input: {
  email: string;
  password: string;
  hint: string;
  kdf: Kdf;
  /** A family's invitation instead of the server's (docs/uwu-api.md §16.2). */
  family?: { token: string; memberId: string };
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
  await request('/api/accounts/set-password', {
    body: {
      masterPasswordHash: made.hash,
      masterPasswordHint: input.hint.trim() || null,
      key: made.key,
      kdf: kdf.kdfType,
      kdfIterations: kdf.iterations,
      kdfMemory: kdf.memory,
      kdfParallelism: kdf.parallelism,
      keys: { publicKey, encryptedPrivateKey: made.encryptedPrivateKey },
      orgIdentifier: null,
    },
  });
}

/** How strong a password is, in bits, the way the generator counts. */
export const strength = (password: string) => call((core) => core.entropyBits(password));

/**
 * The bits as a score from 0 to 4 like zxcvbn's, which the admin's rule is written in. zxcvbn
 * draws its lines at 10³, 10⁶, 10⁸ and 10¹⁰ guesses: that is 10, 20, 26.6 and 33.2 bits.
 */
export function complexityScore(bits: number): number {
  if (bits < 10) return 0;
  if (bits < 20) return 1;
  if (bits < 26.6) return 2;
  if (bits < 33.2) return 3;
  return 4;
}

/** Why a new master password is refused under `rules`, or null when it is fine. */
export function passwordProblem(
  password: string,
  bits: number,
  rules: PasswordRules,
): string | null {
  // Bitwarden's clients ask for 12 characters whatever the server says; so does this one.
  const length = Math.max(rules.minLength, DEFAULT_RULES.minLength);
  if ([...password].length < length) return t('Mindestens {n} Zeichen.', { n: length });
  if (rules.minComplexity > 0 && complexityScore(bits) < rules.minComplexity)
    return t(
      'Dieser Server verlangt ein stärkeres Master-Passwort (Stufe {need} von 4, dieses hat {has}).',
      {
        need: rules.minComplexity,
        has: complexityScore(bits),
      },
    );
  return null;
}

/**
 * Key derivation settings that meet the server's minimum. Bitwarden's Argon2id default when that
 * is enough; otherwise Argon2id raised to the minimum — or, for an account on PBKDF2 when
 * Argon2id is not the answer, PBKDF2 with enough rounds.
 */
export function kdfForMinimum(current: Kdf, minimum: MinimumKdf, keepKind = false): Kdf {
  if (keepKind && current.kind === 'pbkdf2')
    return {
      kind: 'pbkdf2',
      iterations: Math.max(DEFAULT_KDFS.pbkdf2.iterations, minimum.pbkdf2Iterations),
    };
  const base = DEFAULT_KDFS.argon2id as Extract<Kdf, { kind: 'argon2id' }>;
  return {
    kind: 'argon2id',
    memory: Math.max(base.memory, minimum.argon2Memory),
    iterations: Math.max(base.iterations, minimum.argon2Iterations),
    parallelism: Math.max(base.parallelism, minimum.argon2Parallelism),
  };
}

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

/** An emergency contact who gets the new user key too, with the phrase to check them by. */
export type RotationContact = { id: string; who: string; publicKey: string; phrase: string };

/**
 * The emergency contacts who hold the user key, each with the public key the server has for
 * them and its fingerprint phrase. The new key is wrapped for exactly these keys, so the person
 * compares the phrases first: a key the server swapped would get the whole vault.
 */
export async function rotationContacts(): Promise<RotationContact[]> {
  const trusted = await request<{
    data: {
      id: string;
      granteeId: string | null;
      name: string | null;
      email: string | null;
      status: number;
    }[];
  }>('/api/emergency-access/trusted');
  const contacts = [];
  for (const contact of trusted.data.filter((c) => c.status >= 2 && c.granteeId)) {
    const key = await request<{ publicKey: string }>(
      `/api/users/${encodeURIComponent(contact.granteeId!)}/public-key`,
    );
    const phrase = await call((core) => core.fingerprint(contact.granteeId!, key.publicKey));
    contacts.push({
      id: contact.id,
      who: contact.name || contact.email || '?',
      publicKey: key.publicKey,
      phrase,
    });
  }
  return contacts;
}

/** A new user key for everything in the vault, wrapped for `contacts` as they were checked. */
export async function rotateKeys(password: string, contacts: RotationContact[]) {
  const profile = currentProfile();
  const keys = profile?.accountKeys as Record<string, Record<string, string>> | null | undefined;
  const publicKey = keys?.publicKeyEncryptionKeyPair?.publicKey;
  if (!publicKey) throw { kind: 'invalid', message: 'This account has no key pair.' };
  // Everybody else who holds the user key gets the new one too.
  const emergency = contacts.map((contact) => ({ id: contact.id, publicKey: contact.publicKey }));
  const passkeys = (
    await request<{ data: { id: string; prfStatus: number; encryptedPublicKey: string | null }[] }>(
      '/api/webauthn',
    )
  ).data
    .filter((passkey) => passkey.prfStatus === 0 && passkey.encryptedPublicKey)
    .map((passkey) => ({ id: passkey.id, encryptedPublicKey: passkey.encryptedPublicKey }));
  const holders = JSON.stringify({ emergency, passkeys });
  // UwULock's own under the user key comes along: the extras key, wrapped for the new key, and
  // every earlier version of an item, encrypted anew (docs/uwu-api.md §3).
  await openExtras().catch((error: { kind?: string }) => {
    if (error?.kind !== 'extras-lost') throw error;
  });
  for (let attempt = 0; ; attempt++) {
    const versions = await request<unknown>('/uwu/v1/versions?scope=personal');
    const body = await callJson<unknown>((core) =>
      core.rotateUwu(password, publicKey, holders, JSON.stringify(versions)),
    );
    try {
      await request('/uwu/v1/accounts/rotate-keys', { body });
      break;
    } catch (error) {
      // A version came or went in between: once more with the list as it is now.
      if ((error as ApiError).status !== 409 || attempt > 0) throw error;
    }
  }
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
  /** The UwU app behind a suite login (`uwussh`, `uwurdp`), `null` for everything else. */
  app: string | null;
};

export const devices = () => request<Device[]>('/uwu/v1/devices');

// ── Suite vault (docs/suite.md) ───────────────────────────

export type SuiteSpace = {
  space: string;
  id: string;
  records: number;
  bytes: number;
  revisionDate: string;
};

export const suiteSpaces = async () =>
  (await request<{ data: SuiteSpace[] }>('/uwu/v1/suite/spaces')).data;

export const deleteSuiteSpace = async (space: string, password: string) =>
  request(`/uwu/v1/suite/spaces/${encodeURIComponent(space)}`, {
    method: 'DELETE',
    body: await secret(password),
  });

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

// ── Inviting people ───────────────────────────────────────

export type MyInvitation = { email: string; created: string; expires: string; expired: boolean };

export type MyInvitations = {
  allowed: boolean;
  /** How many one may bring in; none for admins. */
  quota: number | null;
  used: number;
  invitations: MyInvitation[];
};

export const myInvitations = () => request<MyInvitations>('/uwu/v1/invitations');
export const invitePerson = (email: string) =>
  request<{ email: string; link: string | null; mailed: boolean; expires: string }>(
    '/uwu/v1/invitations',
    { body: { email } },
  );
export const withdrawInvitation = (email: string) =>
  request(`/uwu/v1/invitations/${encodeURIComponent(email)}`, { method: 'DELETE' });
