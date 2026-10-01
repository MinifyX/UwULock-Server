/**
 * The vault, for the page: the same calls the desktop app makes into Rust, answered here by
 * the WebAssembly module (keys, crypto, the opened vault) and the server's API.
 *
 * Everything secret stays in the module: the page gets names, usernames and notes, and a
 * password only when someone asks to see it (`revealField`). After every change the vault is
 * synced again — the server answers that in one request.
 */

import { emit, listen } from './events';
import { getSettings } from './settings';
import { call, callJson } from './web/core';
import { ApiError, currentSession, deviceId, deviceType, request, setSession } from './web/http';
import { startLive, stopLive } from './web/live';
import * as webauthn from './web/webauthn';

export type Failure = { kind: string; message: string };

export type ServerKind = 'bitwarden-us' | 'bitwarden-eu' | 'self-hosted';

/** One account in the switcher. */
export type AccountBrief = {
  id: string;
  label: string;
  email: string;
  name: string | null;
  server: string;
  serverKind: ServerKind;
  unlocked: boolean;
  active: boolean;
  lastSync: number | null;
};

export type Status = {
  state: 'logged-out' | 'locked' | 'unlocked';
  accountId: string | null;
  label: string | null;
  email: string | null;
  name: string | null;
  server: string | null;
  serverKind: ServerKind | null;
  serverUrl: string | null;
  lastSync: number | null;
  syncing: boolean;
  syncError: string | null;
  sessionExpired: boolean;
  accounts: AccountBrief[];
};

export type TwoFactorMethod = {
  provider: number;
  kind: 'authenticator' | 'email' | 'yubikey' | 'duo' | 'webauthn' | 'u2f' | 'other';
  supported: boolean;
  hint: string | null;
  /** For a security key: the options the server gave for it. */
  options?: Record<string, unknown> | null;
};

export type LoginStep =
  | { step: 'done'; status: Status }
  | { step: 'two-factor'; methods: TwoFactorMethod[]; message: string | null }
  | { step: 'new-device' };

/** `wifi` is a secure note with UwULock's marker field (lib/wifi.ts); saved as a `note`. */
export type ItemKind = 'login' | 'note' | 'card' | 'identity' | 'ssh-key' | 'wifi';

export type ItemSummary = {
  id: string;
  kind: ItemKind;
  name: string;
  subtitle: string | null;
  host: string | null;
  favorite: boolean;
  folderId: string | null;
  organizationId: string | null;
  collectionIds: string[];
  deleted: boolean;
  archived: boolean;
  reprompt: boolean;
  hasTotp: boolean;
  hasPassword: boolean;
  hasUsername: boolean;
  broken: boolean;
  revisionDate: string | null;
};

export type Folder = { id: string; name: string };
export type Collection = { id: string; organizationId: string; name: string };
export type Organization = { id: string; name: string };
export type Overview = {
  folders: Folder[];
  collections: Collection[];
  organizations: Organization[];
  skipped: number;
};

export type FieldKind = 'text' | 'hidden' | 'boolean' | 'linked';

export type ItemDetail = {
  summary: ItemSummary;
  locked: boolean;
  notes?: string | null;
  login?: {
    username: string | null;
    hasPassword: boolean;
    hasTotp: boolean;
    passwordRevisionDate: string | null;
    uris: { uri: string; match: number | null; host: string | null; openable: boolean }[];
    passkeys: number;
  } | null;
  card?: {
    cardholderName: string | null;
    brand: string | null;
    numberEnding: string | null;
    expMonth: string | null;
    expYear: string | null;
    hasCode: boolean;
  } | null;
  identity?: { name: string; sensitive: boolean; value: string | null }[] | null;
  sshKey?: {
    publicKey: string | null;
    fingerprint: string | null;
    hasPrivateKey: boolean;
  } | null;
  fields?: {
    index: number;
    name: string | null;
    kind: FieldKind;
    value: string | null;
    hasValue: boolean;
  }[];
  passwordHistory?: { index: number; lastUsed: string | null }[];
  attachments?: number;
  creationDate?: string | null;
};

export type TotpCode = { code: string; remaining: number; period: number };

/**
 * What the editor sends back. A secret it never had — a password nobody
 * looked at, a card number, a hidden field — stays `null`, and Rust keeps the
 * value the item already has; `''` clears it.
 */
export type Draft = {
  kind: ItemKind;
  name: string;
  notes?: string | null;
  favorite: boolean;
  reprompt: boolean;
  folderId: string | null;
  login?: {
    username?: string | null;
    password?: string | null;
    totp?: string | null;
    uris: { uri: string; match: number | null }[];
  };
  card?: {
    cardholderName?: string | null;
    brand?: string | null;
    number?: string | null;
    expMonth?: string | null;
    expYear?: string | null;
    code?: string | null;
  };
  /** By field name; a name that isn't in here keeps its value. */
  identity?: Record<string, string>;
  sshKey?: {
    privateKey?: string | null;
    publicKey?: string | null;
    fingerprint?: string | null;
  };
  fields: {
    name: string | null;
    kind: FieldKind;
    value?: string | null;
    /** Which field of the item this one was, for a value the editor never saw. */
    from: number | null;
  }[];
};

export type GeneratorOptions = {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
};

export type UpdateInfo = { version: string; notes: string | null };
export type ProjectPage = 'source' | 'releases' | 'issues' | 'license' | 'suite';

// ── State ─────────────────────────────────────────────────

type Pending = {
  email: string;
  hash: string;
  kdf: string;
  methods: TwoFactorMethod[];
  /** An SSO login: the form of its code, in place of the password's. */
  form?: Record<string, string>;
};

let pending: Pending | null = null;
let lastSync: number | null = null;
let syncing = false;
let syncError: string | null = null;
let name: string | null = null;
/** The profile of the last sync, for what the module does not keep: the public key. */
let profile: Record<string, unknown> | null = null;
let unlocked = false;

/** Errors as `{ kind, message }`, whatever threw them. */
export function failure(error: unknown): Failure {
  if (error instanceof ApiError) {
    const kind =
      error.status === 401 ? 'session-expired' : error.status === 0 ? 'network' : 'server';
    return { kind, message: error.message };
  }
  if (typeof error === 'object' && error !== null && 'kind' in error) return error as Failure;
  return { kind: 'unknown', message: String(error) };
}

async function status(): Promise<Status> {
  const session = currentSession();
  const state: Status['state'] = !session ? 'logged-out' : unlocked ? 'unlocked' : 'locked';
  return {
    state,
    accountId: session ? session.email : null,
    label: session?.email ?? null,
    email: session?.email ?? null,
    name,
    server: location.host,
    serverKind: 'self-hosted',
    serverUrl: location.origin,
    lastSync,
    syncing,
    syncError,
    sessionExpired: false,
    accounts: [],
  };
}

async function announce(): Promise<Status> {
  const next = await status();
  emit('vault-status', next);
  return next;
}

function kdfText(prelogin: Record<string, unknown>): string {
  return JSON.stringify({
    kdf: prelogin.kdf ?? 0,
    kdfIterations: prelogin.kdfIterations,
    kdfMemory: prelogin.kdfMemory,
    kdfParallelism: prelogin.kdfParallelism,
  });
}

export async function prelogin(email: string): Promise<string> {
  const body = await request<Record<string, unknown>>('/identity/accounts/prelogin', {
    body: { email: email.trim().toLowerCase() },
    auth: false,
  });
  return kdfText(body);
}

// ── Logging in ────────────────────────────────────────────

const TWO_FACTOR_KINDS: Record<string, [TwoFactorMethod['kind'], boolean]> = {
  '0': ['authenticator', true],
  '1': ['email', true],
  '2': ['duo', false],
  '3': ['yubikey', false],
  '7': ['webauthn', true],
};

async function token(extra: Record<string, string>): Promise<LoginStep> {
  const p = pending!;
  const device = deviceType();
  const form = new URLSearchParams({
    ...(p.form ?? {
      grant_type: 'password',
      username: p.email,
      password: p.hash,
      scope: 'api offline_access',
      client_id: 'web',
    }),
    deviceType: String(device.kind),
    deviceIdentifier: deviceId(),
    deviceName: device.name,
    ...extra,
  });
  let body: Record<string, unknown>;
  try {
    body = await request<Record<string, unknown>>('/identity/connect/token', {
      form,
      auth: false,
    });
  } catch (error) {
    if (error instanceof ApiError && error.body && typeof error.body === 'object') {
      const refusal = error.body as Record<string, unknown>;
      const providers = refusal.TwoFactorProviders2 as
        Record<string, ({ Email?: string } & Record<string, unknown>) | null> | undefined;
      if (providers) {
        p.methods = Object.entries(providers).map(([provider, details]) => {
          const [kind, supported] = TWO_FACTOR_KINDS[provider] ?? ['other', false];
          return {
            provider: Number(provider),
            kind,
            supported: supported && (kind !== 'webauthn' || webauthn.available()),
            hint: details?.Email ?? null,
            options: kind === 'webauthn' ? details : null,
          };
        });
        const message = extra.twoFactorToken ? error.message : null;
        return { step: 'two-factor', methods: p.methods, message };
      }
    }
    throw failure(error);
  }
  if (p.form) {
    // Through SSO: logged in, but the vault opens only with the master password — or, for an
    // account made just now, waits for its first one.
    pending = null;
    return finishKeyless(body, async () => false);
  }
  setSession({
    email: p.email,
    accessToken: String(body.access_token),
    refreshToken: String(body.refresh_token),
    expiresAt: Date.now() + Number(body.expires_in ?? 3600) * 1000,
  });
  await call((core) => core.unlock(p.email, p.kdf, String(body.Key)));
  pending = null;
  unlocked = true;
  await sync();
  return { step: 'done', status: await announce() };
}

export const login = async (
  _server: { kind: ServerKind; url?: string },
  email: string,
  password: string,
): Promise<LoginStep> => {
  const address = email.trim().toLowerCase();
  const kdf = await prelogin(address);
  const hash = await call((core) => core.deriveLogin(address, password, kdf));
  pending = { email: address, hash, kdf, methods: [] };
  return token({});
};

/**
 * Trade the code an SSO login brought back (docs/uwu-api.md §19.2 step 5). The server's own
 * two-step login may still ask for its second step, as after a password.
 */
export const loginSso = (code: string, verifier: string): Promise<LoginStep> => {
  pending = {
    email: '',
    hash: '',
    kdf: '',
    methods: [],
    form: {
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      redirect_uri: `${location.origin}/sso-connector.html`,
      client_id: 'web',
      scope: 'api offline_access',
    },
  };
  return token({});
};

export const loginTwoFactor = (provider: number, code: string, remember: boolean) =>
  token({
    twoFactorProvider: String(provider),
    twoFactorToken: provider === 7 ? code : code.trim().replace(/\s/g, ''),
    twoFactorRemember: remember ? '1' : '0',
  });

/** The second step with a security key: it signs the server's challenge. */
export async function loginSecurityKey(method: TwoFactorMethod, remember: boolean) {
  if (!method.options) throw { kind: 'invalid', message: 'The server sent no challenge.' };
  const credential = await webauthn.get(webauthn.requestOptions(method.options));
  return loginTwoFactor(7, JSON.stringify(webauthn.assertionJson(credential)), remember);
}

/** A login without the master password: the tokens are here, the key came another way. */
async function finishKeyless(
  body: Record<string, unknown>,
  unlock: (email: string, kdf: string) => Promise<boolean>,
): Promise<LoginStep> {
  const claims = JSON.parse(
    atob(String(body.access_token).split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')),
  ) as { email: string };
  const email = claims.email;
  setSession({
    email,
    accessToken: String(body.access_token),
    refreshToken: String(body.refresh_token ?? ''),
    expiresAt: Date.now() + Number(body.expires_in ?? 3600) * 1000,
  });
  const kdf = await prelogin(email);
  unlocked = await unlock(email, kdf);
  if (unlocked) await sync();
  return { step: 'done', status: await announce() };
}

function loginForm(extra: Record<string, string>): URLSearchParams {
  const device = deviceType();
  return new URLSearchParams({
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: String(device.kind),
    deviceIdentifier: deviceId(),
    deviceName: device.name,
    ...extra,
  });
}

/**
 * Log in with a passkey the browser picks. One that can unlock (PRF) opens the vault too;
 * with another, the vault stays locked until the master password.
 */
export async function loginPasskey(): Promise<LoginStep> {
  const offer = await request<{ options: Record<string, unknown>; token: string }>(
    '/identity/accounts/webauthn/assertion-options',
    { auth: false },
  );
  const salt = await call((core) => core.prfSalt());
  const credential = await webauthn.get(webauthn.requestOptions(offer.options, salt));
  let body: Record<string, unknown>;
  try {
    body = await request<Record<string, unknown>>('/identity/connect/token', {
      form: loginForm({
        grant_type: 'webauthn',
        token: offer.token,
        deviceResponse: JSON.stringify(webauthn.assertionJson(credential)),
      }),
      auth: false,
    });
  } catch (error) {
    throw failure(error);
  }
  const prf = webauthn.prfOutput(credential);
  const option = (body.UserDecryptionOptions as Record<string, unknown> | undefined)
    ?.WebAuthnPrfOption as Record<string, string> | undefined;
  return finishKeyless(body, async (email, kdf) => {
    if (!prf || !option) return false;
    await call((core) =>
      core.unlockWithPasskey(
        email,
        kdf,
        prf,
        option.EncryptedPrivateKey!,
        option.EncryptedUserKey!,
      ),
    );
    return true;
  });
}

export type DeviceLogin = { id: string; fingerprint: string; accessCode: string; email: string };

/** Ask a device that is logged in already to let this one in. */
export async function startDeviceLogin(email: string): Promise<DeviceLogin> {
  const address = email.trim().toLowerCase();
  const made = await callJson<{ publicKey: string; fingerprint: string; accessCode: string }>(
    (core) => core.startDeviceLogin(address),
  );
  const answer = await request<{ id: string }>('/api/auth-requests', {
    body: {
      email: address,
      publicKey: made.publicKey,
      deviceIdentifier: deviceId(),
      accessCode: made.accessCode,
      type: 0,
    },
    auth: false,
  });
  return {
    id: answer.id,
    fingerprint: made.fingerprint,
    accessCode: made.accessCode,
    email: address,
  };
}

/** Whether the other device answered: `null` while it has not, the login once it said yes. */
export async function checkDeviceLogin(started: DeviceLogin): Promise<LoginStep | 'denied' | null> {
  const answer = await request<Record<string, unknown>>(
    `/api/auth-requests/${encodeURIComponent(started.id)}/response?code=${encodeURIComponent(started.accessCode)}`,
    { auth: false },
  );
  if (answer.requestApproved === false) return 'denied';
  if (answer.requestApproved !== true || !answer.key) return null;
  let body: Record<string, unknown>;
  try {
    body = await request<Record<string, unknown>>('/identity/connect/token', {
      form: loginForm({
        grant_type: 'password',
        username: started.email,
        password: started.accessCode,
        authRequest: started.id,
      }),
      auth: false,
    });
  } catch (error) {
    throw failure(error);
  }
  return finishKeyless(body, async (email, kdf) => {
    await call((core) => core.finishDeviceLogin(email, kdf, String(answer.key)));
    return true;
  });
}

export const loginNewDevice = async (_code: string): Promise<LoginStep> => {
  throw { kind: 'unsupported', message: 'This server does not ask for new devices.' };
};

export const loginSendEmail = async () => {
  if (!pending) return;
  await request('/api/two-factor/send-email-login', {
    body: {
      email: pending.email,
      masterPasswordHash: pending.hash,
      deviceIdentifier: deviceId(),
    },
    auth: false,
  });
};

export const loginCancel = async () => {
  pending = null;
  // The master key from the first step is wiped too, not left until the next lock.
  if (!unlocked) await call((core) => core.lock());
};

/** After a reload: the session is still there, the keys are not. */
export const unlock = async (password: string): Promise<Status> => {
  const session = currentSession();
  if (!session) throw { kind: 'session-expired', message: 'Log in again.' };
  const kdf = await prelogin(session.email);
  await call((core) => core.deriveLogin(session.email, password, kdf));
  const sync = await request<Record<string, unknown>>('/api/sync?excludeDomains=true');
  const key = (sync.profile as Record<string, unknown>).key as string;
  await call((core) => core.unlock(session.email, kdf, key));
  unlocked = true;
  await open(sync);
  return announce();
};

export const lock = async () => {
  // Whatever was copied from the vault goes with it, as soon as the page may touch the clipboard.
  clearDue = toClear !== null;
  void clearClipboard();
  stopLive();
  await call((core) => core.lock());
  unlocked = false;
  await announce();
};

export const logout = async (_id?: string): Promise<Status> => {
  if (currentSession()) {
    // This browser's refresh token is gone too, not only the page's copy of it.
    await request(`/uwu/v1/devices/${encodeURIComponent(deviceId())}`, {
      method: 'DELETE',
    }).catch(() => undefined);
  }
  stopLive();
  setSession(null);
  clearDue = toClear !== null;
  void clearClipboard();
  await call((core) => core.lock());
  unlocked = false;
  name = null;
  profile = null;
  return announce();
};

// ── Locking by itself ─────────────────────────────────────

let lastActive = Date.now();
let autoLockMinutes: number | null = null;
let clipboardSeconds: number | null = null;

export const touch = async () => {
  lastActive = Date.now();
};

export const setSecurity = async (minutes: number | null, seconds: number | null) => {
  autoLockMinutes = minutes;
  clipboardSeconds = seconds;
};

setInterval(() => {
  if (unlocked && autoLockMinutes && Date.now() - lastActive > autoLockMinutes * 60_000)
    void lock();
}, 15_000);

// A session the server ended — "log out everywhere" on another device, a new master password,
// an admin — closes an open vault here too, keys and all, instead of leaving it readable in a
// tab somebody else may be sitting at.
void listen('session-ended', () => {
  stopLive();
  void call((core) => core.lock()).finally(() => {
    unlocked = false;
    name = null;
    profile = null;
    void announce();
  });
});

// Another device changed something: the hub says so, and the vault here follows.
void listen('hub-sync', () => {
  if (unlocked && !syncing) void sync().then(announce, () => undefined);
});

// The account's sessions were ended somewhere: asking the server tells whether ours was too —
// and if so, the vault closes as above.
void listen('hub-logout', () => {
  if (currentSession()) void request('/api/accounts/revision-date').catch(() => undefined);
});

// Asked now and then, so a vault nobody syncs notices that too.
setInterval(() => {
  if (unlocked && currentSession())
    void request('/api/accounts/revision-date').catch(() => undefined);
}, 5 * 60_000);

// ── The vault ─────────────────────────────────────────────

async function open(sync: Record<string, unknown>) {
  profile = sync.profile as Record<string, unknown>;
  name = (profile.name as string | null) ?? null;
  await call((core) => core.open(JSON.stringify(sync)));
  lastSync = Math.floor(Date.now() / 1000);
  syncError = null;
  emit('vault-changed');
  // However the vault was opened — password, passkey, another device — from now on it listens.
  startLive();
}

/** Fetch the vault again and open it. */
export async function sync(): Promise<void> {
  syncing = true;
  try {
    const body = await request<Record<string, unknown>>('/api/sync?excludeDomains=true');
    await open(body);
  } catch (error) {
    syncError = failure(error).message;
    throw failure(error);
  } finally {
    syncing = false;
  }
}

export const syncNow = async (): Promise<Status> => {
  await sync();
  return announce();
};

/** The profile of the last sync. */
export const currentProfile = () => profile;

export const vaultStatus = () => status();
export const vaultOverview = () => callJson<Overview>((core) => core.overview());
export const vaultItems = () => callJson<ItemSummary[]>((core) => core.items());
export const vaultItem = (id: string) => callJson<ItemDetail>((core) => core.item(id));
export const verifyReprompt = (id: string, password: string) =>
  call((core) => core.verifyReprompt(id, password));
export const revealField = (id: string, field: string) =>
  call((core) => core.reveal(id, field, Date.now() / 1000));

let clearTimer: number | undefined;
/** What is still to be taken off the clipboard, once the time is up. */
let toClear: string | null = null;
let clearDue = false;

/**
 * Take what was copied off the clipboard, if it is still there. A browser lets a page at the
 * clipboard only while it has the focus — and when the time is up, the person has usually gone
 * to another window to paste. So this is tried when the time is up, and again whenever the page
 * is back in use, until it worked.
 */
async function clearClipboard() {
  if (!toClear || !clearDue || !document.hasFocus()) return;
  const copied = toClear;
  try {
    // Reading may be refused where writing is not: then it is cleared either way.
    const now = await navigator.clipboard.readText().catch(() => copied);
    if (now === copied) await navigator.clipboard.writeText('');
    if (toClear === copied) {
      toClear = null;
      clearDue = false;
    }
  } catch {
    // Not now; the next time the page is used.
  }
}

for (const name of ['focus', 'pointerdown', 'keydown']) {
  window.addEventListener(name, () => void clearClipboard(), true);
}

/** Copy `text`, and take it off the clipboard again after the configured time. */
async function copy(text: string) {
  await navigator.clipboard.writeText(text);
  window.clearTimeout(clearTimer);
  const seconds = clipboardSeconds ?? getSettings().clipboardClear;
  toClear = seconds ? text : null;
  clearDue = false;
  if (seconds) {
    clearTimer = window.setTimeout(() => {
      clearDue = true;
      void clearClipboard();
    }, seconds * 1000);
  }
}

export const copyField = async (id: string, field: string) => copy(await revealField(id, field));
export const copyGenerated = (text: string) => copy(text);
export const totpCode = (id: string) =>
  callJson<TotpCode>((core) => core.totp(id, Date.now() / 1000));
export const generatePassword = (options: GeneratorOptions) =>
  callJson<{ password: string; bits: number }>((core) => core.generate(JSON.stringify(options)));

// ── Saving ────────────────────────────────────────────────

async function changed<T>(write: Promise<T>): Promise<T> {
  let result: T;
  try {
    result = await write;
  } catch (error) {
    throw failure(error);
  }
  await sync().catch(() => undefined);
  return result;
}

export const saveItem = async (id: string | null, draft: Draft): Promise<string> => {
  const sealed = await call((core) =>
    core.sealDraft(id ?? '', JSON.stringify(draft), new Date().toISOString()),
  );
  const body = JSON.parse(sealed) as Record<string, unknown>;
  if (!id) {
    const session = currentSession();
    body.encryptedFor = (profile?.id as string | undefined) ?? session?.email;
    const created = await changed(request<{ id: string }>('/api/ciphers', { body }));
    return created.id;
  }
  await changed(request(`/api/ciphers/${encodeURIComponent(id)}`, { method: 'PUT', body }));
  return id;
};

async function summaryOf(id: string): Promise<ItemSummary> {
  const found = (await vaultItems()).find((item) => item.id === id);
  if (!found) throw { kind: 'not-found', message: "This item isn't in the vault any more." };
  return found;
}

export const setFavorite = async (id: string, favorite: boolean) => {
  const item = await summaryOf(id);
  await changed(
    request(`/api/ciphers/${encodeURIComponent(id)}/partial`, {
      method: 'PUT',
      body: { folderId: item.folderId, favorite },
    }),
  );
};

export const setItemFolder = async (id: string, folderId: string | null) => {
  const item = await summaryOf(id);
  await changed(
    request(`/api/ciphers/${encodeURIComponent(id)}/partial`, {
      method: 'PUT',
      body: { folderId, favorite: item.favorite },
    }),
  );
};

export const deleteItem = (id: string, permanent: boolean) =>
  changed(
    permanent
      ? request(`/api/ciphers/${encodeURIComponent(id)}`, { method: 'DELETE' })
      : request(`/api/ciphers/${encodeURIComponent(id)}/delete`, { method: 'PUT' }),
  ).then(() => undefined);

export const restoreItem = (id: string) =>
  changed(request(`/api/ciphers/${encodeURIComponent(id)}/restore`, { method: 'PUT' })).then(
    () => undefined,
  );

export const archiveItem = (id: string, archived: boolean) =>
  changed(
    request(`/api/ciphers/${encodeURIComponent(id)}/${archived ? 'archive' : 'unarchive'}`, {
      method: 'PUT',
    }),
  ).then(() => undefined);

/** Several items at once: into the trash, out of it, gone for good, archived or not, moved. */
export const bulkItems = (
  what: 'trash' | 'restore' | 'delete' | 'archive' | 'unarchive',
  ids: string[],
) => {
  const path = {
    trash: ['/api/ciphers/delete', 'PUT'],
    restore: ['/api/ciphers/restore', 'PUT'],
    delete: ['/api/ciphers', 'DELETE'],
    archive: ['/api/ciphers/archive', 'PUT'],
    unarchive: ['/api/ciphers/unarchive', 'PUT'],
  }[what];
  return changed(request(path[0]!, { method: path[1], body: { ids } })).then(() => undefined);
};

export const moveItems = (ids: string[], folderId: string | null) =>
  changed(request('/api/ciphers/move', { method: 'PUT', body: { ids, folderId } })).then(
    () => undefined,
  );

export const saveFolder = async (id: string | null, folderName: string): Promise<string> => {
  const encrypted = await call((core) => core.encryptText(folderName.trim()));
  const folder = await changed(
    id
      ? request<{ id: string }>(`/api/folders/${encodeURIComponent(id)}`, {
          method: 'PUT',
          body: { name: encrypted },
        })
      : request<{ id: string }>('/api/folders', { body: { name: encrypted } }),
  );
  return folder.id;
};

export const deleteFolder = (id: string) =>
  changed(request(`/api/folders/${encodeURIComponent(id)}`, { method: 'DELETE' })).then(
    () => undefined,
  );

export const openItemUri = async (id: string, index: number) => {
  const uri = await revealField(id, `uri:${index}`);
  if (/^https?:\/\//i.test(uri)) window.open(uri, '_blank', 'noopener,noreferrer');
};

export const openWebVault = async () => undefined;

// ── What only the desktop app has ─────────────────────────

export const setUpdateChannel = async (_channel: 'stable' | 'beta') => undefined;
export const updateStatus = async (): Promise<UpdateInfo | null> => null;
export const checkForUpdates = async (): Promise<UpdateInfo | null> => null;
export const installUpdate = async () => undefined;

const PAGES: Record<ProjectPage, string> = {
  source: 'https://github.com/MinifyX/UwULock-Server',
  releases: 'https://github.com/MinifyX/UwULock-Server/releases',
  issues: 'https://github.com/MinifyX/UwULock-Server/issues',
  license: 'https://github.com/MinifyX/UwULock-Server/blob/main/LICENSE',
  suite: 'https://github.com/MinifyX',
};

export const openProjectPage = async (page: ProjectPage) => {
  window.open(PAGES[page], '_blank', 'noopener,noreferrer');
};
