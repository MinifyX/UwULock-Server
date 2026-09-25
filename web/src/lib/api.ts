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
};

export type LoginStep =
  | { step: 'done'; status: Status }
  | { step: 'two-factor'; methods: TwoFactorMethod[]; message: string | null }
  | { step: 'new-device' };

export type ItemKind = 'login' | 'note' | 'card' | 'identity' | 'ssh-key';

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
  '7': ['webauthn', false],
};

async function token(extra: Record<string, string>): Promise<LoginStep> {
  const p = pending!;
  const device = deviceType();
  const form = new URLSearchParams({
    grant_type: 'password',
    username: p.email,
    password: p.hash,
    scope: 'api offline_access',
    client_id: 'web',
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
        Record<string, { Email?: string } | null> | undefined;
      if (providers) {
        p.methods = Object.entries(providers).map(([provider, details]) => {
          const [kind, supported] = TWO_FACTOR_KINDS[provider] ?? ['other', false];
          return {
            provider: Number(provider),
            kind,
            supported,
            hint: details?.Email ?? null,
          };
        });
        const message = extra.twoFactorToken ? error.message : null;
        return { step: 'two-factor', methods: p.methods, message };
      }
    }
    throw failure(error);
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

export const loginTwoFactor = (provider: number, code: string, remember: boolean) =>
  token({
    twoFactorProvider: String(provider),
    twoFactorToken: code.trim().replace(/\s/g, ''),
    twoFactorRemember: remember ? '1' : '0',
  });

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
  setSession(null);
  clearDue = toClear !== null;
  void clearClipboard();
  await call((core) => core.lock());
  unlocked = false;
  name = null;
  profile = null;
  return announce();
};

export const switchAccount = async (_id: string) => status();
export const renameAccount = async (_id: string, _label: string) => status();

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
  void call((core) => core.lock()).finally(() => {
    unlocked = false;
    name = null;
    profile = null;
    void announce();
  });
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
