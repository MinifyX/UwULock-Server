/** The admin portal's API (`/uwu/v1/admin`): what the server says, typed. */

import { prelogin } from './api';
import { N_, t } from './i18n';
import { call } from './web/core';
import { ApiError, currentSession, download, freshToken, request } from './web/http';

/** What the server is warning about right now (§21.3); the same kinds the channels can send. */
export type AlertKind =
  | 'backupFailed'
  | 'backupStale'
  | 'certificateExpiring'
  | 'updateAvailable'
  | 'manyFailedLogins'
  | 'diskLow'
  | 'pushRelayFailing'
  | 'mailFailing';

/** The names of the alerts, for the overview and the channels' check boxes. */
export const ALERT_TITLES: Record<string, string> = {
  backupFailed: N_('Backup fehlgeschlagen'),
  backupStale: N_('Backup zu alt'),
  certificateExpiring: N_('Zertifikat läuft bald ab'),
  updateAvailable: N_('Update verfügbar'),
  manyFailedLogins: N_('Viele fehlgeschlagene Anmeldungen'),
  diskLow: N_('Wenig Speicherplatz'),
  pushRelayFailing: N_('Push-Relay geht nicht'),
  mailFailing: N_('Mailversand geht nicht'),
};

export const alertTitle = (kind: string) => (ALERT_TITLES[kind] ? t(ALERT_TITLES[kind]) : kind);

export type Alert = {
  kind: AlertKind | string;
  severity: 'info' | 'warning' | 'error';
  since: string;
  /** Already in the admin's language. */
  detail: string;
};

export type LokiStatus = {
  enabled: boolean;
  queued: number;
  sent: number;
  dropped: number;
  lastSuccess: string | null;
  error: string | null;
};

export type Overview = {
  version: string;
  uptimeSeconds: number;
  users: number;
  admins: number;
  disabled: number;
  invitations: number;
  devices: number;
  ciphers: number;
  trashed: number;
  folders: number;
  twoFactor: number;
  failedLoginsDay: number;
  databaseBytes: number;
  backups: number;
  backupBytes: number;
  lastBackup: string | null;
  mail: boolean;
  webVault: boolean;
  update: {
    checked: string | null;
    newer: string | null;
    url: string | null;
    commits: number | null;
    error: string | null;
    channel: string | null;
    commit: string | null;
  };
  alerts: Alert[];
  failingChannels: { id: string; name: string; kind: ChannelKind; error: string }[];
  storage: { databaseBytes: number; filesBytes: { attachments: number; sends: number } };
  loki: LokiStatus;
  /** The last diagnosis in short; none before the first. */
  diagnosis: { date: string; errors: number; warnings: number } | null;
};

export type User = {
  id: string;
  email: string;
  name: string | null;
  admin: boolean;
  disabled: boolean;
  language: string;
  created: string;
  lastLogin: string | null;
  revision: string;
  devices: number;
  ciphers: number;
  twoFactor: boolean;
  kdf: string;
  /** Attachments and the files of Sends. */
  storageBytes: number;
};

export type UserDevice = {
  id: string;
  name: string;
  type: number;
  typeName: string;
  created: string;
  lastSeen: string;
  lastIp: string | null;
  loggedIn: boolean;
};

export type Invitation = {
  email: string;
  admin: boolean;
  invitedBy: string | null;
  language: string;
  created: string;
  expires: string;
  expired: boolean;
};

export type Smtp = {
  host: string;
  port: number;
  security: 'tls' | 'starttls' | 'none';
  username: string | null;
  password?: string | null;
  passwordSet?: boolean;
  from: string;
  fromName: string | null;
};

export type Push = {
  installationId: string;
  /** Only sent, never shown: `installationKeySet` says whether there is one. */
  installationKey?: string;
  installationKeySet?: boolean;
  region: 'us' | 'eu';
};

/** Server-wide rules for every account (§20). */
export type Policies = {
  requireTwoFactor: {
    enabled: boolean;
    /** RFC 3339, UTC; none: at once. */ deadline: string | null;
  };
  minimumKdf: {
    pbkdf2Iterations: number;
    /** MiB. */
    argon2Memory: number;
    argon2Iterations: number;
    argon2Parallelism: number;
  };
  /** `minComplexity` is a zxcvbn score, 0 to 4; 0 asks for nothing. */
  masterPassword: { minLength: number; minComplexity: number; enforceOnLogin: boolean };
};

export type Metrics = {
  enabled: boolean;
  tokenSet?: boolean;
  /** Only sent: left out keeps the stored one, "" removes it. */
  token?: string | null;
  /** An address of its own, like 127.0.0.1:9100, served without a token. */
  listen: string | null;
};

export type Loki = {
  enabled: boolean;
  url: string;
  tenant: string | null;
  username: string | null;
  /** Only sent: left out (or empty) keeps the stored one for the same Loki and user. */
  password?: string | null;
  passwordSet?: boolean;
  labels: Record<string, string>;
};

export type Settings = {
  smtp: Smtp | null;
  defaultLanguage: 'de' | 'en';
  invitationDays: number;
  newDeviceMail: boolean;
  passwordHints: boolean;
  rememberTwoFactor: boolean;
  maxFileMb: number;
  hibp: boolean;
  push: Push | null;
  usersMayInvite: boolean;
  invitationsPerUser: number;
  mailEnabled?: boolean;
  /** Kinds of security notices that are only listed, not mailed. */
  securityNotices: { mailOff: string[] };
  policies: Policies;
  /** CIDRs the portal answers to; none: everywhere. */
  adminNetworks: string[];
  metrics: Metrics;
  loki: Loki;
  fileRequests: { enabled: boolean; perUser: number; maxDays: number; maxFiles: number };
  /** How much an account may keep in files; null: no limit. */
  storagePerUserMb: number | null;
  /** Earlier states of items: how many per item (0: none), how many days (0: no limit). */
  versions: { perItem: number; days: number };
  /** Websites' icons fetched by the server, and the icon library. */
  icons: { automatic: boolean; library: boolean; sources: string[] };
};

/** What the server keeps of icons. */
export type IconStatus = {
  cached: number;
  cacheBytes: number;
  ownBytes: number;
  libraryUpdated: string | null;
  libraryIcons: number;
};

/** One day of the numbers over time. */
export type Day = {
  day: string;
  users: number;
  devices: number;
  ciphers: number;
  sends: number;
  fileBytes: number;
  logins: number;
  failedLogins: number;
};

export type Event = {
  id: number;
  time: string;
  kind: string;
  userId: string | null;
  email: string | null;
  ip: string | null;
  deviceType: string | null;
  detail: string | null;
};

export type LogLine = { seq: number; time: string; level: string; target: string; message: string };

export type Backup = { name: string; bytes: number; time: string | null };

export type UserAction =
  'disable' | 'enable' | 'make-admin' | 'remove-admin' | 'log-out' | 'reset-two-factor';

const base = '/uwu/v1/admin';

export const overview = () => request<Overview>(`${base}/overview`);
export const users = () => request<User[]>(`${base}/users`);
export const userAction = (id: string, action: UserAction) =>
  request<User>(`${base}/users/${encodeURIComponent(id)}/${action}`, {
    method: 'POST',
    body: {},
  });
export const deleteUser = (id: string) =>
  request(`${base}/users/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const userDevices = (id: string) =>
  request<UserDevice[]>(`${base}/users/${encodeURIComponent(id)}/devices`);
export const deleteUserDevice = (id: string, device: string) =>
  request(`${base}/users/${encodeURIComponent(id)}/devices/${encodeURIComponent(device)}`, {
    method: 'DELETE',
  });
export const invitations = () => request<Invitation[]>(`${base}/invitations`);
export const invite = (email: string, admin: boolean) =>
  request<{ email: string; link: string; mailed: boolean; expires: string }>(
    `${base}/invitations`,
    {
      body: { email, admin },
    },
  );
export const uninvite = (email: string) =>
  request(`${base}/invitations/${encodeURIComponent(email)}`, { method: 'DELETE' });
export const settings = () => request<Settings>(`${base}/settings`);
export const iconStatus = () => request<IconStatus>(`${base}/icons`);
export const clearIconCache = () => request(`${base}/icons/cache`, { method: 'DELETE' });
export const refreshIconLibrary = () => request(`${base}/icons/library/refresh`, { body: {} });
export const saveSettings = (next: Settings) =>
  request<Settings>(`${base}/settings`, { method: 'PUT', body: next });
export const testMail = (to: string) => request(`${base}/settings/test-mail`, { body: { to } });
export const testPush = () => request(`${base}/settings/test-push`, { body: {} });
export const testLoki = (loki: Loki) => request(`${base}/settings/test-loki`, { body: loki });
export const stats = (days: number) => request<Day[]>(`${base}/stats?days=${days}`);
export const events = (kind: string | null, before: number | null) => {
  const query = new URLSearchParams({ limit: '100' });
  if (kind) query.set('kind', kind);
  if (before) query.set('before', String(before));
  return request<Event[]>(`${base}/events?${query}`);
};
export const logs = (after: number, level: string) =>
  request<LogLine[]>(`${base}/logs?after=${after}&level=${encodeURIComponent(level)}&limit=1000`);
export const backups = () => request<Backup[]>(`${base}/backups`);
export const createBackup = () => request<Backup>(`${base}/backups`, { method: 'POST', body: {} });
/**
 * A backup, for the master password. The portal keeps no vault open, so the hash is derived
 * here from the password and the account's key derivation, and the master key it takes is
 * wiped again right after.
 */
async function passwordHash(password: string): Promise<string> {
  const email = currentSession()?.email;
  if (!email) throw new ApiError(401, 'The session has ended. Log in again.', null);
  const kdf = await prelogin(email);
  try {
    return await call((core) => core.deriveLogin(email, password, kdf));
  } finally {
    await call((core) => core.lock());
  }
}

export async function downloadBackup(name: string, password: string): Promise<Blob> {
  const masterPasswordHash = await passwordHash(password);
  return download(`${base}/backups/${encodeURIComponent(name)}`, { masterPasswordHash });
}

/** Put a backup back while the server runs; what was there becomes a backup of its own. */
export async function restoreBackup(name: string, password: string) {
  const masterPasswordHash = await passwordHash(password);
  return request<{ restored: string; before: string }>(
    `${base}/backups/${encodeURIComponent(name)}/restore`,
    { body: { masterPasswordHash } },
  );
}

// ── Settings helpers ──────────────────────────────────────

const TOKEN_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** A random token from the browser's own random numbers: for the metrics, shown once. */
export function randomToken(length = 32): string {
  let out = '';
  const bytes = new Uint8Array(length * 2);
  while (out.length < length) {
    crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      // 248 is the largest multiple of 62 below 256: no letter comes up more often than another.
      if (byte < 248 && out.length < length) out += TOKEN_ALPHABET[byte % 62];
    }
  }
  return out;
}

/** Loki's labels as `name=value` lines, the way the settings edit them. */
export function labelsText(labels: Record<string, string>): string {
  return Object.entries(labels)
    .map(([name, value]) => `${name}=${value}`)
    .join('\n');
}

/**
 * `name=value` lines back into labels. Names are Prometheus label names; `bad` holds the lines
 * that are not a label, to show.
 */
export function parseLabels(text: string): { labels: Record<string, string>; bad: string[] } {
  const labels: Record<string, string> = {};
  const bad: string[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const at = line.indexOf('=');
    const name = at < 0 ? '' : line.slice(0, at).trim();
    const value = at < 0 ? '' : line.slice(at + 1).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || !value) bad.push(line);
    else labels[name] = value;
  }
  return { labels, bad };
}

/** A local `datetime-local` value from a UTC date of the server, and back. */
export function localInput(iso: string | null): string {
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function fromLocalInput(value: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// ── Notification channels ─────────────────────────────────

export type ChannelKind = 'mail' | 'ntfy' | 'gotify' | 'matrix';

/** A channel's settings as the server shows them: secrets only as `…Set`. */
export type ChannelConfig = {
  url?: string;
  topic?: string;
  priority?: number;
  tokenSet?: boolean;
  homeserver?: string;
  roomId?: string;
  accessTokenSet?: boolean;
};

export type Channel = {
  id: string;
  kind: ChannelKind;
  name: string;
  enabled: boolean;
  events: string[];
  config: ChannelConfig;
  status: {
    lastSuccess: string | null;
    lastError: string | null;
    lastErrorDate: string | null;
    queued: number;
  };
};

/** What is saved: the secrets as `token` (ntfy, Gotify) or `accessToken` (Matrix). */
export type ChannelDraft = {
  kind: ChannelKind;
  name: string;
  enabled: boolean;
  events: string[];
  config: {
    url?: string;
    topic?: string;
    priority?: number;
    token?: string;
    homeserver?: string;
    roomId?: string;
    accessToken?: string;
  };
};

export const notifications = () =>
  request<{ channels: Channel[]; events: string[] }>(`${base}/notifications`);
export const addChannel = (draft: ChannelDraft) =>
  request<Channel>(`${base}/notifications`, { body: draft });
export const saveChannel = (id: string, draft: ChannelDraft) =>
  request<Channel>(`${base}/notifications/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: draft,
  });
export const deleteChannel = (id: string) =>
  request(`${base}/notifications/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const testChannel = (id: string) =>
  request(`${base}/notifications/${encodeURIComponent(id)}/test`, { body: {} });

// ── Diagnosis ─────────────────────────────────────────────

export type CheckStatus = 'ok' | 'warning' | 'error' | 'skipped';

export type Check = {
  id: string;
  status: CheckStatus;
  /** The texts come in the admin's language. */
  summary: string;
  detail: string | null;
  fix: { text: string; caddy: string | null; nginx: string | null } | null;
};

export type Diagnosis = { date: string | null; version: string; checks: Check[] };

export type SocketResult = { ok: boolean; error: string | null };
export type UploadResult = { ok: boolean; status: number | null; bytes: number };

export const diagnosis = () => request<Diagnosis>(`${base}/diagnosis`);
export const runDiagnosis = () => request<Diagnosis>(`${base}/diagnosis`, { body: {} });
export const clientDiagnosis = (results: { websocket?: SocketResult; upload?: UploadResult }) =>
  request<Diagnosis>(`${base}/diagnosis/client`, { body: results });

/**
 * Whether a WebSocket gets through to this server: one opens, sends "ping", and has to get it
 * back within five seconds. The token goes in the query — a browser cannot set headers on one.
 */
export async function checkWebSocket(): Promise<SocketResult> {
  const token = (await freshToken()) ?? '';
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${scheme}://${location.host}${base}/diagnosis/websocket?access_token=${encodeURIComponent(token)}`;
  return new Promise((resolve) => {
    let socket: WebSocket | null = null;
    let done = false;
    const finish = (error: string | null) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        socket?.close();
      } catch {
        // Closing one that never opened: nothing to do.
      }
      resolve({ ok: error === null, error });
    };
    const timer = setTimeout(() => finish(t('Keine Antwort innerhalb von 5 Sekunden.')), 5000);
    try {
      socket = new WebSocket(url);
    } catch (e) {
      finish(String(e));
      return;
    }
    socket.onopen = () => socket?.send('ping');
    socket.onmessage = (event) =>
      finish(event.data === 'ping' ? null : t('Es kam etwas anderes zurück als gesendet.'));
    socket.onerror = () => finish(t('Die Verbindung kam nicht zustande.'));
    socket.onclose = (event) =>
      finish(t('Die Verbindung wurde geschlossen (Code {code}).', { code: event.code }));
  });
}

const MIB = 1024 * 1024;
let sixteen: Blob | null = null;

/** `mib` MiB of zeros, made of one MiB used again and again. */
function zeros(mib: number): Blob {
  const chunk = new Uint8Array(MIB);
  return new Blob(
    Array.from({ length: mib }, () => chunk),
    { type: 'application/octet-stream' },
  );
}

/**
 * Whether an upload of `mib` MiB gets through: the server counts and drops it. A proxy in front
 * may answer 413, or just cut the connection.
 */
export async function checkUpload(mib = 16): Promise<UploadResult> {
  const body = mib === 16 ? (sixteen ??= zeros(16)) : zeros(mib);
  const token = (await freshToken()) ?? '';
  try {
    const response = await fetch(`${base}/diagnosis/upload`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream' },
      body,
    });
    return { ok: response.ok, status: response.status, bytes: body.size };
  } catch {
    return { ok: false, status: null, bytes: body.size };
  }
}

// ── Off-site backups (§21.2) ──────────────────────────────

export type OffsiteKind = 'sftp' | 's3' | 'folder';

export type OffsiteTarget = {
  kind: OffsiteKind;
  host?: string;
  port?: number;
  user?: string;
  path?: string;
  method?: 'key' | 'password';
  publicKey?: string | null;
  passwordSet?: boolean;
  hostKey?: string | null;
  endpoint?: string;
  region?: string;
  bucket?: string;
  prefix?: string;
  accessKey?: string;
  secretKeySet?: boolean;
  pathStyle?: boolean;
};

export type Retention = { days: number; weeks: number; months: number };

export type Offsite = {
  enabled: boolean;
  hour: number;
  minute: number;
  retention: Retention;
  encrypted: boolean;
  warnAfterHours: number;
  target: OffsiteTarget | null;
  status: {
    lastSuccess: string | null;
    lastAttempt: string | null;
    lastError: string | null;
    lastDuration: number | null;
    bytes: number | null;
    uploaded: number | null;
  };
  running: boolean;
  stale: boolean;
  /** Only in the answer to the first save that encrypts: shown once. */
  recoveryKey?: string | null;
};

/** What the portal sends: the target with the secrets typed (empty keeps the stored ones). */
export type OffsiteDraft = Omit<
  Offsite,
  'status' | 'running' | 'stale' | 'recoveryKey' | 'target'
> & {
  target: (OffsiteTarget & { password?: string; secretKey?: string }) | null;
};

export type Snapshot = {
  id: string;
  date: string;
  bytes: number;
  version: string;
  hostname: string;
  uploaded: number;
};

const offsiteBase = `${base}/backups/offsite`;

export const offsite = () => request<Offsite>(offsiteBase);
export const saveOffsite = (draft: OffsiteDraft) =>
  request<Offsite>(offsiteBase, { method: 'PUT', body: draft });
export const testOffsite = () =>
  request<{ kind: OffsiteKind; hostKey: string | null; known: boolean }>(`${offsiteBase}/test`, {
    body: {},
  });
export const forgetHostKey = () => request<Offsite>(`${offsiteBase}/forget-host-key`, { body: {} });
export const runOffsite = () => request(`${offsiteBase}/run`, { body: {} });
export const snapshots = async () =>
  (await request<{ data: Snapshot[] }>(`${offsiteBase}/snapshots`)).data;

export async function restoreSnapshot(snapshot: string, password: string) {
  const masterPasswordHash = await passwordHash(password);
  return request<{ restored: string; before: string; files: number }>(`${offsiteBase}/restore`, {
    body: { snapshot, masterPasswordHash },
  });
}

export async function recoveryKey(password: string): Promise<string> {
  const masterPasswordHash = await passwordHash(password);
  const answer = await request<{ recoveryKey: string }>(`${offsiteBase}/recovery-key`, {
    body: { masterPasswordHash },
  });
  return answer.recoveryKey;
}
