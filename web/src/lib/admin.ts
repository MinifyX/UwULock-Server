/** The admin portal's API (`/uwu/v1/admin`): what the server says, typed. */

import type { Branding } from './account';
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
  /** Where the addresses of failed logins are, from DB-IP's databases on the server. */
  geoip: boolean;
  /** The other breach sources of the password check (§15); missing before 0.7. */
  breaches?: {
    xonPasswords: boolean;
    siteBreaches: boolean;
    emailCheck: boolean;
    changePassword: boolean;
  };
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
  /** Whether file requests are there at all is a feature switch (`lib/switches.ts`). */
  fileRequests: { perUser: number; maxDays: number; maxFiles: number };
  /** How much an account may keep in files; null: no limit. */
  storagePerUserMb: number | null;
  /** Earlier states of items: how many per item (0: none), how many days (0: no limit). */
  versions: { perItem: number; days: number };
  /** Websites' icons fetched by the server, and the icon library. */
  icons: {
    automatic: boolean;
    library: boolean;
    sources: string[];
    /** The icon databases that come with the server and are used (docs/icons.md). */
    databases: string[];
  };
  /** Families (§16.4): who may make one, its size, how many one account may own. */
  families: OrgRules;
  /** The suite vault of UwUSSH and UwURDP (§6): what one account may keep. On or off is a
   * feature switch. */
  suite: { maxRecords: number; maxMb: number };
  /** The UwUMail servers accounts may connect for masked addresses (§21.8). */
  masked?: { servers: { url: string; name: string }[] };
};

export type OrgRules = {
  whoMayCreate: 'everyone' | 'admins' | 'nobody';
  maxMembers: number;
  perUser: number;
};

/** A family (or organisation) as the portal lists it: no vault content, only who is in it. */
export type AdminOrganization = {
  id: string;
  name: string;
  kind: 'family' | 'organization';
  members: number;
  owners: string[];
  creationDate: string;
};

/** What the server keeps of icons. */
export type IconStatus = {
  cached: number;
  cacheBytes: number;
  /** The ceiling of the cache: past it, the oldest icons go. */
  cacheMaxBytes: number;
  cacheMaxFiles: number;
  ownBytes: number;
  libraryUpdated: string | null;
  libraryIcons: number;
  /** The icon databases in the server's binary: who made them, their licence, what they hold. */
  databases?: IconDatabase[];
};

export type IconDatabase = {
  id: string;
  name: string;
  url: string;
  license: string;
  licenseUrl: string;
  attribution: string;
  repository: string;
  commit: string;
  on: boolean;
  icons: number;
  domains: number;
  names: number;
  bytes: number;
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

/** Where an address is, from the GeoIP databases on the server. */
export type Place = {
  country?: string;
  countryName?: string;
  region?: string;
  city?: string;
  asn?: number;
  network?: string;
};

/** Where an address is, in one line: "Berlin, Deutschland · Example Net (AS64496)". */
export function placeText(place: Place | null | undefined): string | null {
  if (!place) return null;
  const where = [place.city, place.countryName ?? place.country].filter(Boolean).join(', ');
  const network = place.network
    ? `${place.network}${place.asn ? ` (AS${place.asn})` : ''}`
    : place.asn
      ? `AS${place.asn}`
      : '';
  return [where, network].filter(Boolean).join(' · ') || null;
}

export type FailedReason = 'password' | 'unknown-account' | 'disabled' | 'api-key' | 'two-factor';

/** One login attempt: refused, or (in an address's history) one that worked. */
export type LoginAttempt = {
  id: number;
  time: string;
  kind: string;
  reason: FailedReason | null;
  /** The address that was typed. */
  email: string | null;
  /** The account it was for, while it is there; null: no such account. */
  account: { id: string; email: string } | null;
  ip: string | null;
  place: Place | null;
  deviceType: string | null;
  deviceName: string | null;
  userAgent: string | null;
  clientName: string | null;
  clientVersion: string | null;
  detail: string | null;
};

export type LoginFilter = {
  hours: number | null;
  user: string;
  ip: string;
  reason: FailedReason | '';
  /** The logins that worked too. */
  all?: boolean;
};

export type IpGroup = {
  ip: string;
  attempts: number;
  first: string;
  last: string;
  targets: number;
  unknown: number;
  emails: string[];
  logins: number;
  place: Place | null;
  blocked: boolean;
};

export type IpBlock = {
  id: number;
  network: string;
  reason: string;
  created: string;
  expires: string | null;
  createdBy: string | null;
  place: Place | null;
};

export type GeoIpStatus = {
  enabled: boolean;
  ready: boolean;
  month: string | null;
  cityBytes: number;
  asnBytes: number;
  attempted: string | null;
  error: string | null;
  updating: boolean;
  source: {
    name: string;
    url: string;
    license: string;
    licenseUrl: string;
    attribution: string;
  };
};

export type LogLine = { seq: number; time: string; level: string; target: string; message: string };

export type Backup = { name: string; bytes: number; time: string | null };

export type UserAction =
  'disable' | 'enable' | 'make-admin' | 'remove-admin' | 'log-out' | 'reset-two-factor';

const base = '/uwu/v1/admin';

// ── Branding ──────────────────────────────────────────────

export type BrandingAdmin = Branding & {
  nameSet: boolean;
  colorSet: boolean;
  contrast: { light: number; dark: number; ok: boolean } | null;
};

export type BrandingPreview = {
  light: Record<string, string>;
  dark: Record<string, string>;
  contrast: { light: number; dark: number; ok: boolean };
};

export type BrandingImage = 'logo/light' | 'logo/dark' | 'favicon';

/** Where a branding lives: the server's own, or one send domain's (§14.4). */
export const SERVER_BRANDING = `${base}/branding`;
export const domainBranding = (domainId: string) =>
  `${base}/send-domains/${encodeURIComponent(domainId)}/branding`;

export const branding = (path = SERVER_BRANDING) => request<BrandingAdmin>(path);
export const saveBranding = (name: string | null, color: string | null, path = SERVER_BRANDING) =>
  request<BrandingAdmin>(path, { method: 'PUT', body: { name, color } });
export const brandingPreview = (color: string, path = SERVER_BRANDING) =>
  request<BrandingPreview>(`${path}/preview?color=${encodeURIComponent(color)}`);
export const uploadBrandingImage = (image: BrandingImage, file: Blob, path = SERVER_BRANDING) =>
  request<BrandingAdmin>(`${path}/${image}`, { method: 'PUT', raw: file });
export const removeBrandingImage = (image: BrandingImage, path = SERVER_BRANDING) =>
  request<BrandingAdmin>(`${path}/${image}`, { method: 'DELETE' });
/** A send domain back to the server's look. */
export const resetDomainBranding = (domainId: string) =>
  request(domainBranding(domainId), { method: 'DELETE' });

// ── Send domains (§14.1) ──────────────────────────────────

export type SendDomainTls = 'acme' | 'proxy';

export type AdminSendDomain = {
  id: string;
  host: string;
  tls: SendDomainTls;
  certificate: {
    status: 'ok' | 'pending' | 'failed' | 'proxy';
    expires: string | null;
    error: string | null;
  };
  /** Its own look, or null for the server's. */
  branding: Branding | null;
  creationDate: string;
};

export type SendDomainCheck = {
  dns: { ok: boolean; addresses: string[] };
  https: { ok: boolean; error: string | null };
  routing: { ok: boolean };
};

const domains = `${base}/send-domains`;

export const sendDomains = async () => {
  const answer = await request<AdminSendDomain[] | { data: AdminSendDomain[] }>(domains);
  return Array.isArray(answer) ? answer : answer.data;
};
export const addSendDomain = (host: string, tls: SendDomainTls) =>
  request<AdminSendDomain>(domains, { body: { host, tls } });
export const setSendDomainTls = (id: string, tls: SendDomainTls) =>
  request<AdminSendDomain>(`${domains}/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: { tls },
  });
export const deleteSendDomain = (id: string) =>
  request(`${domains}/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const checkSendDomain = (id: string) =>
  request<SendDomainCheck>(`${domains}/${encodeURIComponent(id)}/check`, { body: {} });

// ── Allowed UwUMail servers (§21.8) ───────────────────────

export type MaskedServerCheck = {
  discovery: boolean;
  maskedScope: boolean;
  registration: boolean;
  error: string | null;
};

export const checkMaskedServer = (url: string) =>
  request<MaskedServerCheck>(`${base}/masked/check`, { body: { url } });

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
function loginQuery(filter: LoginFilter): URLSearchParams {
  const query = new URLSearchParams();
  if (filter.hours) query.set('hours', String(filter.hours));
  if (filter.user.trim()) query.set('user', filter.user.trim());
  if (filter.ip.trim()) query.set('ip', filter.ip.trim());
  if (filter.reason) query.set('reason', filter.reason);
  if (filter.all) query.set('all', 'true');
  return query;
}
export const failedLogins = (filter: LoginFilter, before: number | null) => {
  const query = loginQuery(filter);
  query.set('limit', '100');
  if (before) query.set('before', String(before));
  return request<{ attempts: LoginAttempt[]; more: boolean; geoip: boolean }>(
    `${base}/failed-logins?${query}`,
  );
};
export const failedByIp = (filter: LoginFilter) =>
  request<{ groups: IpGroup[] }>(`${base}/failed-logins/by-ip?${loginQuery(filter)}`);
export const ipBlocks = () =>
  request<{ blocks: IpBlock[]; yourAddress: string }>(`${base}/ip-blocks`);
export const blockIp = (network: string, reason: string, hours: number | null) =>
  request<IpBlock>(`${base}/ip-blocks`, { body: { network, reason, hours } });
export const unblockIp = (id: number) => request(`${base}/ip-blocks/${id}`, { method: 'DELETE' });
export const geoipStatus = () => request<GeoIpStatus>(`${base}/geoip`);
export const updateGeoip = () => request(`${base}/geoip/update`, { body: {} });
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

export const organizations = () => request<AdminOrganization[]>(`${base}/organizations`);

/** Delete a family and everything in it, for the admin's master password. */
export async function deleteOrganization(id: string, password: string) {
  const masterPasswordHash = await passwordHash(password);
  await request(`${base}/organizations/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    body: { masterPasswordHash },
  });
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
 * back within five seconds. A browser cannot set headers on one, so a one-time ticket goes in the
 * query, never the access token (which a proxy's log would keep).
 */
export async function checkWebSocket(): Promise<SocketResult> {
  let ticket: string;
  try {
    ticket = (await request<{ ticket: string }>(`${base}/diagnosis/websocket-ticket`, { body: {} }))
      .ticket;
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${scheme}://${location.host}${base}/diagnosis/websocket?ticket=${encodeURIComponent(ticket)}`;
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
  /** Settings from before that send backups unencrypted over SFTP or S3: they do not run. */
  encryptionRequired?: boolean;
  /** Only in the answer to the first save that encrypts: shown once. */
  recoveryKey?: string | null;
};

/** What the portal sends: the target with the secrets typed (empty keeps the stored ones). */
export type OffsiteDraft = Omit<
  Offsite,
  'status' | 'running' | 'stale' | 'recoveryKey' | 'target' | 'encryptionRequired'
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
/**
 * The settings decide where the whole database goes, so saving them asks for the master
 * password. `forgetKey` says out loud that encryption goes off and the recovery key with it.
 */
export async function saveOffsite(draft: OffsiteDraft, password: string, forgetKey = false) {
  const masterPasswordHash = await passwordHash(password);
  return request<Offsite>(offsiteBase, {
    method: 'PUT',
    body: { ...draft, masterPasswordHash, forgetKey },
  });
}
/** Without a confirmed SFTP host key the server only reads the key (`confirmed: false`); tested
 * again with that `hostKey`, it trusts it. */
export const testOffsite = (hostKey?: string) =>
  request<{ kind: OffsiteKind; hostKey: string | null; known: boolean; confirmed?: boolean }>(
    `${offsiteBase}/test`,
    { body: hostKey ? { hostKey } : {} },
  );
export async function forgetHostKey(password: string) {
  const masterPasswordHash = await passwordHash(password);
  return request<Offsite>(`${offsiteBase}/forget-host-key`, { body: { masterPasswordHash } });
}
export const runOffsite = () => request(`${offsiteBase}/run`, { body: {} });
/** The snapshots, and whether the last one this server wrote is missing from them. */
export const snapshots = async () =>
  request<{ data: Snapshot[]; lastWrittenMissing?: boolean }>(`${offsiteBase}/snapshots`);

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
