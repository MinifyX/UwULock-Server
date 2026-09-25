/** The admin portal's API (`/uwu/v1/admin`): what the server says, typed. */

import { download, request } from './web/http';

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

export type Settings = {
  smtp: Smtp | null;
  defaultLanguage: 'de' | 'en';
  invitationDays: number;
  newDeviceMail: boolean;
  passwordHints: boolean;
  rememberTwoFactor: boolean;
  mailEnabled?: boolean;
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
export const saveSettings = (next: Settings) =>
  request<Settings>(`${base}/settings`, { method: 'PUT', body: next });
export const testMail = (to: string) => request(`${base}/settings/test-mail`, { body: { to } });
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
export const downloadBackup = (name: string) =>
  download(`${base}/backups/${encodeURIComponent(name)}`);
