/**
 * Feature switches (docs/features.md): the extras an admin turns on or off. The server lists
 * them under `switches` in `/uwu/v1/info` — each one `true` when it works — and leaves those
 * that are off out of `features`. What is off, the web vault and the admin portal hide; a link
 * that leads to one shows that this server does not offer it.
 */

import { useServerInfo } from './branding';
import { N_ } from './i18n';
import { request } from './web/http';

export type SwitchId =
  | 'families'
  | 'file-requests'
  | 'send-domains'
  | 'masked-addresses'
  | 'versions'
  | 'reminders'
  | 'travel-mode'
  | 'emergency-sheet'
  | 'own-icons'
  | 'icon-library'
  | 'twofa-directory'
  | 'sso'
  | 'scim'
  | 'offsite-backups'
  | 'admin-notifications'
  | 'suite';

export type SwitchGroup = 'sharing' | 'vault' | 'sign-in' | 'operations' | 'apps';

/** The groups, in the order the admin portal lists them. */
export const SWITCH_GROUPS: { id: SwitchGroup; label: string }[] = [
  { id: 'sharing', label: N_('Teilen') },
  { id: 'vault', label: N_('Im Tresor') },
  { id: 'sign-in', label: N_('Anmeldung') },
  { id: 'operations', label: N_('Betrieb') },
  { id: 'apps', label: N_('UwU-Apps') },
];

/** What each switch is called, and what it does in one line anybody understands. */
export const SWITCH_TEXTS: Record<SwitchId, { label: string; description: string }> = {
  families: {
    label: N_('Familien'),
    description: N_(
      'Einträge in einer Familie teilen, mit Sammlungen und Rechten. Organisationen aus Vaultwarden brauchen das auch.',
    ),
  },
  'file-requests': {
    label: N_('Datei-Anfragen'),
    description: N_(
      'Ein Link, über den jemand ohne Konto Dateien verschlüsselt zu dir hochlädt – etwa Ausweis-Scans.',
    ),
  },
  'send-domains': {
    label: N_('Eigene Send-Domains'),
    description: N_(
      'Sends und Datei-Anfragen unter einer eigenen, kurzen Adresse wie send.example.com.',
    ),
  },
  'masked-addresses': {
    label: N_('Maskierte Adressen'),
    description: N_(
      'Wegwerf-Adressen von UwUMail direkt im Tresor anlegen, auch aus den Bitwarden-Apps.',
    ),
  },
  versions: {
    label: N_('Versionen von Einträgen'),
    description: N_('Der Server hebt frühere Stände eines Eintrags auf; man kann sie zurückholen.'),
  },
  reminders: {
    label: N_('Erinnerungen'),
    description: N_(
      'Eine Mail, wenn es Zeit ist, ein Passwort zu erneuern – nur wenn man sie will.',
    ),
  },
  'travel-mode': {
    label: N_('Reisemodus'),
    description: N_('Ordner auf Reisen von allen Geräten ausblenden, etwa an einer Grenze.'),
  },
  'emergency-sheet': {
    label: N_('Notfallblatt'),
    description: N_('Ein PDF zum Ausdrucken für Angehörige, im Browser erzeugt.'),
  },
  'own-icons': {
    label: N_('Eigene Icons'),
    description: N_('Eigene Bilder als Icon für Einträge, verschlüsselt gespeichert.'),
  },
  'icon-library': {
    label: N_('Icon-Bibliothek'),
    description: N_(
      'Fertige Icons für selbst gehostete Dienste zum Aussuchen. Braucht „Eigene Icons“.',
    ),
  },
  'twofa-directory': {
    label: N_('2FA-Hinweise'),
    description: N_(
      'Die Passwortprüfung zeigt, wo eine Website 2FA kann, du es aber nicht nutzt (Liste von 2fa.directory).',
    ),
  },
  sso: {
    label: N_('Anmeldung über UwUAuth (SSO)'),
    description: N_(
      'Anmelden über UwUAuth oder einen anderen OpenID-Connect-Anbieter. Das Master-Passwort bleibt.',
    ),
  },
  scim: {
    label: N_('Konten aus UwUAuth (SCIM)'),
    description: N_(
      'Der Anbieter legt Konten an, sperrt oder entfernt sie von selbst. Braucht SSO.',
    ),
  },
  'offsite-backups': {
    label: N_('Backups außer Haus'),
    description: N_(
      'Nächtliche, verschlüsselte Backups auf ein NAS (SFTP), in S3 oder einen Ordner. Die lokalen Backups gibt es immer.',
    ),
  },
  'admin-notifications': {
    label: N_('Benachrichtigungen über ntfy, Gotify, Matrix'),
    description: N_('Probleme des Servers auch aufs Handy. Die Mail an die Admins gibt es immer.'),
  },
  suite: {
    label: N_('Suite-Tresor für UwUSSH und UwURDP'),
    description: N_(
      'Die UwU-Apps speichern ihre Hosts und Verbindungen verschlüsselt hier, mit demselben Konto.',
    ),
  },
};

/** One switch as the admin API lists it. */
export type SwitchState = {
  id: SwitchId;
  group: SwitchGroup;
  /** The switch itself. */
  on: boolean;
  /** On, and what it needs is too. */
  works: boolean;
  requires: SwitchId | null;
  /** Something is kept for it, or it is set up. */
  inUse: boolean;
};

type Answer = { features: SwitchState[] };

export const adminSwitches = () =>
  request<Answer>('/uwu/v1/admin/features').then((answer) => answer.features);

export const saveSwitches = (changes: Partial<Record<SwitchId, boolean>>) =>
  request<Answer>('/uwu/v1/admin/features', { method: 'PUT', body: changes }).then(
    (answer) => answer.features,
  );

type InfoLike = { features?: string[]; switches?: Record<string, boolean> } | null | undefined;

/**
 * Whether the server has `id` switched off. A server without switches (older, or a send domain,
 * which says less) is asked by its `features`; until it answered, nothing counts as off.
 */
export function switchedOff(info: InfoLike, id: SwitchId): boolean {
  if (!info) return false;
  if (info.switches && id in info.switches) return info.switches[id] === false;
  return !(info.features ?? []).includes(id);
}

/** Whether `id` works on this server; false until the server answered, like `useFeature`. */
export function useSwitch(id: SwitchId): boolean {
  const info = useServerInfo();
  return info !== null && !switchedOff(info, id);
}

/**
 * The switch a link into the web vault needs, by its path after `#` (or `request` for the page
 * of a file request on a send domain): none for everything else.
 */
export function switchOfLink(path: string, query: URLSearchParams): SwitchId | null {
  if (/^\/(file-requests|request)\//.test(path)) return 'file-requests';
  if (/^\/organizations\/[^/]+$/.test(path) || path === '/accept-organization') return 'families';
  if (path === '/vault' && query.get('due') === '1') return 'reminders';
  if (path === '/settings/travel') return 'travel-mode';
  if (path === '/settings/masked') return 'masked-addresses';
  return null;
}
