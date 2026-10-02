/**
 * The admin portal's map: a few areas in the sidebar, each with its tabs (docs/ui.md, "The admin portal").
 * A tab's path is its address after `#`; the first tab of an area has the area's own path. A tab
 * or an area that `needs` a feature switch is there only while it works, and an area without
 * any tab left is not there either.
 */

import type { IconName } from '../components/Icon';
import { N_ } from '../lib/i18n';
import type { SwitchId } from '../lib/switches';

export type TabId =
  | 'overview'
  | 'accounts'
  | 'invitations'
  | 'families'
  | 'sign-in'
  | 'master-password'
  | 'admin-access'
  | 'failed-logins'
  | 'ip-blocks'
  | 'sso'
  | 'sso-rules'
  | 'scim'
  | 'features'
  | 'storage'
  | 'icons'
  | 'masked'
  | 'send-domains'
  | 'mail-server'
  | 'user-mails'
  | 'alerts'
  | 'local-backups'
  | 'offsite'
  | 'branding'
  | 'diagnosis'
  | 'events'
  | 'log'
  | 'monitoring';

export type AdminTab = {
  id: TabId;
  path: string;
  label: string;
  /** Every switch named must work. */
  needs?: SwitchId[];
};

export type Area = {
  id: string;
  label: string;
  /** One line under the heading: what is found here. */
  lead: string;
  icon: IconName;
  tabs: AdminTab[];
};

export const AREAS: Area[] = [
  {
    id: 'overview',
    label: N_('Übersicht'),
    lead: N_('Was gerade Aufmerksamkeit braucht, und die Zahlen des Servers.'),
    icon: 'house',
    tabs: [{ id: 'overview', path: '/', label: N_('Übersicht') }],
  },
  {
    id: 'users',
    label: N_('Benutzer & Einladungen'),
    lead: N_('Wer ein Konto hat, wer eingeladen ist, und wer mit wem teilt.'),
    icon: 'user',
    tabs: [
      { id: 'accounts', path: '/users', label: N_('Konten') },
      { id: 'invitations', path: '/users/invitations', label: N_('Einladungen') },
      { id: 'families', path: '/users/families', label: N_('Familien'), needs: ['families'] },
    ],
  },
  {
    id: 'security',
    label: N_('Sicherheit & Anmeldung'),
    lead: N_(
      'Wie sich Konten anmelden, wie stark Master-Passwörter sein müssen, wer ins Admin-Portal kommt, und wer es vergeblich versucht.',
    ),
    icon: 'shield',
    tabs: [
      { id: 'sign-in', path: '/security', label: N_('Anmeldung') },
      { id: 'master-password', path: '/security/master-password', label: N_('Master-Passwort') },
      { id: 'admin-access', path: '/security/admin-access', label: N_('Admin-Portal') },
      {
        id: 'failed-logins',
        path: '/security/failed-logins',
        label: N_('Fehlgeschlagene Anmeldungen'),
      },
      { id: 'ip-blocks', path: '/security/blocked', label: N_('Gesperrte Adressen') },
      { id: 'sso', path: '/security/sso', label: N_('SSO-Anbieter'), needs: ['sso'] },
      { id: 'sso-rules', path: '/security/sso-rules', label: N_('SSO-Regeln'), needs: ['sso'] },
      { id: 'scim', path: '/security/scim', label: N_('SCIM'), needs: ['sso', 'scim'] },
    ],
  },
  {
    id: 'vault',
    label: N_('Tresor & Funktionen'),
    lead: N_('Was UwULock über den Tresor hinaus kann, und wie viel Platz jedes Konto bekommt.'),
    icon: 'grid',
    tabs: [
      { id: 'features', path: '/vault', label: N_('Funktionen') },
      { id: 'storage', path: '/vault/storage', label: N_('Speicher & Grenzen') },
      { id: 'icons', path: '/vault/icons', label: N_('Icons & Passwortprüfung') },
      {
        id: 'masked',
        path: '/vault/masked',
        label: N_('Maskierte Adressen'),
        needs: ['masked-addresses'],
      },
      {
        id: 'send-domains',
        path: '/vault/send-domains',
        label: N_('Send-Domains'),
        needs: ['send-domains'],
      },
    ],
  },
  {
    id: 'mail',
    label: N_('E-Mail & Benachrichtigungen'),
    lead: N_('Über welchen Mailserver der Server schreibt, was er Nutzern und Admins meldet.'),
    icon: 'bell',
    tabs: [
      { id: 'mail-server', path: '/mail', label: N_('Mailserver') },
      { id: 'user-mails', path: '/mail/users', label: N_('Mails an Nutzer') },
      {
        id: 'alerts',
        path: '/mail/alerts',
        label: N_('Meldungen an Admins'),
        needs: ['admin-notifications'],
      },
    ],
  },
  {
    id: 'backups',
    label: N_('Datensicherung'),
    lead: N_('Backups auf diesem Server und an einem zweiten Ort, und der Weg zurück.'),
    icon: 'drive',
    tabs: [
      { id: 'local-backups', path: '/backups', label: N_('Auf diesem Server') },
      {
        id: 'offsite',
        path: '/backups/offsite',
        label: N_('Außer Haus'),
        needs: ['offsite-backups'],
      },
    ],
  },
  {
    id: 'branding',
    label: N_('Aussehen'),
    lead: N_('Name, Farbe und Logos, mit denen der Server sich zeigt.'),
    icon: 'eye',
    tabs: [{ id: 'branding', path: '/branding', label: N_('Aussehen') }],
  },
  {
    id: 'system',
    label: N_('System & Diagnose'),
    lead: N_('Ob alles richtig eingerichtet ist, was passiert ist, und was der Server schreibt.'),
    icon: 'lifebuoy',
    tabs: [
      { id: 'diagnosis', path: '/system', label: N_('Diagnose') },
      { id: 'events', path: '/system/events', label: N_('Ereignisse') },
      { id: 'log', path: '/system/log', label: N_('Log') },
      { id: 'monitoring', path: '/system/monitoring', label: N_('Überwachung') },
    ],
  },
];

/** Where the pages of 0.6.0-beta.1 went: their addresses keep working. */
export const MOVED: Record<string, string> = {
  '/invitations': '/users/invitations',
  '/families': '/users/families',
  '/features': '/vault',
  '/settings': '/security',
  '/login': '/security/sso',
  '/send-domains': '/vault/send-domains',
  '/events': '/system/events',
  '/logs': '/system/log',
  '/notifications': '/mail/alerts',
  '/diagnosis': '/system',
};

/** The areas and tabs there are, with what is switched off left out. */
export function visibleAreas(works: (id: SwitchId) => boolean): Area[] {
  return AREAS.map((area) => ({
    ...area,
    tabs: area.tabs.filter((tab) => (tab.needs ?? []).every(works)),
  })).filter((area) => area.tabs.length > 0);
}

/**
 * The area and tab for a path: an old path goes where its page moved, and anything unknown (or
 * switched off) to the first tab of its area, or to the overview.
 */
export function locate(path: string, areas: Area[]): { area: Area; tab: AdminTab } {
  const wanted = MOVED[path] ?? path;
  for (const area of areas) {
    const tab = area.tabs.find((each) => each.path === wanted);
    if (tab) return { area, tab };
  }
  const head = `/${wanted.split('/')[1] ?? ''}`;
  const area = areas.find((each) => each.tabs[0]!.path === head) ?? areas[0]!;
  return { area, tab: area.tabs[0]! };
}
