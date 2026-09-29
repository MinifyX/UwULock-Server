/**
 * Security notices (§12): what happened on the account — failed logins, a new device, a changed
 * password — listed in Settings → Security, and mailed unless the admin switched a kind off.
 */

import { N_, t } from './i18n';
import { request } from './web/http';

export type Notice = {
  id: string;
  kind: string;
  date: string;
  ip: string | null;
  /** Bitwarden's device type. */
  deviceType: number | null;
  deviceName: string | null;
  /** The client: web, browser, desktop, cli, mobile. */
  app: string | null;
  detail: Record<string, unknown>;
  mailed: boolean;
  seen: boolean;
};

export type NoticePage = { data: Notice[]; continuationToken: string | null; unseen: number };

export function notices(continuationToken: string | null = null): Promise<NoticePage> {
  const query = new URLSearchParams({ limit: '50' });
  if (continuationToken) query.set('continuationToken', continuationToken);
  return request<NoticePage>(`/uwu/v1/security/notices?${query}`);
}

/** This one and every older one are seen. */
export const markSeen = (upToId: string) =>
  request('/uwu/v1/security/notices/seen', { body: { upToId } });

/** The web vault exported the vault: a notice of its own, and a mail. Failing is no problem. */
export function reportExport(format: 'json' | 'encrypted_json' | 'csv') {
  request('/uwu/v1/security/notices/report', {
    body: { kind: 'vaultExported', detail: { format } },
  }).catch(() => undefined);
}

/**
 * The kinds the admin can keep from being mailed, in this order. Later stages add theirs here
 * once the server makes them.
 */
export const MAILABLE_KINDS: { kind: string; label: string }[] = [
  { kind: 'failedLogins', label: N_('Falsche Master-Passwörter') },
  { kind: 'failedTwoFactor', label: N_('Falsche Codes im zweiten Schritt') },
  { kind: 'newDevice', label: N_('Anmeldung auf einem neuen Gerät') },
  { kind: 'passwordChanged', label: N_('Master-Passwort geändert') },
  { kind: 'emailChanged', label: N_('E-Mail-Adresse geändert') },
  { kind: 'kdfChanged', label: N_('Schlüsselableitung geändert') },
  { kind: 'keysRotated', label: N_('Tresor neu verschlüsselt') },
  { kind: 'twoFactorEnabled', label: N_('Zwei-Schritt-Anmeldung eingeschaltet') },
  { kind: 'twoFactorDisabled', label: N_('Zwei-Schritt-Anmeldung ausgeschaltet') },
  { kind: 'apiKeyCreated', label: N_('API-Key abgerufen') },
  { kind: 'apiKeyRotated', label: N_('Neuer API-Key') },
  { kind: 'emergencyAccessRequested', label: N_('Notfallzugriff angefragt') },
  { kind: 'emergencyAccessTakenOver', label: N_('Konto per Notfallzugriff übernommen') },
  { kind: 'loginWithDeviceRequested', label: N_('Anmeldung mit Gerät angefragt') },
  { kind: 'vaultExported', label: N_('Tresor exportiert') },
  { kind: 'kdfBelowMinimum', label: N_('Schlüsselableitung schwächer als verlangt') },
  { kind: 'ssoLinked', label: N_('Anmeldung über SSO verknüpft') },
  { kind: 'maskedConnected', label: N_('Mit UwUMail verbunden') },
  { kind: 'maskedDisconnected', label: N_('Von UwUMail getrennt') },
  { kind: 'maskedApiKeyCreated', label: N_('Schlüssel für maskierte Adressen erstellt') },
  { kind: 'organizationJoined', label: N_('In eine Familie aufgenommen') },
  { kind: 'organizationRemoved', label: N_('Aus einer Familie entfernt') },
  { kind: 'organizationRoleChanged', label: N_('Rolle in einer Familie geändert') },
];

const PROVIDERS: Record<number, string> = {
  0: N_('Authenticator-App'),
  1: N_('Codes per Mail'),
  7: N_('Sicherheitsschlüssel'),
  8: N_('Wiederherstellungscode'),
};

function provider(value: unknown): string {
  const name = typeof value === 'number' ? PROVIDERS[value] : undefined;
  return name ? t(name) : t('unbekannt');
}

const FORMATS: Record<string, string> = {
  json: 'JSON',
  csv: 'CSV',
  encrypted_json: N_('verschlüsseltes JSON'),
};

/** What happened, as a sentence in the page's language. */
export function noticeText(notice: Pick<Notice, 'kind' | 'detail'>): string {
  const detail = notice.detail ?? {};
  const text = (key: string) => (typeof detail[key] === 'string' ? (detail[key] as string) : '');
  const count = typeof detail.count === 'number' ? detail.count : 0;
  switch (notice.kind) {
    case 'failedLogins':
      return t('{n}-mal wurde ein falsches Master-Passwort eingegeben.', { n: count });
    case 'failedTwoFactor':
      return t('{n}-mal kam ein falscher Code im zweiten Schritt ({provider}).', {
        n: count,
        provider: provider(detail.provider),
      });
    case 'newDevice':
      return t('Ein neues Gerät hat sich angemeldet.');
    case 'passwordChanged':
      return t('Das Master-Passwort wurde geändert.');
    case 'emailChanged':
      return t('Die E-Mail-Adresse wurde geändert.');
    case 'kdfChanged':
      return t('Die Schlüsselableitung wurde geändert.');
    case 'keysRotated':
      return t('Der Tresor wurde mit neuen Schlüsseln verschlüsselt.');
    case 'twoFactorEnabled':
      return t('Zwei-Schritt-Anmeldung eingeschaltet: {provider}.', {
        provider: provider(detail.provider),
      });
    case 'twoFactorDisabled':
      return t('Zwei-Schritt-Anmeldung ausgeschaltet: {provider}.', {
        provider: provider(detail.provider),
      });
    case 'apiKeyCreated':
      return t('Der API-Key wurde abgerufen.');
    case 'apiKeyRotated':
      return t('Ein neuer API-Key wurde erzeugt; der alte meldet nicht mehr an.');
    case 'maskedApiKeyCreated':
      return t('Ein Schlüssel für maskierte Adressen wurde erstellt: {name}.', {
        name: text('name'),
      });
    case 'emergencyAccessRequested':
      return t('{who} hat Notfallzugriff auf dein Konto angefragt.', { who: text('grantee') });
    case 'emergencyAccessTakenOver':
      return t('{who} hat dein Konto per Notfallzugriff übernommen.', { who: text('grantee') });
    case 'loginWithDeviceRequested':
      return t('Eine Anmeldung mit Gerät wurde angefragt.');
    case 'vaultExported': {
      const format = FORMATS[text('format')];
      return format
        ? t('Der Tresor wurde exportiert ({format}).', { format: t(format) })
        : t('Der Tresor wurde exportiert.');
    }
    case 'travelModeEnabled':
      return t('Der Reisemodus wurde eingeschaltet.');
    case 'travelModeDisabled':
      return t('Der Reisemodus wurde ausgeschaltet.');
    case 'travelDisableFailed':
      return t('Ein Versuch, den Reisemodus auszuschalten, ist gescheitert.');
    case 'extrasKeyReset':
      return t('Der Schlüssel für die UwU-Extras wurde zurückgesetzt.');
    case 'kdfBelowMinimum':
      return t('Deine Schlüsselableitung ist schwächer, als dieser Server verlangt.');
    case 'ssoLinked':
      return t('Eine Anmeldung über {issuer} wurde mit dem Konto verknüpft.', {
        issuer: text('issuer'),
      });
    case 'maskedConnected':
      return t('Maskierte Adressen sind jetzt mit {server} verbunden.', { server: text('server') });
    case 'maskedDisconnected':
      return t('Maskierte Adressen sind nicht mehr mit {server} verbunden.', {
        server: text('server'),
      });
    case 'organizationJoined':
      return t('Du bist jetzt in „{name}“ und siehst, was dort geteilt ist.', {
        name: text('organization'),
      });
    case 'organizationRemoved':
      return t('Du bist nicht mehr in „{name}“.', { name: text('organization') });
    case 'organizationRoleChanged':
      return detail.type === 0
        ? t('Du bist jetzt Eigentümer von „{name}“.', { name: text('organization') })
        : t('Deine Rolle in „{name}“ wurde geändert.', { name: text('organization') });
    default:
      return notice.kind;
  }
}

/** Bitwarden's device types: the name, and what kind of client it is. */
const DEVICES: Record<number, [string, 'app' | 'extension' | 'desktop' | 'browser' | 'cli']> = {
  0: ['Android', 'app'],
  1: ['iOS', 'app'],
  2: ['Chrome', 'extension'],
  3: ['Firefox', 'extension'],
  4: ['Opera', 'extension'],
  5: ['Edge', 'extension'],
  6: ['Windows', 'desktop'],
  7: ['macOS', 'desktop'],
  8: ['Linux', 'desktop'],
  9: ['Chrome', 'browser'],
  10: ['Firefox', 'browser'],
  11: ['Opera', 'browser'],
  12: ['Edge', 'browser'],
  13: ['Internet Explorer', 'browser'],
  14: ['Browser', 'browser'],
  15: ['Android (Amazon)', 'app'],
  16: ['Windows (UWP)', 'desktop'],
  17: ['Safari', 'browser'],
  18: ['Vivaldi', 'browser'],
  19: ['Vivaldi', 'extension'],
  20: ['Safari', 'extension'],
  21: ['SDK', 'cli'],
  22: ['Server', 'cli'],
  23: ['Windows', 'cli'],
  24: ['macOS', 'cli'],
  25: ['Linux', 'cli'],
  26: ['DuckDuckGo', 'browser'],
};

/** "Firefox-Erweiterung", "Android-App", "Chrome": the device of a notice, or null. */
export function deviceText(notice: Pick<Notice, 'deviceType' | 'deviceName'>): string | null {
  const known = notice.deviceType === null ? undefined : DEVICES[notice.deviceType];
  if (!known) return notice.deviceName || null;
  const [name, kind] = known;
  const label =
    kind === 'extension'
      ? t('{name}-Erweiterung', { name })
      : kind === 'app' || kind === 'desktop'
        ? t('{name}-App', { name })
        : kind === 'cli'
          ? t('Kommandozeile ({name})', { name })
          : name;
  const own = notice.deviceName?.trim();
  return own && own.toLowerCase() !== name.toLowerCase() ? `${label} · ${own}` : label;
}
