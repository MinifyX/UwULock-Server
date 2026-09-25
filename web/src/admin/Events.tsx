import { useCallback, useEffect, useState } from 'react';
import { Segmented } from '../components/web/controls';
import { events, type Event } from '../lib/admin';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { N_, t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';

const KINDS: Record<string, string> = {
  login: N_('Anmeldung'),
  'login-failed': N_('Anmeldung abgelehnt'),
  'two-factor-failed': N_('Falscher zweiter Schritt'),
  'two-factor-recovered': N_('Wiederherstellungscode benutzt'),
  register: N_('Registriert'),
  admin: N_('Admin'),
};

/** What an admin did, as the server writes it down (in English), in the reader's language. */
function detailText(kind: string, detail: string | null): string | null {
  if (!detail || kind !== 'admin') return detail;
  const rules: [RegExp, (m: RegExpMatchArray) => string][] = [
    [/^invited (\S+) as admin$/, (m) => t('{email} als Admin eingeladen', { email: m[1]! })],
    [/^invited (\S+)$/, (m) => t('{email} eingeladen', { email: m[1]! })],
    [
      /^withdrew the invitation for (\S+)$/,
      (m) => t('Einladung für {email} zurückgezogen', { email: m[1]! }),
    ],
    [/^changed the settings$/, () => t('Einstellungen geändert')],
    [/^wrote the backup (\S+)$/, (m) => t('Backup {name} geschrieben', { name: m[1]! })],
    [/^downloaded the backup (\S+)$/, (m) => t('Backup {name} heruntergeladen', { name: m[1]! })],
    [/^deleted the account (\S+)$/, (m) => t('Konto {email} gelöscht', { email: m[1]! })],
    [
      /^logged out device (\S+) of (\S+)$/,
      (m) => t('Gerät {device} abgemeldet', { device: m[1]! }),
    ],
    [/^disable for (\S+)$/, (m) => t('{email} gesperrt', { email: m[1]! })],
    [/^enable for (\S+)$/, (m) => t('{email} freigegeben', { email: m[1]! })],
    [/^make-admin for (\S+)$/, (m) => t('{email} zum Admin gemacht', { email: m[1]! })],
    [/^remove-admin for (\S+)$/, (m) => t('{email} ist kein Admin mehr', { email: m[1]! })],
    [/^log-out for (\S+)$/, (m) => t('{email} überall abgemeldet', { email: m[1]! })],
    [
      /^reset-two-factor for (\S+)$/,
      (m) => t('Zwei-Schritt-Anmeldung von {email} zurückgesetzt', { email: m[1]! }),
    ],
  ];
  for (const [pattern, text] of rules) {
    const match = detail.match(pattern);
    if (match) return text(match);
  }
  return detail;
}

/** Logins, refused logins, registrations and what admins did, the newest first; 90 days of it. */
export function Events() {
  useLanguage();
  const [kind, setKind] = useState<string>('');
  const [list, setList] = useState<Event[]>([]);
  const [more, setMore] = useState(false);

  const load = useCallback(
    (before: number | null) => {
      events(kind || null, before).then(
        (page) => {
          setList((all) => (before ? [...all, ...page] : page));
          setMore(page.length === 100);
        },
        (e) => toast(errorText(e), 'error'),
      );
    },
    [kind],
  );
  useEffect(() => load(null), [load]);

  return (
    <>
      <Segmented
        label={t('Art')}
        value={kind}
        onChange={setKind}
        options={[
          { value: '', label: t('Alle') },
          { value: 'login-failed', label: t('Abgelehnt') },
          { value: 'login', label: t('Anmeldungen') },
          { value: 'admin', label: t('Admin') },
        ]}
      />
      <table className="admin-table events">
        <thead>
          <tr>
            <th>{t('Wann')}</th>
            <th>{t('Was')}</th>
            <th>{t('Wer')}</th>
            <th>{t('Von wo')}</th>
          </tr>
        </thead>
        <tbody>
          {list.map((event) => (
            <tr key={event.id} data-alarm={event.kind.endsWith('failed') || undefined}>
              <td>{when(event.time)}</td>
              <td>
                {t(KINDS[event.kind] ?? event.kind)}
                {event.detail && (
                  <small className="event-detail">{detailText(event.kind, event.detail)}</small>
                )}
              </td>
              <td>{event.email ?? '–'}</td>
              <td>
                {event.ip ?? '–'}
                {event.deviceType && <small className="event-detail">{event.deviceType}</small>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {list.length === 0 && <p className="empty-note">{t('Noch nichts.')}</p>}
      {more && (
        <button className="load-more" onClick={() => load(list[list.length - 1]?.id ?? null)}>
          {t('Ältere laden')}
        </button>
      )}
    </>
  );
}
