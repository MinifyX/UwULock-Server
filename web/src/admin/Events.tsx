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
                {event.detail && <small className="event-detail">{event.detail}</small>}
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
