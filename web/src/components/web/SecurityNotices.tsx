import { useEffect, useRef, useState } from 'react';
import { errorText } from '../../lib/errors';
import { when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { deviceText, markSeen, notices, noticeText, type Notice } from '../../lib/notices';
import { Icon } from '../Icon';
import { ResultLine, type Result } from './controls';

const WARNINGS = new Set([
  'failedLogins',
  'failedTwoFactor',
  'loginsLimited',
  'emergencyAccessTakenOver',
  'travelDisableFailed',
  'kdfBelowMinimum',
  'twoFactorDisabled',
]);

/**
 * What happened on the account, newest first: failed logins, new devices, changes to how it is
 * unlocked. Opening the list marks them seen; the new ones stay marked until it is closed.
 */
export function SecurityNotices({ onSeen }: { onSeen: () => void }) {
  useLanguage();
  const [list, setList] = useState<Notice[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  // The latest callback, without loading again when it changes.
  const seen = useRef(onSeen);
  seen.current = onSeen;

  useEffect(() => {
    notices().then(
      (page) => {
        setList(page.data);
        setNext(page.continuationToken);
        const newest = page.data[0];
        if (newest && page.unseen > 0)
          void markSeen(newest.id).then(
            () => seen.current(),
            () => undefined,
          );
      },
      (e) => setResult({ tone: 'error', text: errorText(e) }),
    );
  }, []);

  const more = async () => {
    if (!next) return;
    setBusy(true);
    try {
      const page = await notices(next);
      setList((list) => [...(list ?? []), ...page.data]);
      setNext(page.continuationToken);
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <h3 className="settings-heading">{t('Sicherheitshinweise')}</h3>
      <p className="settings-lead">
        {t(
          'Was auf deinem Konto passiert ist. Kennst du etwas davon nicht, ändere dein Master-Passwort und melde dich überall ab (unter Konto).',
        )}
      </p>
      <ResultLine result={result} />
      <ul className="device-list notice-list">
        {list?.map((notice) => (
          <li key={notice.id} className="device" data-unseen={notice.seen ? undefined : true}>
            <Icon name={WARNINGS.has(notice.kind) ? 'warning' : 'shield'} size={20} />
            <span className="device-text">
              <b>
                {noticeText(notice)}
                {!notice.seen && <span className="badge">{t('neu')}</span>}
              </b>
              <small>
                {[
                  when(notice.date),
                  notice.ip,
                  deviceText(notice),
                  notice.mailed ? t('per Mail gemeldet') : null,
                ]
                  .filter(Boolean)
                  .join(' · ')}
              </small>
            </span>
          </li>
        ))}
        {list?.length === 0 && <li className="empty-note">{t('Noch nichts passiert.')}</li>}
      </ul>
      {next && (
        <button className="load-more" disabled={busy} onClick={() => void more()}>
          {busy ? t('Lädt …') : t('Mehr laden')}
        </button>
      )}
    </>
  );
}
