import { useCallback, useEffect, useState } from 'react';
import { save } from '../components/web/controls';
import { backups, createBackup, downloadBackup, type Backup } from '../lib/admin';
import { errorText } from '../lib/errors';
import { bytes } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';

/** What the time stamp in a backup's name says: `2026-09-25-031000`. */
function stampText(stamp: string | null): string {
  const match = stamp?.match(/^(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})$/);
  if (!match) return stamp ?? '';
  const [, y, m, d, hh, mm] = match;
  return new Date(
    Date.UTC(Number(y), Number(m) - 1, Number(d), Number(hh), Number(mm)),
  ).toLocaleString();
}

/**
 * Every night and before every update the server writes a backup, and keeps seven. Here one
 * can be written now, and taken home — putting one back stays on the command line, with the
 * server stopped.
 */
export function Backups() {
  useLanguage();
  const [list, setList] = useState<Backup[] | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => {
    backups().then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  return (
    <>
      <p className="settings-lead">
        {t(
          'Backups liegen im selben Volume wie die Datenbank. Gegen eine kaputte Platte hilft nur eine Kopie woanders: Lade ab und zu eines herunter. Zurückspielen geht auf der Kommandozeile: docker compose run --rm uwulock restore.',
        )}
      </p>
      <div className="form-actions">
        <button
          className="primary"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await createBackup();
              toast(t('Backup geschrieben ✧'), 'info');
              load();
            } catch (e) {
              toast(errorText(e), 'error');
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? t('Schreibt …') : t('Jetzt ein Backup schreiben')}
        </button>
      </div>
      <table className="admin-table">
        <thead>
          <tr>
            <th>{t('Backup')}</th>
            <th>{t('Größe')}</th>
            <th aria-label={t('Aktionen')} />
          </tr>
        </thead>
        <tbody>
          {list?.map((backup) => (
            <tr key={backup.name}>
              <td>
                <b>{stampText(backup.time)}</b>
                <small className="event-detail">{backup.name}</small>
              </td>
              <td>{bytes(backup.bytes)}</td>
              <td className="row-actions">
                <button
                  onClick={async () => {
                    try {
                      save(await downloadBackup(backup.name), backup.name);
                    } catch (e) {
                      toast(errorText(e), 'error');
                    }
                  }}
                >
                  {t('Herunterladen')}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {list?.length === 0 && (
        <p className="empty-note">
          {t('Noch keine Backups. Das erste schreibt der Server zehn Minuten nach dem Start.')}
        </p>
      )}
    </>
  );
}
