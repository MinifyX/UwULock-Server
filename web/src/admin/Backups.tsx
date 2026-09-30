import { useCallback, useEffect, useState } from 'react';
import { Button, ButtonRow, Section, Table } from '../components/ui';
import { PasswordPrompt, save } from '../components/web/controls';
import { logout } from '../lib/api';
import { backups, createBackup, downloadBackup, restoreBackup, type Backup } from '../lib/admin';
import { errorText } from '../lib/errors';
import { bytes } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';

/**
 * What the time stamp in a backup's name says: `2026-09-25-031000`, and whether it is the one
 * written just before a backup went back.
 */
function stampText(stamp: string | null): string {
  const match = stamp?.match(/^(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})(-before-restore)?/);
  if (!match) return stamp ?? '';
  const [, y, m, d, hh, mm, , before] = match;
  const when = new Date(
    Date.UTC(Number(y), Number(m) - 1, Number(d), Number(hh), Number(mm)),
  ).toLocaleString();
  return before ? t('{when}, vor dem Zurückspielen', { when }) : when;
}

/**
 * Every night and before every update the server writes a backup, and keeps seven. Here one
 * can be written now, taken home, or put back while the server runs — what was there is
 * written as a backup first, so that step can be undone the same way.
 */
export function Backups() {
  useLanguage();
  const [list, setList] = useState<Backup[] | null>(null);
  const [busy, setBusy] = useState(false);
  /** The backup the master password is being asked for. */
  const [taking, setTaking] = useState<string | null>(null);
  const [restoring, setRestoring] = useState<string | null>(null);
  const load = useCallback(() => {
    backups().then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  return (
    <>
      <Section
        heading={t('Backups auf diesem Server')}
        lead={t(
          'Jede Nacht und vor jedem Update schreibt der Server ein Backup und hebt sieben auf. Sie liegen im selben Volume wie die Datenbank: Gegen eine kaputte Platte hilft nur eine Kopie woanders – lade ab und zu eines herunter, oder richte Backups außer Haus ein.',
        )}
      >
        <ButtonRow>
          <Button
            variant="primary"
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
          </Button>
        </ButtonRow>
        {list?.length === 0 ? (
          <p className="empty-note">
            {t('Noch keine Backups. Das erste schreibt der Server zehn Minuten nach dem Start.')}
          </p>
        ) : (
          <Table
            label={t('Backups auf diesem Server')}
            head={
              <>
                <th>{t('Backup')}</th>
                <th>{t('Größe')}</th>
                <th>
                  <span className="sr-only">{t('Aktionen')}</span>
                </th>
              </>
            }
          >
            {list?.map((backup) => (
              <tr key={backup.name}>
                <td>
                  <b>{stampText(backup.time)}</b>
                  <small className="event-detail">{backup.name}</small>
                </td>
                <td>{bytes(backup.bytes)}</td>
                <td className="row-actions">
                  <Button size="small" icon="download" onClick={() => setTaking(backup.name)}>
                    {t('Herunterladen')}
                  </Button>
                  <Button
                    size="small"
                    variant="quiet-danger"
                    onClick={() => setRestoring(backup.name)}
                  >
                    {t('Zurückspielen')}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
        <p className="field-hint">
          {t(
            'Beim Zurückspielen wird der jetzige Stand vorher selbst ein Backup – so lässt es sich auf demselben Weg rückgängig machen. Danach melden sich alle neu an.',
          )}
        </p>
      </Section>
      {taking && (
        <PasswordPrompt
          title={t('Backup herunterladen?')}
          tone="warning"
          lead={t(
            'Ein Backup ist die ganze Datenbank: jeder Tresor, verschlüsselt, und die Schlüssel des Servers. Bewahre es so sicher auf wie deine Passwörter.',
          )}
          confirm={t('Herunterladen')}
          onCancel={() => setTaking(null)}
          action={async (password) => {
            save(await downloadBackup(taking, password), taking);
            setTaking(null);
          }}
        />
      )}
      {restoring && (
        <PasswordPrompt
          title={t('Dieses Backup zurückspielen?')}
          tone="warning"
          lead={t(
            'Alles kommt auf den Stand von {when}: Konten, Tresore, Einstellungen. Was seitdem dazukam, ist dann weg – außer im Backup, das jetzt vorher geschrieben wird. Danach melden sich alle neu an, auf jedem Gerät, du auch.',
            { when: stampText(list?.find((b) => b.name === restoring)?.time ?? null) },
          )}
          confirm={t('Zurückspielen')}
          onCancel={() => setRestoring(null)}
          action={async (password) => {
            const done = await restoreBackup(restoring, password);
            setRestoring(null);
            toast(
              t('Zurückgespielt ✧ Der Stand davor ist jetzt {name}. Melde dich neu an.', {
                name: done.before,
              }),
              'info',
            );
            // Every session ended with the restore, this one too.
            await logout();
          }}
        />
      )}
    </>
  );
}
