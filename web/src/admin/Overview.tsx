import { useEffect, useState } from 'react';
import { overview, type Overview as Data } from '../lib/admin';
import { errorText } from '../lib/errors';
import { ago, bytes, seconds } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';

function uptime(total: number): string {
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  if (days) return t('{d} Tage, {h} Std.', { d: days, h: hours });
  return t('{h} Std., {m} Min.', { h: hours, m: Math.floor((total % 3600) / 60) });
}

/** The numbers: accounts, items, devices, the database, backups, mail, updates. */
export function Overview() {
  useLanguage();
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    overview().then(setData, (e) => setError(errorText(e)));
  }, []);
  if (error) return <p className="form-error">{error}</p>;
  if (!data) return null;
  const update = data.update;
  return (
    <>
      <div className="stat-grid">
        <Stat
          label={t('Nutzer')}
          value={data.users}
          note={t('{n} Admins, {d} gesperrt', { n: data.admins, d: data.disabled })}
        />
        <Stat label={t('Offene Einladungen')} value={data.invitations} />
        <Stat
          label={t('Einträge')}
          value={data.ciphers}
          note={t('{n} im Papierkorb, {f} Ordner', { n: data.trashed, f: data.folders })}
        />
        <Stat label={t('Angemeldete Geräte')} value={data.devices} />
        <Stat
          label={t('Mit Zwei-Schritt-Anmeldung')}
          value={data.twoFactor}
          note={t('von {n} Nutzern', { n: data.users })}
        />
        <Stat
          label={t('Fehlgeschlagene Anmeldungen')}
          value={data.failedLoginsDay}
          note={t('in den letzten 24 Stunden')}
          alarm={data.failedLoginsDay > 20}
        />
      </div>
      <div className="facts">
        <Fact
          label={t('Version')}
          value={`${data.version}${update.commit ? ` (${update.commit.slice(0, 7)})` : ''}`}
        />
        <Fact label={t('Läuft seit')} value={uptime(data.uptimeSeconds)} />
        <Fact label={t('Datenbank')} value={bytes(data.databaseBytes)} />
        <Fact
          label={t('Backups')}
          value={
            data.backups
              ? t('{n} Stück, {size}, das neueste: {name}', {
                  n: data.backups,
                  size: bytes(data.backupBytes),
                  name: data.lastBackup ?? '',
                })
              : t('noch keins')
          }
        />
        <Fact
          label={t('Mail')}
          value={
            data.mail
              ? t('eingerichtet')
              : t('nicht eingerichtet – ohne Mail gehen Einladungen nur per Link')
          }
        />
        <Fact
          label={t('Updates')}
          value={
            update.newer
              ? t('Version {version} ist da: sudo bash update.sh neben compose.yaml', {
                  version: update.newer,
                })
              : update.commits
                ? t('main ist {n} Commits weiter', { n: update.commits })
                : update.error
                  ? t('Nachsehen ging nicht: {error}', { error: update.error })
                  : update.checked
                    ? t('aktuell (nachgesehen {when})', {
                        when: ago(seconds(update.checked)),
                      })
                    : t('noch nicht nachgesehen')
          }
          alarm={Boolean(update.newer)}
        />
        {update.channel && <Fact label={t('Kanal')} value={update.channel} />}
      </div>
    </>
  );
}

function Stat({
  label,
  value,
  note,
  alarm,
}: {
  label: string;
  value: number;
  note?: string;
  alarm?: boolean;
}) {
  return (
    <div className="stat" data-alarm={alarm || undefined}>
      <span className="stat-value">{value.toLocaleString()}</span>
      <span className="stat-label">{label}</span>
      {note && <span className="stat-note">{note}</span>}
    </div>
  );
}

function Fact({ label, value, alarm }: { label: string; value: string; alarm?: boolean }) {
  return (
    <div className="fact" data-alarm={alarm || undefined}>
      <span className="fact-label">{label}</span>
      <span className="fact-value">{value}</span>
    </div>
  );
}
