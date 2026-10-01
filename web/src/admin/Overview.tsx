import { useEffect, useState } from 'react';
import { Badge, Button, Callout, Card, Section } from '../components/ui';
import { alertTitle, overview, type Alert, type Overview as Data } from '../lib/admin';
import { errorText } from '../lib/errors';
import { ago, bytes, seconds, when } from '../lib/format';
import { N_, t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import { History } from './History';

const SEVERITY: Record<Alert['severity'], string> = {
  info: N_('Hinweis'),
  warning: N_('Warnung'),
  error: N_('Fehler'),
};

function uptime(total: number): string {
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  if (days) return t('{d} Tage, {h} Std.', { d: days, h: hours });
  return t('{h} Std., {m} Min.', { h: hours, m: Math.floor((total % 3600) / 60) });
}

/**
 * What needs attention first — alerts, channels that fail, the last diagnosis — then the numbers:
 * accounts, items, devices, the database, backups, mail, updates.
 */
export function Overview() {
  useLanguage();
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    overview().then(setData, (e) => setError(errorText(e)));
  }, []);
  if (error) return <Callout tone="error">{error}</Callout>;
  if (!data) return null;
  const update = data.update;
  const loki = data.loki;
  return (
    <>
      {data.alerts.length > 0 && (
        <ul className="stack-list" aria-label={t('Warnungen')}>
          {data.alerts.map((alert) => (
            <li key={alert.kind}>
              <Callout
                tone={
                  alert.severity === 'info'
                    ? 'info'
                    : alert.severity === 'error'
                      ? 'error'
                      : 'warning'
                }
                icon="warning"
                title={
                  <>
                    {alertTitle(alert.kind)}
                    <Badge tone={alert.severity === 'info' ? 'accent' : 'alarm'}>
                      {t(SEVERITY[alert.severity] ?? alert.severity)}
                    </Badge>
                  </>
                }
              >
                <p className="muted">
                  {alert.detail}
                  {when(alert.since) ? ` · ${t('seit {when}', { when: when(alert.since)! })}` : ''}
                </p>
              </Callout>
            </li>
          ))}
        </ul>
      )}
      {data.failingChannels.length > 0 && (
        <Callout
          tone="warning"
          title={t('Benachrichtigungen kommen nicht an:')}
          actions={
            <Button size="small" onClick={() => go('/mail/alerts')}>
              {t('Zu den Benachrichtigungen')}
            </Button>
          }
        >
          {data.failingChannels.map((channel) => `${channel.name} (${channel.error})`).join(', ')}
        </Callout>
      )}
      <Callout
        tone={data.diagnosis && data.diagnosis.errors > 0 ? 'warning' : 'info'}
        icon="lifebuoy"
        actions={
          <Button size="small" onClick={() => go('/system')}>
            {t('Zur Diagnose')}
          </Button>
        }
      >
        {data.diagnosis
          ? t('Letzte Diagnose {when}: {errors} Fehler, {warnings} Warnungen.', {
              when: when(data.diagnosis.date) ?? '',
              errors: data.diagnosis.errors,
              warnings: data.diagnosis.warnings,
            })
          : t(
              'Die Diagnose lief noch nie. Sie prüft Zertifikat, Uhrzeit, Mail, Backups und den Proxy davor.',
            )}
      </Callout>
      <Section heading={t('Zahlen')}>
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
            onOpen={() => go('/security/failed-logins')}
          />
        </div>
      </Section>
      <Section heading={t('Server')}>
        <Card as="div">
          <dl className="facts">
            <Fact
              label={t('Version')}
              value={`${data.version}${update.commit ? ` (${update.commit.slice(0, 7)})` : ''}`}
            />
            <Fact label={t('Läuft seit')} value={uptime(data.uptimeSeconds)} />
            <Fact label={t('Datenbank')} value={bytes(data.databaseBytes)} />
            <Fact
              label={t('Dateien')}
              value={t('Anhänge {attachments}, Sends {sends}', {
                attachments: bytes(data.storage.filesBytes.attachments),
                sends: bytes(data.storage.filesBytes.sends),
              })}
            />
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
            {loki.enabled && (
              <Fact
                label={t('Loki')}
                value={
                  loki.error
                    ? t('Geht nicht: {error}', { error: loki.error })
                    : t('{sent} Zeilen geschickt, {queued} warten, {dropped} verworfen', {
                        sent: loki.sent.toLocaleString(),
                        queued: loki.queued.toLocaleString(),
                        dropped: loki.dropped.toLocaleString(),
                      })
                }
                alarm={Boolean(loki.error) || loki.dropped > 0}
              />
            )}
          </dl>
        </Card>
      </Section>
      <History />
    </>
  );
}

function Stat({
  label,
  value,
  note,
  alarm,
  onOpen,
}: {
  label: string;
  value: number;
  note?: string;
  alarm?: boolean;
  /** A tile that leads to its own page. */
  onOpen?: () => void;
}) {
  const content = (
    <>
      <span className="stat-value" data-alarm={alarm || undefined}>
        {value.toLocaleString()}
      </span>
      <span className="stat-label">{label}</span>
      {note && <span className="stat-note">{note}</span>}
    </>
  );
  if (onOpen)
    return (
      <button type="button" className="card stat stat-link" onClick={onOpen}>
        {content}
        <span className="stat-more" aria-hidden>
          {t('Ansehen')} →
        </span>
      </button>
    );
  return (
    <Card as="div" className="stat">
      {content}
    </Card>
  );
}

function Fact({ label, value, alarm }: { label: string; value: string; alarm?: boolean }) {
  return (
    <div className="fact" data-alarm={alarm || undefined}>
      <dt className="fact-label">{label}</dt>
      <dd className="fact-value">{value}</dd>
    </div>
  );
}
