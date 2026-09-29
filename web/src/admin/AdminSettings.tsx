import { ComfortSettings } from './ComfortSettings';
import { FamilySettings } from './FamilySettings';
import { useEffect, useState } from 'react';
import { PasswordInput } from '../components/PasswordInput';
import { ResultLine, Row, Segmented, Toggle, type Result } from '../components/web/controls';
import {
  saveSettings,
  settings as load,
  testMail,
  testPush,
  type Push,
  type Settings,
  type Smtp,
} from '../lib/admin';
import { errorText } from '../lib/errors';
import { ApiError } from '../lib/web/http';
import { t, useLanguage } from '../lib/i18n';
import {
  LokiSettings,
  MetricsSettings,
  NetworkSettings,
  NoticeMailSettings,
  PolicySettings,
} from './OperationsSettings';

const EMPTY_PUSH: Push = { installationId: '', installationKey: '', region: 'eu' };

const EMPTY_SMTP: Smtp = {
  host: '',
  port: 587,
  security: 'starttls',
  username: null,
  password: null,
  from: '',
  fromName: 'UwULock',
};

/**
 * Mail, invitations, policies, who reaches the portal, metrics and logs — kept in the database;
 * `.env` only gave the start.
 */
export function AdminSettings({ me }: { me: string }) {
  useLanguage();
  const [current, setCurrent] = useState<Settings | null>(null);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  const [testTo, setTestTo] = useState(me);
  /** Counts saves and discards: the text boxes that keep their own text start again then. */
  const [generation, setGeneration] = useState(0);

  useEffect(() => {
    load().then(
      (loaded) => {
        setCurrent(loaded);
        setDraft(loaded);
      },
      (e) => setResult({ tone: 'error', text: errorText(e) }),
    );
  }, []);

  if (!draft || !current) return <ResultLine result={result} />;
  const smtp = draft.smtp ?? EMPTY_SMTP;
  const setSmtp = (change: Partial<Smtp>) => setDraft({ ...draft, smtp: { ...smtp, ...change } });
  const push = draft.push ?? EMPTY_PUSH;
  const setPush = (change: Partial<Push>) => setDraft({ ...draft, push: { ...push, ...change } });
  const dirty = JSON.stringify(draft) !== JSON.stringify(current);

  const save = async () => {
    setBusy(true);
    setResult(null);
    try {
      const body: Settings = { ...draft, smtp: draft.smtp?.host.trim() ? draft.smtp : null };
      const saved = await saveSettings(body);
      setCurrent(saved);
      setDraft(saved);
      setGeneration((n) => n + 1);
      setResult({ tone: 'info', text: t('Gespeichert ✧') });
    } catch (e) {
      const code = e instanceof ApiError ? (e.body as { code?: string } | null)?.code : null;
      setResult({
        tone: 'error',
        text:
          code === 'would_lock_out'
            ? `${errorText(e)} ${t('Nichts gespeichert: Du hättest dich selbst ausgesperrt.')}`
            : errorText(e),
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="admin-settings">
      <h2 className="settings-heading">{t('Mail')}</h2>
      <p className="settings-lead">
        {t(
          'Für Einladungen, Codes zur Zwei-Schritt-Anmeldung, Passwort-Hinweise und Hinweise auf neue Geräte. Ohne Mailserver geht alles andere trotzdem.',
        )}
      </p>
      <div className="field-grid wide">
        <label className="field">
          <span>{t('Server')}</span>
          <input
            value={smtp.host}
            onChange={(e) => setSmtp({ host: e.target.value })}
            placeholder="mail.example.com"
          />
        </label>
        <label className="field">
          <span>{t('Port')}</span>
          <input
            type="number"
            value={smtp.port}
            onChange={(e) => setSmtp({ port: Number(e.target.value) })}
          />
        </label>
        <div className="field">
          <span>{t('Verschlüsselung')}</span>
          <Segmented
            label={t('Verschlüsselung')}
            value={smtp.security}
            onChange={(security) =>
              setSmtp({
                security,
                port: security === 'tls' ? 465 : security === 'starttls' ? 587 : 25,
              })
            }
            options={[
              { value: 'starttls', label: 'STARTTLS' },
              { value: 'tls', label: 'TLS' },
              { value: 'none', label: t('keine') },
            ]}
          />
        </div>
        <label className="field">
          <span>{t('Benutzername')}</span>
          <input
            value={smtp.username ?? ''}
            onChange={(e) => setSmtp({ username: e.target.value || null })}
            autoComplete="off"
          />
        </label>
        <label className="field">
          <span>{t('Passwort')}</span>
          <PasswordInput
            value={smtp.password ?? ''}
            onChange={(password) => setSmtp({ password: password || null })}
            autoComplete="new-password"
          />
          {smtp.passwordSet && !smtp.password && (
            <small className="field-hint">
              {t('Ein Passwort ist gespeichert. Leer lassen behält es.')}
            </small>
          )}
        </label>
        <label className="field">
          <span>{t('Absender')}</span>
          <input
            value={smtp.from}
            onChange={(e) => setSmtp({ from: e.target.value })}
            placeholder="vault@example.com"
          />
        </label>
        <label className="field">
          <span>{t('Absendername')}</span>
          <input
            value={smtp.fromName ?? ''}
            onChange={(e) => setSmtp({ fromName: e.target.value || null })}
          />
        </label>
      </div>
      {smtp.security === 'none' && (
        <p className="field-hint">
          {t(
            'Ohne Verschlüsselung nur für einen Mailserver auf diesem Rechner oder im selben geschützten Netz.',
          )}
        </p>
      )}

      <h2 className="settings-heading">{t('Einladungen und Anmeldung')}</h2>
      <Row
        label={t('Einladungen gelten')}
        description={t('So lange funktioniert der Link aus einer Einladung.')}
      >
        <select
          className="select"
          aria-label={t('Einladungen gelten')}
          value={draft.invitationDays}
          onChange={(e) => setDraft({ ...draft, invitationDays: Number(e.target.value) })}
        >
          {[1, 3, 7, 14, 30].map((days) => (
            <option key={days} value={days}>
              {days === 1 ? t('1 Tag') : t('{n} Tage', { n: days })}
            </option>
          ))}
        </select>
      </Row>
      <Row
        label={t('Nutzer dürfen einladen')}
        description={t(
          'Sonst nur Admins. Einladungen von Nutzern machen nie Admins; im Tresor unter Einstellungen → Einladen.',
        )}
      >
        <Toggle
          label={t('Nutzer dürfen einladen')}
          checked={draft.usersMayInvite}
          onChange={(usersMayInvite) => setDraft({ ...draft, usersMayInvite })}
        />
      </Row>
      {draft.usersMayInvite && (
        <Row
          label={t('Einladungen pro Nutzer')}
          description={t(
            'So viele Leute holt ein Nutzer höchstens her, offene Einladungen mitgezählt.',
          )}
        >
          <select
            className="select"
            aria-label={t('Einladungen pro Nutzer')}
            value={draft.invitationsPerUser}
            onChange={(e) => setDraft({ ...draft, invitationsPerUser: Number(e.target.value) })}
          >
            {[1, 2, 3, 5, 10, 20, 50, 100].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </Row>
      )}
      <Row
        label={t('Sprache neuer Konten')}
        description={t('Für Einladungen, und bis jemand selbst eine wählt.')}
      >
        <Segmented
          label={t('Sprache neuer Konten')}
          value={draft.defaultLanguage}
          onChange={(defaultLanguage) => setDraft({ ...draft, defaultLanguage })}
          options={[
            { value: 'de', label: 'Deutsch' },
            { value: 'en', label: 'English' },
          ]}
        />
      </Row>
      <Row
        label={t('Mail bei neuem Gerät')}
        description={t('Wenn sich ein Konto auf einem Gerät zum ersten Mal anmeldet.')}
      >
        <Toggle
          label={t('Mail bei neuem Gerät')}
          checked={draft.newDeviceMail}
          onChange={(newDeviceMail) => setDraft({ ...draft, newDeviceMail })}
        />
      </Row>
      <Row
        label={t('Passwort-Hinweise')}
        description={t('Ein Hinweis zum Master-Passwort, der auf Wunsch per Mail kommt.')}
      >
        <Toggle
          label={t('Passwort-Hinweise')}
          checked={draft.passwordHints}
          onChange={(passwordHints) => setDraft({ ...draft, passwordHints })}
        />
      </Row>
      <Row
        label={t('Geräte merken')}
        description={t('„Auf diesem Gerät merken“ lässt den zweiten Schritt 30 Tage lang weg.')}
      >
        <Toggle
          label={t('Geräte merken')}
          checked={draft.rememberTwoFactor}
          onChange={(rememberTwoFactor) => setDraft({ ...draft, rememberTwoFactor })}
        />
      </Row>

      <h2 className="settings-heading">{t('Dateien und Passwortprüfung')}</h2>
      <Row
        label={t('Größte Datei')}
        description={t('Für Anhänge und Sends. Hinter einem Proxy muss der sie auch durchlassen.')}
      >
        <select
          className="select"
          aria-label={t('Größte Datei')}
          value={draft.maxFileMb}
          onChange={(e) => setDraft({ ...draft, maxFileMb: Number(e.target.value) })}
        >
          {[...new Set([25, 100, 250, 500, 1024, 2048, 4096, draft.maxFileMb])]
            .sort((a, b) => a - b)
            .map((mb) => (
              <option key={mb} value={mb}>
                {mb >= 1024 ? `${mb / 1024} GB` : `${mb} MB`}
              </option>
            ))}
        </select>
      </Row>
      <Row
        label={t('Datenlecks prüfen')}
        description={t(
          'Die Passwortprüfung im Tresor fragt Have I Been Pwned über diesen Server – nur die ersten fünf Zeichen eines Hashes verlassen ihn.',
        )}
      >
        <Toggle
          label={t('Datenlecks prüfen')}
          checked={draft.hibp}
          onChange={(hibp) => setDraft({ ...draft, hibp })}
        />
      </Row>

      <Row
        label={t('Speicher pro Konto')}
        description={t(
          'Anhänge, Send-Dateien, Datei-Anfragen, Versionen und eigene Icons zusammen. Leer: keine Grenze.',
        )}
      >
        <input
          type="number"
          min={1}
          className="narrow-number"
          placeholder={t('keine Grenze')}
          aria-label={t('Speicher pro Konto in MB')}
          value={draft.storagePerUserMb ?? ''}
          onChange={(e) =>
            setDraft({
              ...draft,
              storagePerUserMb: e.target.value ? Math.max(1, Number(e.target.value)) : null,
            })
          }
        />
      </Row>

      <h2 className="settings-heading">{t('Datei-Anfragen')}</h2>
      <Row
        label={t('Datei-Anfragen')}
        description={t(
          'Links, über die jemand ohne Konto Dateien und Text hochlädt, verschlüsselt für den, der den Link gemacht hat.',
        )}
      >
        <Toggle
          label={t('Datei-Anfragen')}
          checked={draft.fileRequests.enabled}
          onChange={(enabled) =>
            setDraft({ ...draft, fileRequests: { ...draft.fileRequests, enabled } })
          }
        />
      </Row>
      <Row label={t('Anfragen pro Konto')}>
        <input
          type="number"
          min={1}
          max={1000}
          className="narrow-number"
          aria-label={t('Anfragen pro Konto')}
          value={draft.fileRequests.perUser}
          onChange={(e) =>
            setDraft({
              ...draft,
              fileRequests: { ...draft.fileRequests, perUser: Number(e.target.value) },
            })
          }
        />
      </Row>
      <Row label={t('Längste Laufzeit in Tagen')}>
        <input
          type="number"
          min={1}
          max={365}
          className="narrow-number"
          aria-label={t('Längste Laufzeit in Tagen')}
          value={draft.fileRequests.maxDays}
          onChange={(e) =>
            setDraft({
              ...draft,
              fileRequests: { ...draft.fileRequests, maxDays: Number(e.target.value) },
            })
          }
        />
      </Row>
      <Row label={t('Dateien pro Einsendung')}>
        <input
          type="number"
          min={1}
          max={100}
          className="narrow-number"
          aria-label={t('Dateien pro Einsendung')}
          value={draft.fileRequests.maxFiles}
          onChange={(e) =>
            setDraft({
              ...draft,
              fileRequests: { ...draft.fileRequests, maxFiles: Number(e.target.value) },
            })
          }
        />
      </Row>

      <ComfortSettings draft={draft} setDraft={setDraft} />

      <FamilySettings draft={draft} setDraft={setDraft} />

      <h2 className="settings-heading">{t('Push für die Handy-Apps')}</h2>
      <p className="settings-lead">
        {t(
          'Weckt die Bitwarden-Apps, wenn sich etwas ändert. Dafür braucht es eine Installations-ID und einen Schlüssel von bitwarden.com/host – kostenlos, und nur mit der Region, in der sie gemacht wurden. Ohne Push synchronisieren die Apps beim Öffnen.',
        )}{' '}
        <a href="https://bitwarden.com/host/" target="_blank" rel="noreferrer">
          bitwarden.com/host
        </a>
      </p>
      <Row label={t('Push über Bitwarden')}>
        <Toggle
          label={t('Push über Bitwarden')}
          checked={draft.push !== null}
          onChange={(on) => setDraft({ ...draft, push: on ? (current.push ?? EMPTY_PUSH) : null })}
        />
      </Row>
      {draft.push && (
        <div className="field-grid wide">
          <div className="field">
            <span>{t('Region')}</span>
            <Segmented
              label={t('Region')}
              value={push.region}
              onChange={(region) => setPush({ region })}
              options={[
                { value: 'eu', label: 'EU' },
                { value: 'us', label: 'US' },
              ]}
            />
          </div>
          <label className="field">
            <span>{t('Installations-ID')}</span>
            <input
              value={push.installationId}
              onChange={(e) => setPush({ installationId: e.target.value })}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <label className="field">
            <span>{t('Installations-Schlüssel')}</span>
            <PasswordInput
              value={push.installationKey ?? ''}
              onChange={(installationKey) => setPush({ installationKey })}
              autoComplete="new-password"
            />
            {push.installationKeySet && !push.installationKey && (
              <small className="field-hint">
                {t('Ein Schlüssel ist gespeichert. Leer lassen behält ihn.')}
              </small>
            )}
          </label>
          <div className="field">
            <span aria-hidden>&nbsp;</span>
            <button
              disabled={busy || dirty || !current.push}
              title={dirty ? t('Erst speichern') : undefined}
              onClick={async () => {
                setBusy(true);
                setResult(null);
                try {
                  await testPush();
                  setResult({ tone: 'info', text: t('Der Relay nimmt ID und Schlüssel an ✧') });
                } catch (e) {
                  setResult({ tone: 'error', text: errorText(e) });
                } finally {
                  setBusy(false);
                }
              }}
            >
              {t('Verbindung testen')}
            </button>
          </div>
        </div>
      )}

      <PolicySettings draft={draft} setDraft={setDraft} />
      <NoticeMailSettings draft={draft} setDraft={setDraft} />
      <NetworkSettings key={`networks-${generation}`} draft={draft} setDraft={setDraft} />
      <MetricsSettings draft={draft} setDraft={setDraft} />
      <LokiSettings key={`loki-${generation}`} draft={draft} setDraft={setDraft} dirty={dirty} />

      <div className="form-actions sticky-actions">
        <span className="inline-form">
          <input
            type="email"
            value={testTo}
            onChange={(e) => setTestTo(e.target.value)}
            aria-label={t('Testmail an')}
          />
          <button
            disabled={busy || dirty || !current.mailEnabled}
            title={dirty ? t('Erst speichern') : undefined}
            onClick={async () => {
              setBusy(true);
              setResult(null);
              try {
                await testMail(testTo);
                setResult({ tone: 'info', text: t('Die Testmail ist raus ✧') });
              } catch (e) {
                setResult({ tone: 'error', text: errorText(e) });
              } finally {
                setBusy(false);
              }
            }}
          >
            {t('Testmail senden')}
          </button>
        </span>
        <span className="spacer" />
        <button
          disabled={busy || !dirty}
          onClick={() => {
            setDraft(current);
            setGeneration((n) => n + 1);
          }}
          data-secondary
        >
          {t('Verwerfen')}
        </button>
        <button className="primary" disabled={busy || !dirty} onClick={() => void save()}>
          {t('Speichern')}
        </button>
      </div>
      <ResultLine result={result} />
    </div>
  );
}
