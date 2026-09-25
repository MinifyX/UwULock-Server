import { useEffect, useState } from 'react';
import { PasswordInput } from '../components/PasswordInput';
import { ResultLine, Row, Segmented, Toggle, type Result } from '../components/web/controls';
import { saveSettings, settings as load, testMail, type Settings, type Smtp } from '../lib/admin';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';

const EMPTY_SMTP: Smtp = {
  host: '',
  port: 587,
  security: 'starttls',
  username: null,
  password: null,
  from: '',
  fromName: 'UwULock',
};

/** Mail, invitations and a few switches, kept in the database; `.env` only gave the start. */
export function AdminSettings({ me }: { me: string }) {
  useLanguage();
  const [current, setCurrent] = useState<Settings | null>(null);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  const [testTo, setTestTo] = useState(me);

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
  const dirty = JSON.stringify(draft) !== JSON.stringify(current);

  const save = async () => {
    setBusy(true);
    setResult(null);
    try {
      const body: Settings = { ...draft, smtp: draft.smtp?.host.trim() ? draft.smtp : null };
      const saved = await saveSettings(body);
      setCurrent(saved);
      setDraft(saved);
      setResult({ tone: 'info', text: t('Gespeichert ✧') });
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
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
        <button disabled={busy || !dirty} onClick={() => setDraft(current)} data-secondary>
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
