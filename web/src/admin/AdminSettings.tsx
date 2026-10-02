import { useState } from 'react';
import { PasswordInput } from '../components/PasswordInput';
import {
  Button,
  Callout,
  Field,
  FormRow,
  Section,
  Segmented,
  Select,
  SettingRow,
  TextField,
  Toggle,
} from '../components/ui';
import { ResultLine, type Result } from '../components/web/controls';
import { testMail, type Smtp } from '../lib/admin';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { useSwitch } from '../lib/switches';
import { SettingsTab } from './draft';
import { Explain, NumberInput } from './fields';

const EMPTY_SMTP: Smtp = {
  host: '',
  port: 587,
  security: 'starttls',
  username: null,
  password: null,
  from: '',
  fromName: 'UwULock',
};

/** *E-Mail → Mailserver*: the SMTP server the mails go out through, and a test mail. */
export function MailServerTab({ me }: { me: string }) {
  useLanguage();
  const [testTo, setTestTo] = useState(me);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  return (
    <SettingsTab>
      {({ draft, current, setDraft, dirty }) => {
        const smtp = draft.smtp ?? EMPTY_SMTP;
        const setSmtp = (change: Partial<Smtp>) =>
          setDraft({ ...draft, smtp: { ...smtp, ...change } });
        return (
          <>
            <Section
              heading={t('Mailserver (SMTP)')}
              lead={t(
                'Über ihn gehen Einladungen, Codes für die Zwei-Schritt-Anmeldung, Passwort-Hinweise und Sicherheitshinweise. Ohne Mailserver geht alles andere trotzdem; Einladungen gibt es dann nur als Link.',
              )}
            >
              <FormRow min="wide">
                <TextField
                  label={t('Adresse des Mailservers')}
                  value={smtp.host}
                  onChange={(host) => setSmtp({ host })}
                  placeholder="mail.example.com"
                  spellCheck={false}
                />
                <Field label={t('Port')} hint={t('587 bei STARTTLS, 465 bei TLS.')}>
                  <input
                    type="number"
                    value={smtp.port}
                    onChange={(e) => setSmtp({ port: Number(e.target.value) })}
                  />
                </Field>
              </FormRow>
              <SettingRow
                label={t('Verschlüsselung der Verbindung')}
                description={
                  <Explain recommended={t('STARTTLS oder TLS')}>
                    {t(
                      'Wie der Server mit dem Mailserver spricht. Der Port stellt sich passend ein.',
                    )}
                  </Explain>
                }
              >
                <Segmented
                  label={t('Verschlüsselung der Verbindung')}
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
              </SettingRow>
              {smtp.security === 'none' && (
                <Callout tone="warning">
                  {t(
                    'Ohne Verschlüsselung nur für einen Mailserver auf diesem Rechner oder im selben geschützten Netz.',
                  )}
                </Callout>
              )}
            </Section>
            <Section
              heading={t('Anmeldung beim Mailserver')}
              lead={t(
                'Die Zugangsdaten, die dein Mail-Anbieter dir gibt. Leer, wenn er keine braucht.',
              )}
            >
              <FormRow min="wide">
                <TextField
                  label={t('Benutzername')}
                  value={smtp.username ?? ''}
                  onChange={(username) => setSmtp({ username: username || null })}
                  autoComplete="off"
                />
                <Field
                  label={t('Passwort')}
                  hint={
                    smtp.passwordSet && !smtp.password
                      ? t('Ein Passwort ist gespeichert. Leer lassen behält es.')
                      : undefined
                  }
                >
                  <PasswordInput
                    value={smtp.password ?? ''}
                    onChange={(password) => setSmtp({ password: password || null })}
                    autoComplete="new-password"
                  />
                </Field>
              </FormRow>
            </Section>
            <Section
              heading={t('Absender')}
              lead={t('So stehen die Mails im Postfach der Empfänger.')}
            >
              <FormRow min="wide">
                <TextField
                  label={t('Absender-Adresse')}
                  value={smtp.from}
                  onChange={(from) => setSmtp({ from })}
                  placeholder="vault@example.com"
                  spellCheck={false}
                />
                <TextField
                  label={t('Absendername')}
                  value={smtp.fromName ?? ''}
                  onChange={(fromName) => setSmtp({ fromName: fromName || null })}
                />
              </FormRow>
            </Section>
            <Section
              heading={t('Testmail')}
              lead={t(
                'Schickt eine Mail mit den gespeicherten Angaben. Änderungen erst speichern.',
              )}
            >
              <div className="inline-form">
                <input
                  type="email"
                  value={testTo}
                  onChange={(e) => setTestTo(e.target.value)}
                  aria-label={t('Testmail an')}
                />
                <Button
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
                </Button>
              </div>
              <ResultLine result={result} />
            </Section>
          </>
        );
      }}
    </SettingsTab>
  );
}

const DAYS = [1, 3, 7, 14, 30];

/** *Benutzer → Einladungen*: how long a link lasts, and who else may invite. */
export function InvitationRules() {
  useLanguage();
  return (
    <SettingsTab>
      {({ draft, setDraft }) => (
        <Section
          heading={t('Regeln für Einladungen')}
          lead={t('Ohne Einladung legt niemand ein Konto an.')}
        >
          <SettingRow
            label={t('Einladungen gelten')}
            description={
              <Explain recommended={t('7 Tage')}>
                {t('So lange funktioniert der Link aus einer Einladung.')}
              </Explain>
            }
          >
            <Select
              label={t('Einladungen gelten')}
              value={String(draft.invitationDays)}
              onChange={(days) => setDraft({ ...draft, invitationDays: Number(days) })}
              options={DAYS.map((days) => ({
                value: String(days),
                label: days === 1 ? t('1 Tag') : t('{n} Tage', { n: days }),
              }))}
            />
          </SettingRow>
          <SettingRow
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
          </SettingRow>
          {draft.usersMayInvite && (
            <SettingRow
              label={t('Einladungen pro Nutzer')}
              description={t(
                'So viele Leute holt ein Nutzer höchstens her, offene Einladungen mitgezählt.',
              )}
            >
              <Select
                label={t('Einladungen pro Nutzer')}
                value={String(draft.invitationsPerUser)}
                onChange={(n) => setDraft({ ...draft, invitationsPerUser: Number(n) })}
                options={[1, 2, 3, 5, 10, 20, 50, 100].map((n) => ({
                  value: String(n),
                  label: String(n),
                }))}
              />
            </SettingRow>
          )}
          <SettingRow
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
          </SettingRow>
        </Section>
      )}
    </SettingsTab>
  );
}

/** The biggest file sizes offered: a value set elsewhere stays among them. */
const SIZES = [25, 100, 250, 500, 1024, 2048, 4096];

/**
 * *Tresor → Speicher & Grenzen*: the biggest file, the room of one account, and the limits of
 * the extras that keep things (versions, file requests, the suite vault) — those only while on.
 */
export function StorageTab() {
  useLanguage();
  const versionsOn = useSwitch('versions');
  const requestsOn = useSwitch('file-requests');
  const suiteOn = useSwitch('suite');
  return (
    <SettingsTab>
      {({ draft, setDraft }) => {
        const versions = draft.versions;
        const setRequests = (change: Partial<typeof draft.fileRequests>) =>
          setDraft({ ...draft, fileRequests: { ...draft.fileRequests, ...change } });
        const setSuite = (change: Partial<typeof draft.suite>) =>
          setDraft({ ...draft, suite: { ...draft.suite, ...change } });
        return (
          <>
            <Section
              heading={t('Dateien und Speicherplatz')}
              lead={t('Wie groß eine Datei sein darf, und wie viel ein Konto insgesamt ablegt.')}
            >
              <SettingRow
                label={t('Größte Datei')}
                description={t(
                  'Für Anhänge und Sends. Steht ein Proxy davor, muss er so große Uploads auch durchlassen (die Diagnose prüft das).',
                )}
              >
                <Select
                  label={t('Größte Datei')}
                  value={String(draft.maxFileMb)}
                  onChange={(mb) => setDraft({ ...draft, maxFileMb: Number(mb) })}
                  options={[...new Set([...SIZES, draft.maxFileMb])]
                    .sort((a, b) => a - b)
                    .map((mb) => ({
                      value: String(mb),
                      label: mb >= 1024 ? `${mb / 1024} GB` : `${mb} MB`,
                    }))}
                />
              </SettingRow>
              <SettingRow
                label={t('Speicher pro Konto')}
                description={t(
                  'Anhänge, Send-Dateien, Datei-Anfragen, Versionen und eigene Icons zusammen. Leer: keine Grenze.',
                )}
              >
                <NumberInput
                  label={t('Speicher pro Konto')}
                  unit={t('Megabyte')}
                  min={1}
                  placeholder={t('keine Grenze')}
                  value={draft.storagePerUserMb}
                  onChange={(mb) =>
                    setDraft({ ...draft, storagePerUserMb: mb === null ? null : Math.max(1, mb) })
                  }
                />
              </SettingRow>
            </Section>

            {versionsOn && (
              <Section
                heading={t('Frühere Versionen von Einträgen')}
                lead={t(
                  'Bei jeder Änderung hebt der Server den Stand davor auf, verschlüsselt wie der Eintrag. Zählt zum Speicher des Kontos.',
                )}
              >
                <SettingRow
                  label={t('Versionen pro Eintrag')}
                  description={<Explain recommended="20">{t('0 hebt keine auf.')}</Explain>}
                >
                  <NumberInput
                    label={t('Versionen pro Eintrag')}
                    min={0}
                    max={100}
                    value={versions.perItem}
                    onChange={(n) =>
                      setDraft({ ...draft, versions: { ...versions, perItem: n ?? 0 } })
                    }
                  />
                </SettingRow>
                <SettingRow
                  label={t('Versionen aufheben')}
                  description={t('So lange bleibt eine alte Version. 0: ohne Grenze.')}
                >
                  <NumberInput
                    label={t('Versionen aufheben')}
                    unit={t('Tage')}
                    min={0}
                    max={3650}
                    value={versions.days}
                    onChange={(n) =>
                      setDraft({ ...draft, versions: { ...versions, days: n ?? 0 } })
                    }
                  />
                </SettingRow>
              </Section>
            )}

            {requestsOn && (
              <Section
                heading={t('Datei-Anfragen')}
                lead={t('Links, über die jemand ohne Konto Dateien hochlädt.')}
              >
                <SettingRow
                  label={t('Anfragen pro Konto')}
                  description={t('So viele offene Datei-Anfragen hat ein Konto höchstens.')}
                >
                  <NumberInput
                    label={t('Anfragen pro Konto')}
                    min={1}
                    max={1000}
                    value={draft.fileRequests.perUser}
                    onChange={(n) => setRequests({ perUser: n ?? 0 })}
                  />
                </SettingRow>
                <SettingRow
                  label={t('Längste Laufzeit')}
                  description={t('So lange nimmt ein Link höchstens Dateien an.')}
                >
                  <NumberInput
                    label={t('Längste Laufzeit')}
                    unit={t('Tage')}
                    min={1}
                    max={365}
                    value={draft.fileRequests.maxDays}
                    onChange={(n) => setRequests({ maxDays: n ?? 0 })}
                  />
                </SettingRow>
                <SettingRow
                  label={t('Dateien pro Einsendung')}
                  description={t('So viele Dateien schickt jemand auf einmal.')}
                >
                  <NumberInput
                    label={t('Dateien pro Einsendung')}
                    min={1}
                    max={100}
                    value={draft.fileRequests.maxFiles}
                    onChange={(n) => setRequests({ maxFiles: n ?? 0 })}
                  />
                </SettingRow>
              </Section>
            )}

            {suiteOn && (
              <Section
                heading={t('Suite-Tresor (UwUSSH und UwURDP)')}
                lead={t('Was die UwU-Apps pro Konto auf diesem Server ablegen dürfen.')}
              >
                <SettingRow
                  label={t('Einträge pro Konto')}
                  description={t('Alles, was UwUSSH und UwURDP eines Kontos ablegen, zusammen.')}
                >
                  <NumberInput
                    label={t('Einträge pro Konto')}
                    min={1}
                    max={1000000}
                    value={draft.suite.maxRecords}
                    onChange={(n) => setSuite({ maxRecords: n ?? 0 })}
                  />
                </SettingRow>
                <SettingRow
                  label={t('Speicher des Suite-Tresors')}
                  description={t('Zählt auch zum Speicher des Kontos.')}
                >
                  <NumberInput
                    label={t('Speicher des Suite-Tresors')}
                    unit={t('Megabyte')}
                    min={1}
                    max={65536}
                    value={draft.suite.maxMb}
                    onChange={(n) => setSuite({ maxMb: n ?? 0 })}
                  />
                </SettingRow>
              </Section>
            )}
          </>
        );
      }}
    </SettingsTab>
  );
}
