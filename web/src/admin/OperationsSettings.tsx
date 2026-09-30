import { useState } from 'react';
import { PasswordInput } from '../components/PasswordInput';
import {
  Button,
  ButtonRow,
  Callout,
  Checkbox,
  Field,
  FormRow,
  IconButton,
  Section,
  Select,
  SettingRow,
  TextField,
  Toggle,
} from '../components/ui';
import { ResultLine, type Result } from '../components/web/controls';
import {
  fromLocalInput,
  labelsText,
  localInput,
  parseLabels,
  randomToken,
  testLoki,
  type Loki,
  type Metrics,
  type Policies,
  type Settings,
} from '../lib/admin';
import { errorText } from '../lib/errors';
import { N_, t, useLanguage } from '../lib/i18n';
import { MAILABLE_KINDS } from '../lib/notices';
import { toast } from '../lib/toast';
import { SettingsTab, useDraft } from './draft';
import { Explain, NumberInput } from './fields';

type Props = { draft: Settings; setDraft: (next: Settings) => void };

const COMPLEXITY = [
  N_('keine Regel'),
  N_('1 – sehr schwach'),
  N_('2 – schwach'),
  N_('3 – gut (empfohlen)'),
  N_('4 – sehr gut'),
];

function setPolicy<K extends keyof Policies>(
  { draft, setDraft }: Props,
  key: K,
  change: Partial<Policies[K]>,
) {
  const policies = draft.policies;
  setDraft({ ...draft, policies: { ...policies, [key]: { ...policies[key], ...change } } });
}

/**
 * *Sicherheit → Anmeldung*: the second step for every account, remembered devices, and the
 * password hint. Rules for every account on this server; organisations have their own later.
 */
export function SignInTab() {
  useLanguage();
  return (
    <SettingsTab>
      {(props) => {
        const { draft, setDraft } = props;
        const twoFactor = draft.policies.requireTwoFactor;
        return (
          <>
            <Section
              heading={t('Zwei-Schritt-Anmeldung')}
              lead={t(
                'Außer dem Master-Passwort ein zweiter Nachweis: ein Code aus einer App, ein Sicherheitsschlüssel oder ein Passkey (2FA).',
              )}
            >
              <SettingRow
                label={t('Zwei-Schritt-Anmeldung verlangen')}
                description={
                  <Explain recommended={t('an')}>
                    {t(
                      'Bis zum Stichtag sehen Konten ohne zweiten Schritt einen Hinweis. Danach kommen sie nur noch in den Web-Tresor, um ihn einzurichten; Apps, Erweiterungen und die CLI melden sie nicht mehr an.',
                    )}
                  </Explain>
                }
              >
                <Toggle
                  label={t('Zwei-Schritt-Anmeldung verlangen')}
                  checked={twoFactor.enabled}
                  onChange={(enabled) => setPolicy(props, 'requireTwoFactor', { enabled })}
                />
              </SettingRow>
              {twoFactor.enabled && (
                <SettingRow
                  label={t('Stichtag')}
                  description={t('Leer: ab sofort. Die Zeit ist die dieses Browsers.')}
                >
                  <input
                    className="select"
                    type="datetime-local"
                    aria-label={t('Stichtag')}
                    value={localInput(twoFactor.deadline)}
                    onChange={(e) =>
                      setPolicy(props, 'requireTwoFactor', {
                        deadline: fromLocalInput(e.target.value),
                      })
                    }
                  />
                </SettingRow>
              )}
              <SettingRow
                label={t('Geräte merken')}
                description={t(
                  '„Auf diesem Gerät merken“ lässt den zweiten Schritt dort 30 Tage lang weg.',
                )}
              >
                <Toggle
                  label={t('Geräte merken')}
                  checked={draft.rememberTwoFactor}
                  onChange={(rememberTwoFactor) => setDraft({ ...draft, rememberTwoFactor })}
                />
              </SettingRow>
            </Section>
            <Section
              heading={t('Vergessenes Master-Passwort')}
              lead={t(
                'Das Master-Passwort kennt nur sein Besitzer; niemand kann es zurücksetzen, auch kein Admin.',
              )}
            >
              <SettingRow
                label={t('Passwort-Hinweise')}
                description={t(
                  'Jeder darf sich einen Hinweis zum Master-Passwort hinterlegen, der auf Wunsch per Mail kommt.',
                )}
              >
                <Toggle
                  label={t('Passwort-Hinweise')}
                  checked={draft.passwordHints}
                  onChange={(passwordHints) => setDraft({ ...draft, passwordHints })}
                />
              </SettingRow>
            </Section>
          </>
        );
      }}
    </SettingsTab>
  );
}

/**
 * *Sicherheit → Master-Passwort*: how long and how strong it has to be, and the weakest key
 * derivation the server takes.
 */
export function MasterPasswordTab() {
  useLanguage();
  return (
    <SettingsTab>
      {(props) => {
        const password = props.draft.policies.masterPassword;
        const kdf = props.draft.policies.minimumKdf;
        const setPassword = (change: Partial<Policies['masterPassword']>) =>
          setPolicy(props, 'masterPassword', change);
        const setKdf = (change: Partial<Policies['minimumKdf']>) =>
          setPolicy(props, 'minimumKdf', change);
        return (
          <>
            <Section
              heading={t('Länge und Stärke')}
              lead={t(
                'Prüfen der Web-Tresor und die Apps beim Registrieren und Ändern; der Server sieht das Passwort nie.',
              )}
            >
              <SettingRow
                label={t('Kürzestes Master-Passwort')}
                description={
                  <Explain recommended={t('12 Zeichen oder mehr')}>
                    {t('0 heißt: keine Regel.')}
                  </Explain>
                }
              >
                <NumberInput
                  label={t('Kürzestes Master-Passwort')}
                  unit={t('Zeichen')}
                  min={0}
                  max={128}
                  value={password.minLength}
                  onChange={(minLength) => setPassword({ minLength: minLength ?? 0 })}
                />
              </SettingRow>
              <SettingRow
                label={t('Stärke des Master-Passworts')}
                description={t(
                  'Wie schwer es zu erraten ist, als Stufe von 0 bis 4 (gemessen mit zxcvbn).',
                )}
              >
                <Select
                  label={t('Stärke des Master-Passworts')}
                  value={String(password.minComplexity)}
                  onChange={(score) => setPassword({ minComplexity: Number(score) })}
                  options={COMPLEXITY.map((label, score) => ({
                    value: String(score),
                    label: t(label),
                  }))}
                />
              </SettingRow>
              <SettingRow
                label={t('Auch beim Anmelden prüfen')}
                description={t(
                  'Wer ein schwächeres Passwort hat, wird in den Bitwarden-Apps nach der Anmeldung gebeten, ein neues zu wählen.',
                )}
              >
                <Toggle
                  label={t('Auch beim Anmelden prüfen')}
                  checked={password.enforceOnLogin}
                  onChange={(enforceOnLogin) => setPassword({ enforceOnLogin })}
                />
              </SettingRow>
            </Section>
            <Section
              heading={t('Schutz vor Durchprobieren')}
              lead={t(
                'Aus dem Master-Passwort wird der Schlüssel des Tresors gerechnet, absichtlich langsam: So dauert es ewig, Passwörter durchzuprobieren. Das Verfahren heißt Schlüsselableitung (KDF) – Argon2id (empfohlen) oder PBKDF2. Hier steht das Mindeste, was der Server annimmt; Konten darunter funktionieren weiter und bekommen im Web-Tresor einen Knopf zum Umstellen.',
              )}
            >
              <FormRow min="narrow">
                <Field label={t('PBKDF2: Runden')} hint={<Explain recommended="600.000" />}>
                  <input
                    type="number"
                    min={100000}
                    max={2000000}
                    step={50000}
                    value={kdf.pbkdf2Iterations}
                    onChange={(e) => setKdf({ pbkdf2Iterations: Number(e.target.value) })}
                  />
                </Field>
                <Field label={t('Argon2id: Speicher in MiB')} hint={<Explain recommended="64" />}>
                  <input
                    type="number"
                    min={15}
                    max={1024}
                    value={kdf.argon2Memory}
                    onChange={(e) => setKdf({ argon2Memory: Number(e.target.value) })}
                  />
                </Field>
                <Field label={t('Argon2id: Durchläufe')} hint={<Explain recommended="3" />}>
                  <input
                    type="number"
                    min={2}
                    max={10}
                    value={kdf.argon2Iterations}
                    onChange={(e) => setKdf({ argon2Iterations: Number(e.target.value) })}
                  />
                </Field>
                <Field label={t('Argon2id: Threads')} hint={<Explain recommended="4" />}>
                  <input
                    type="number"
                    min={1}
                    max={16}
                    value={kdf.argon2Parallelism}
                    onChange={(e) => setKdf({ argon2Parallelism: Number(e.target.value) })}
                  />
                </Field>
              </FormRow>
            </Section>
          </>
        );
      }}
    </SettingsTab>
  );
}

/**
 * *E-Mail → Mails an Nutzer*: the mail about a new device, and which security notices go out
 * by mail; all of them stay in each account's list.
 */
export function UserMailsTab() {
  useLanguage();
  return (
    <SettingsTab>
      {({ draft, setDraft }) => {
        const off = new Set(draft.securityNotices.mailOff);
        const toggle = (kind: string, mailed: boolean) => {
          const next = new Set(off);
          if (mailed) next.delete(kind);
          else next.add(kind);
          setDraft({ ...draft, securityNotices: { mailOff: [...next] } });
        };
        return (
          <>
            <Section
              heading={t('Neues Gerät')}
              lead={t('Eine Mail an das Konto, damit niemand sich unbemerkt anmeldet.')}
            >
              <SettingRow
                label={t('Mail bei neuem Gerät')}
                description={
                  <Explain recommended={t('an')}>
                    {t('Wenn sich ein Konto auf einem Gerät zum ersten Mal anmeldet.')}
                  </Explain>
                }
              >
                <Toggle
                  label={t('Mail bei neuem Gerät')}
                  checked={draft.newDeviceMail}
                  onChange={(newDeviceMail) => setDraft({ ...draft, newDeviceMail })}
                />
              </SettingRow>
            </Section>
            <Section
              heading={t('Sicherheitshinweise per Mail')}
              lead={t(
                'Was auf einem Konto passiert, steht im Web-Tresor unter Einstellungen → Sicherheit. Angehakte Arten kommen außerdem per Mail – gesammelt, höchstens eine Mail in 15 Minuten.',
              )}
            >
              <div className="check-grid" role="group" aria-label={t('Per Mail')}>
                {MAILABLE_KINDS.map(({ kind, label }) => (
                  <Checkbox
                    key={kind}
                    label={t(label)}
                    checked={!off.has(kind)}
                    onChange={(mailed) => toggle(kind, mailed)}
                  />
                ))}
              </div>
              {!draft.newDeviceMail && !off.has('newDevice') && (
                <p className="field-hint">
                  {t(
                    '„Mail bei neuem Gerät“ ist oben aus: neue Geräte kommen trotzdem nicht per Mail.',
                  )}
                </p>
              )}
            </Section>
          </>
        );
      }}
    </SettingsTab>
  );
}

/** *Sicherheit → Admin-Portal*: the networks the portal answers from. */
export function AdminAccessTab() {
  useLanguage();
  return (
    <SettingsTab>
      {({ draft, setDraft, generation }) => (
        <NetworkSettings key={`networks-${generation}`} draft={draft} setDraft={setDraft} />
      )}
    </SettingsTab>
  );
}

function NetworkSettings({ draft, setDraft }: Props) {
  useLanguage();
  const [text, setText] = useState(draft.adminNetworks.join('\n'));
  return (
    <Section
      heading={t('Wer das Admin-Portal erreicht')}
      lead={t(
        'Nur aus diesen Netzen ist das Admin-Portal erreichbar, von überall sonst antwortet es mit „nicht gefunden“. Leer: von überall. Tresor, Sends und Apps betrifft das nicht.',
      )}
    >
      <Field
        label={t('Netze, eines pro Zeile (IP-Adressen oder CIDR)')}
        hint={t(
          "Wer sich aussperrt, kommt auf dem Server wieder herein mit: uwulock-server settings set adminNetworks '[]'",
        )}
      >
        <textarea
          className="mono"
          rows={3}
          value={text}
          placeholder={'192.0.2.0/24\n2001:db8::/32'}
          spellCheck={false}
          onChange={(e) => {
            setText(e.target.value);
            const networks = e.target.value
              .split('\n')
              .map((line) => line.trim())
              .filter(Boolean);
            setDraft({ ...draft, adminNetworks: networks });
          }}
        />
      </Field>
      <Callout tone="warning">
        {t(
          'Das Netz, aus dem du gerade kommst, muss darin stehen: Sonst würdest du dich aussperren, und der Server speichert es nicht.',
        )}
      </Callout>
    </Section>
  );
}

/** *System → Überwachung*: metrics for Prometheus and the log lines to Loki. */
export function MonitoringTab() {
  useLanguage();
  const value = useDraft();
  return (
    <SettingsTab>
      {({ draft, setDraft, generation }) => (
        <>
          <MetricsSettings draft={draft} setDraft={setDraft} />
          <LokiSettings
            key={`loki-${generation}`}
            draft={draft}
            setDraft={setDraft}
            dirty={value?.dirty ?? false}
          />
        </>
      )}
    </SettingsTab>
  );
}

/** Prometheus metrics at /metrics: with a token, or on an address of their own. */
function MetricsSettings({ draft, setDraft }: Props) {
  useLanguage();
  const metrics = draft.metrics;
  const set = (change: Partial<Metrics>) =>
    setDraft({ ...draft, metrics: { ...metrics, ...change } });
  const fresh = metrics.token ? metrics.token : null;
  return (
    <Section
      heading={t('Metriken für Prometheus')}
      lead={t(
        'Zahlen unter /metrics: Anfragen, Anmeldungen, Backups, Zertifikat. Nie Adressen, Namen oder IPs. Dafür braucht es einen Token oder eine eigene Adresse, sonst könnte sie jeder lesen.',
      )}
    >
      <SettingRow
        label={t('Metriken anbieten')}
        description={t('Für ein Monitoring wie Prometheus und Grafana.')}
      >
        <Toggle
          label={t('Metriken anbieten')}
          checked={metrics.enabled}
          onChange={(enabled) => set({ enabled })}
        />
      </SettingRow>
      <SettingRow
        label={t('Token')}
        description={
          fresh
            ? t('Neu, wird mit dem Speichern gültig. Er wird nur jetzt angezeigt: kopiere ihn.')
            : metrics.token === ''
              ? t('Wird mit dem Speichern entfernt.')
              : metrics.tokenSet
                ? t('Ein Token ist gespeichert. Prometheus schickt ihn als Bearer-Token.')
                : t('Noch keiner.')
        }
      >
        {metrics.tokenSet && metrics.token !== '' && !fresh && (
          <Button variant="quiet-danger" onClick={() => set({ token: '' })} data-secondary>
            {t('Entfernen')}
          </Button>
        )}
        <Button onClick={() => set({ token: randomToken() })}>{t('Token erzeugen')}</Button>
      </SettingRow>
      {fresh && (
        <div className="copy-field">
          <code className="mono">{fresh}</code>
          <IconButton
            icon="copy"
            label={t('Kopieren')}
            onClick={() =>
              void navigator.clipboard.writeText(fresh).then(() => toast(t('Kopiert ✧')))
            }
          />
        </div>
      )}
      <SettingRow
        label={t('Eigene Adresse')}
        description={t(
          'Zum Beispiel 127.0.0.1:9100: Dort gibt es /metrics ohne Token, auf der öffentlichen Adresse dann gar nicht. Leer: auf der öffentlichen Adresse, mit Token.',
        )}
      >
        <input
          className="select"
          value={metrics.listen ?? ''}
          placeholder="127.0.0.1:9100"
          aria-label={t('Eigene Adresse')}
          spellCheck={false}
          onChange={(e) => set({ listen: e.target.value.trim() ? e.target.value : null })}
        />
      </SettingRow>
    </Section>
  );
}

/** The server's log lines pushed to a Loki. */
function LokiSettings({ draft, setDraft, dirty }: Props & { dirty: boolean }) {
  useLanguage();
  const loki = draft.loki;
  const set = (change: Partial<Loki>) => setDraft({ ...draft, loki: { ...loki, ...change } });
  const [text, setText] = useState(labelsText(loki.labels));
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  const bad = parseLabels(text).bad;
  return (
    <Section
      heading={t('Logs an Loki')}
      lead={t(
        'Dieselben Zeilen wie im Log, als JSON an Grafana Loki geschickt, gesammelt jede Sekunde. Ist Loki länger weg, werden Zeilen verworfen und gezählt.',
      )}
    >
      <SettingRow
        label={t('Logs an Loki schicken')}
        description={t('Zum Suchen und Aufheben der Logs außerhalb des Servers.')}
      >
        <Toggle
          label={t('Logs an Loki schicken')}
          checked={loki.enabled}
          onChange={(enabled) => set({ enabled })}
        />
      </SettingRow>
      <FormRow min="wide">
        <TextField
          label={t('Adresse')}
          value={loki.url}
          onChange={(url) => set({ url })}
          placeholder="https://loki.example.com"
          spellCheck={false}
        />
        <TextField
          label={t('Mandant (freiwillig)')}
          value={loki.tenant ?? ''}
          onChange={(tenant) => set({ tenant: tenant || null })}
          spellCheck={false}
        />
      </FormRow>
      <FormRow min="wide">
        <TextField
          label={t('Benutzername (freiwillig)')}
          value={loki.username ?? ''}
          onChange={(username) => set({ username: username || null })}
          autoComplete="off"
        />
        <Field
          label={t('Passwort')}
          hint={
            loki.passwordSet && !loki.password
              ? t('Ein Passwort ist gespeichert. Leer lassen behält es.')
              : undefined
          }
        >
          <PasswordInput
            value={loki.password ?? ''}
            onChange={(password) => set({ password: password || null })}
            autoComplete="new-password"
          />
        </Field>
      </FormRow>
      <Field
        label={t('Labels, eines pro Zeile als name=wert')}
        hint={
          bad.length
            ? t('Kein Label: {lines}', { lines: bad.join(', ') })
            : t('Nie etwas über Nutzer: Labels sieht jeder, der die Logs sieht.')
        }
        hintTone={bad.length ? 'warn' : 'default'}
      >
        <textarea
          className="mono"
          rows={2}
          value={text}
          spellCheck={false}
          onChange={(e) => {
            setText(e.target.value);
            set({ labels: parseLabels(e.target.value).labels });
          }}
        />
      </Field>
      <ButtonRow>
        <Button
          disabled={busy || !loki.url.trim()}
          title={dirty ? t('Prüft die Angaben hier, auch ungespeichert.') : undefined}
          onClick={async () => {
            setBusy(true);
            setResult(null);
            try {
              await testLoki(loki);
              setResult({ tone: 'info', text: t('Loki hat eine Testzeile angenommen ✧') });
            } catch (e) {
              setResult({ tone: 'error', text: errorText(e) });
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? t('Prüft …') : t('Verbindung testen')}
        </Button>
      </ButtonRow>
      <ResultLine result={result} />
    </Section>
  );
}
