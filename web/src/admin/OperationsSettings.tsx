import { useState } from 'react';
import { PasswordInput } from '../components/PasswordInput';
import { ResultLine, Row, Toggle, type Result } from '../components/web/controls';
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

type Props = { draft: Settings; setDraft: (next: Settings) => void };

const COMPLEXITY = [
  N_('keine Regel'),
  N_('1 – sehr schwach'),
  N_('2 – schwach'),
  N_('3 – gut'),
  N_('4 – sehr gut'),
];

/** Rules for every account: two-step login, the weakest key derivation, the master password. */
export function PolicySettings({ draft, setDraft }: Props) {
  useLanguage();
  const policies = draft.policies;
  const set = <K extends keyof Policies>(key: K, change: Partial<Policies[K]>) =>
    setDraft({ ...draft, policies: { ...policies, [key]: { ...policies[key], ...change } } });
  const twoFactor = policies.requireTwoFactor;
  const kdf = policies.minimumKdf;
  const password = policies.masterPassword;
  return (
    <>
      <h2 className="settings-heading">{t('Richtlinien')}</h2>
      <p className="settings-lead">
        {t(
          'Gelten für jedes Konto auf diesem Server. Organisationen haben später ihre eigenen Richtlinien.',
        )}
      </p>
      <Row
        label={t('Zwei-Schritt-Anmeldung verlangen')}
        description={t(
          'Bis zum Stichtag sehen Konten ohne zweiten Schritt einen Hinweis im Web-Tresor. Danach kommen sie nur noch in den Web-Tresor, um ihn einzurichten – Apps, Erweiterungen und die CLI melden sie nicht mehr an.',
        )}
      >
        <Toggle
          label={t('Zwei-Schritt-Anmeldung verlangen')}
          checked={twoFactor.enabled}
          onChange={(enabled) => set('requireTwoFactor', { enabled })}
        />
      </Row>
      {twoFactor.enabled && (
        <Row
          label={t('Stichtag')}
          description={t('Leer: ab sofort. Die Zeit ist die dieses Browsers.')}
        >
          <input
            className="select"
            type="datetime-local"
            aria-label={t('Stichtag')}
            value={localInput(twoFactor.deadline)}
            onChange={(e) => set('requireTwoFactor', { deadline: fromLocalInput(e.target.value) })}
          />
        </Row>
      )}

      <Row
        label={t('Schwächste Schlüsselableitung')}
        description={t(
          'Schwächere nimmt der Server bei Registrierung und Änderung nicht an. Konten, die schon darunter liegen, funktionieren weiter und bekommen im Web-Tresor einen Knopf zum Umstellen.',
        )}
      />
      <div className="field-grid four">
        <label className="field">
          <span>{t('PBKDF2-Runden')}</span>
          <input
            type="number"
            min={100000}
            max={2000000}
            step={50000}
            value={kdf.pbkdf2Iterations}
            onChange={(e) => set('minimumKdf', { pbkdf2Iterations: Number(e.target.value) })}
          />
        </label>
        <label className="field">
          <span>{t('Argon2id-Speicher (MiB)')}</span>
          <input
            type="number"
            min={15}
            max={1024}
            value={kdf.argon2Memory}
            onChange={(e) => set('minimumKdf', { argon2Memory: Number(e.target.value) })}
          />
        </label>
        <label className="field">
          <span>{t('Argon2id-Durchläufe')}</span>
          <input
            type="number"
            min={2}
            max={10}
            value={kdf.argon2Iterations}
            onChange={(e) => set('minimumKdf', { argon2Iterations: Number(e.target.value) })}
          />
        </label>
        <label className="field">
          <span>{t('Argon2id-Threads')}</span>
          <input
            type="number"
            min={1}
            max={16}
            value={kdf.argon2Parallelism}
            onChange={(e) => set('minimumKdf', { argon2Parallelism: Number(e.target.value) })}
          />
        </label>
      </div>

      <Row
        label={t('Kürzestes Master-Passwort')}
        description={t(
          'Prüfen der Web-Tresor und die Apps beim Registrieren und Ändern; der Server sieht das Passwort nie.',
        )}
      >
        <input
          className="select narrow-number"
          type="number"
          min={0}
          max={128}
          aria-label={t('Kürzestes Master-Passwort')}
          value={password.minLength}
          onChange={(e) => set('masterPassword', { minLength: Number(e.target.value) })}
        />
      </Row>
      <Row
        label={t('Stärke des Master-Passworts')}
        description={t('Eine Stufe von 0 bis 4, wie zxcvbn sie misst.')}
      >
        <select
          className="select"
          aria-label={t('Stärke des Master-Passworts')}
          value={password.minComplexity}
          onChange={(e) => set('masterPassword', { minComplexity: Number(e.target.value) })}
        >
          {COMPLEXITY.map((label, score) => (
            <option key={score} value={score}>
              {t(label)}
            </option>
          ))}
        </select>
      </Row>
      <Row
        label={t('Auch beim Anmelden prüfen')}
        description={t(
          'Die offiziellen Bitwarden-Apps lassen dann jemanden mit schwächerem Passwort nach der Anmeldung ein neues wählen.',
        )}
      >
        <Toggle
          label={t('Auch beim Anmelden prüfen')}
          checked={password.enforceOnLogin}
          onChange={(enforceOnLogin) => set('masterPassword', { enforceOnLogin })}
        />
      </Row>
    </>
  );
}

/** Which security notices go out by mail; all of them stay in each account's list. */
export function NoticeMailSettings({ draft, setDraft }: Props) {
  useLanguage();
  const off = new Set(draft.securityNotices.mailOff);
  const toggle = (kind: string, mailed: boolean) => {
    const next = new Set(off);
    if (mailed) next.delete(kind);
    else next.add(kind);
    setDraft({ ...draft, securityNotices: { mailOff: [...next] } });
  };
  return (
    <>
      <h2 className="settings-heading">{t('Sicherheitshinweise')}</h2>
      <p className="settings-lead">
        {t(
          'Was auf einem Konto passiert, steht im Web-Tresor unter Einstellungen → Sicherheit. Angehakte Arten kommen außerdem per Mail – gesammelt, höchstens eine Mail in 15 Minuten.',
        )}
      </p>
      <div className="check-grid" role="group" aria-label={t('Per Mail')}>
        {MAILABLE_KINDS.map(({ kind, label }) => (
          <label key={kind} className="check">
            <input
              type="checkbox"
              checked={!off.has(kind)}
              onChange={(e) => toggle(kind, e.target.checked)}
            />
            <span>{t(label)}</span>
          </label>
        ))}
      </div>
      {!draft.newDeviceMail && !off.has('newDevice') && (
        <p className="field-hint">
          {t('„Mail bei neuem Gerät“ ist oben aus: neue Geräte kommen trotzdem nicht per Mail.')}
        </p>
      )}
    </>
  );
}

/** Where the admin portal answers from. */
export function NetworkSettings({ draft, setDraft }: Props) {
  useLanguage();
  const [text, setText] = useState(draft.adminNetworks.join('\n'));
  return (
    <>
      <h2 className="settings-heading">{t('Zugang zum Admin-Portal')}</h2>
      <p className="settings-lead">
        {t(
          'Nur aus diesen Netzen ist das Admin-Portal erreichbar, von überall sonst antwortet es mit „nicht gefunden“. Leer: von überall. Tresor, Sends und Apps betrifft das nicht.',
        )}
      </p>
      <label className="field">
        <span>{t('Netze, eines pro Zeile')}</span>
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
        <small className="field-hint">
          {t(
            "Wer sich aussperrt, kommt auf dem Server wieder herein mit: uwulock-server settings set adminNetworks '[]'",
          )}
        </small>
      </label>
    </>
  );
}

/** Prometheus metrics at /metrics: with a token, or on an address of their own. */
export function MetricsSettings({ draft, setDraft }: Props) {
  useLanguage();
  const metrics = draft.metrics;
  const set = (change: Partial<Metrics>) =>
    setDraft({ ...draft, metrics: { ...metrics, ...change } });
  const fresh = metrics.token ? metrics.token : null;
  return (
    <>
      <h2 className="settings-heading">{t('Metriken')}</h2>
      <p className="settings-lead">
        {t(
          'Zahlen für Prometheus unter /metrics: Anfragen, Anmeldungen, Backups, Zertifikat. Nie Adressen, Namen oder IPs. Dafür braucht es einen Token oder eine eigene Adresse, sonst könnte sie jeder lesen.',
        )}
      </p>
      <Row label={t('Metriken anbieten')}>
        <Toggle
          label={t('Metriken anbieten')}
          checked={metrics.enabled}
          onChange={(enabled) => set({ enabled })}
        />
      </Row>
      <Row
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
        <span className="inline-form">
          {metrics.tokenSet && metrics.token !== '' && !fresh && (
            <button onClick={() => set({ token: '' })} data-secondary>
              {t('Entfernen')}
            </button>
          )}
          <button onClick={() => set({ token: randomToken() })}>{t('Token erzeugen')}</button>
        </span>
      </Row>
      {fresh && (
        <div className="copy-field">
          <code className="mono">{fresh}</code>
          <button
            className="icon-button"
            aria-label={t('Kopieren')}
            onClick={() =>
              void navigator.clipboard.writeText(fresh).then(() => toast(t('Kopiert ✧')))
            }
          >
            ⧉
          </button>
        </div>
      )}
      <Row
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
      </Row>
    </>
  );
}

/** The server's log lines pushed to a Loki. */
export function LokiSettings({ draft, setDraft, dirty }: Props & { dirty: boolean }) {
  useLanguage();
  const loki = draft.loki;
  const set = (change: Partial<Loki>) => setDraft({ ...draft, loki: { ...loki, ...change } });
  const [text, setText] = useState(labelsText(loki.labels));
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  const bad = parseLabels(text).bad;
  return (
    <>
      <h2 className="settings-heading">{t('Logs an Loki')}</h2>
      <p className="settings-lead">
        {t(
          'Dieselben Zeilen wie im Log, als JSON an Loki geschickt, gesammelt jede Sekunde. Ist Loki länger weg, werden Zeilen verworfen und gezählt.',
        )}
      </p>
      <Row label={t('Logs an Loki schicken')}>
        <Toggle
          label={t('Logs an Loki schicken')}
          checked={loki.enabled}
          onChange={(enabled) => set({ enabled })}
        />
      </Row>
      <div className="field-grid wide">
        <label className="field">
          <span>{t('Adresse')}</span>
          <input
            value={loki.url}
            onChange={(e) => set({ url: e.target.value })}
            placeholder="https://loki.example.com"
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>{t('Mandant (freiwillig)')}</span>
          <input
            value={loki.tenant ?? ''}
            onChange={(e) => set({ tenant: e.target.value || null })}
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>{t('Benutzername (freiwillig)')}</span>
          <input
            value={loki.username ?? ''}
            onChange={(e) => set({ username: e.target.value || null })}
            autoComplete="off"
          />
        </label>
        <label className="field">
          <span>{t('Passwort')}</span>
          <PasswordInput
            value={loki.password ?? ''}
            onChange={(password) => set({ password: password || null })}
            autoComplete="new-password"
          />
          {loki.passwordSet && !loki.password && (
            <small className="field-hint">
              {t('Ein Passwort ist gespeichert. Leer lassen behält es.')}
            </small>
          )}
        </label>
        <label className="field span-2">
          <span>{t('Labels, eines pro Zeile als name=wert')}</span>
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
          <small className="field-hint" data-tone={bad.length ? 'warn' : undefined}>
            {bad.length
              ? t('Kein Label: {lines}', { lines: bad.join(', ') })
              : t('Nie etwas über Nutzer: Labels sieht jeder, der die Logs sieht.')}
          </small>
        </label>
      </div>
      <div className="form-actions">
        <button
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
        </button>
      </div>
      <ResultLine result={result} />
    </>
  );
}
