import { useEffect, useState } from 'react';
import { vaultOverview, type Folder } from '../../lib/api';
import type { AccountInfo } from '../../lib/account';
import {
  disableTravel,
  enableTravel,
  setTravelFolders,
  travel,
  travelCodeByMail,
  type Travel,
} from '../../lib/comfort';
import { errorText } from '../../lib/errors';
import { when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { PasswordInput } from '../PasswordInput';
import { Badge } from '../ui';
import { Row, ResultLine, type Result } from './controls';

/**
 * Travel mode (docs/uwu-api.md §9): marked folders, and while it is on, their items gone from
 * every device — the official apps too, at their next sync. On from any device; off only with
 * the master password and the second step of the login.
 */
export function TravelSettings({ info }: { info: AccountInfo | null }) {
  useLanguage();
  const [state, setState] = useState<Travel | null>(null);
  const [folders, setFolders] = useState<Folder[]>([]);
  const [result, setResult] = useState<Result>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const [next, overview] = await Promise.all([travel(), vaultOverview()]);
      setState(next);
      setFolders(overview.folders);
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    }
  };
  useEffect(() => {
    void load();
  }, []);

  const run = async (work: () => Promise<Travel>, done: string) => {
    setBusy(true);
    setResult(null);
    try {
      setState(await work());
      setResult({ tone: 'info', text: done });
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  if (!state) return <ResultLine result={result} />;
  const marked = new Set(state.folderIds);
  const hiddenFolders = state.folderIds.filter((id) => !folders.some((f) => f.id === id)).length;
  const toggle = (id: string) => {
    const next = new Set(marked);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    void run(() => setTravelFolders([...next]), t('Gespeichert.'));
  };
  const providers = (info?.twoFactor ?? []).filter((kind) => [0, 1, 7].includes(kind));

  return (
    <>
      <Row
        label={t('Reisemodus')}
        description={t(
          'Markierte Ordner verschwinden samt ihren Einträgen von allen Geräten, auch aus den offiziellen Bitwarden-Apps beim nächsten Sync. Einschalten geht überall, ausschalten nur mit Master-Passwort und Zwei-Schritt-Anmeldung. Der Server kennt nur die Ordner-IDs, nie ihre Namen.',
        )}
      >
        <Badge tone={state.enabled ? 'ok' : 'neutral'}>{state.enabled ? t('An') : t('Aus')}</Badge>
      </Row>
      {state.enabled && (
        <p className="notice">
          {t('An seit {when}. {n} Einträge sind gerade ausgeblendet.', {
            when: when(state.enabledDate) ?? '',
            n: state.hiddenCount,
          })}
        </p>
      )}

      <h3 className="settings-heading">{t('Auf Reisen ausblenden')}</h3>
      {folders.length === 0 && !hiddenFolders && (
        <p className="field-hint">
          {t('Leg zuerst einen Ordner an und schieb die Einträge hinein.')}
        </p>
      )}
      <ul className="travel-folders">
        {folders.map((folder) => (
          <li key={folder.id}>
            <label className="check">
              <input
                type="checkbox"
                checked={marked.has(folder.id)}
                // While travelling, folders can be added, but none comes back.
                disabled={busy || (state.enabled && marked.has(folder.id))}
                onChange={() => toggle(folder.id)}
              />
              {folder.name}
            </label>
          </li>
        ))}
        {hiddenFolders > 0 && (
          <li className="muted">
            {hiddenFolders === 1
              ? t('1 ausgeblendeter Ordner')
              : t('{n} ausgeblendete Ordner', { n: hiddenFolders })}
          </li>
        )}
      </ul>

      {!state.enabled ? (
        <>
          {providers.length === 0 && (
            <p className="field-hint">
              {t('Der Reisemodus braucht die Zwei-Schritt-Anmeldung: Ausschalten fragt danach.')}
            </p>
          )}
          <div className="comfort-actions">
            <button
              className="primary"
              disabled={busy || marked.size === 0 || providers.length === 0}
              onClick={() => void run(enableTravel, t('Reisemodus an ✧ Gute Reise!'))}
            >
              {t('Reisemodus einschalten')}
            </button>
          </div>
        </>
      ) : (
        <DisableForm
          providers={providers}
          busy={busy}
          onDisable={(work) => void run(work, t('Reisemodus aus. Alles ist wieder da ✧'))}
        />
      )}
      <ResultLine result={result} />
    </>
  );
}

function DisableForm({
  providers,
  busy,
  onDisable,
}: {
  providers: number[];
  busy: boolean;
  onDisable: (work: () => Promise<Travel>) => void;
}) {
  const [password, setPassword] = useState('');
  const [provider, setProvider] = useState<number>(providers[0] ?? 0);
  const [code, setCode] = useState('');
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Without two-step login any more (the recovery code was used), the password alone does it.
  const needsCode = providers.length > 0;
  const label = (kind: number) =>
    kind === 0
      ? t('Authenticator-App')
      : kind === 1
        ? t('Code per Mail')
        : t('Sicherheitsschlüssel');

  const mail = async () => {
    setError(null);
    try {
      await travelCodeByMail(password);
      setSent(true);
    } catch (e) {
      setError(errorText(e));
    }
  };

  return (
    <form
      className="form travel-off"
      onSubmit={(event) => {
        event.preventDefault();
        onDisable(() => disableTravel(password, provider as 0 | 1 | 7, code));
      }}
    >
      <h3 className="settings-heading">{t('Reisemodus ausschalten')}</h3>
      <label className="field">
        <span>{t('Master-Passwort')}</span>
        <PasswordInput
          label={t('Master-Passwort')}
          value={password}
          onChange={setPassword}
          disabled={busy}
        />
      </label>
      {providers.length > 1 && (
        <label className="field">
          <span>{t('Zweiter Schritt')}</span>
          <select value={provider} onChange={(event) => setProvider(Number(event.target.value))}>
            {providers.map((kind) => (
              <option key={kind} value={kind}>
                {label(kind)}
              </option>
            ))}
          </select>
        </label>
      )}
      {needsCode && provider === 1 && (
        <button
          type="button"
          className="quiet"
          disabled={busy || !password}
          onClick={() => void mail()}
        >
          {sent ? t('Neuen Code senden') : t('Code per Mail senden')}
        </button>
      )}
      {needsCode && provider !== 7 && (
        <label className="field">
          <span>{t('Code')}</span>
          <input
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            disabled={busy}
          />
        </label>
      )}
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <div className="comfort-actions">
        <button
          type="submit"
          className="primary"
          disabled={busy || !password || (needsCode && provider !== 7 && !code.trim())}
        >
          {needsCode && provider === 7
            ? t('Mit Sicherheitsschlüssel ausschalten')
            : t('Ausschalten')}
        </button>
      </div>
    </form>
  );
}
