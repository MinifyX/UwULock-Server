import { useEffect, useState, type FormEvent } from 'react';
import {
  DEFAULT_KDFS,
  DEFAULT_RULES,
  kdfForMinimum,
  passwordProblem,
  serverInfo,
  setInitialPassword,
  strength,
  type AccountInfo,
  type PasswordRules,
} from '../../lib/account';
import { logout, unlock, type Status } from '../../lib/api';
import { errorText } from '../../lib/errors';
import { t, useLanguage } from '../../lib/i18n';
import { forwardSso } from '../../lib/sso';
import { NyuScene } from '../nyu/scenes';
import { PasswordInput } from '../PasswordInput';

type Props = {
  status: Status;
  info: AccountInfo;
  onDone: (status: Status) => void;
};

/**
 * The first login of an account made through SSO: its owner sets the master password, which
 * opens the vault from now on. SSO only says who somebody is; the keys come from this password,
 * made here in the browser, and the server never sees it.
 */
export function SetPasswordScreen({ status, info, onDone }: Props) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [again, setAgain] = useState('');
  const [hint, setHint] = useState('');
  const [rules, setRules] = useState<PasswordRules>(DEFAULT_RULES);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const email = status.email ?? '';

  useEffect(() => {
    serverInfo().then(
      (server) => setRules(server.policies?.masterPassword ?? DEFAULT_RULES),
      () => undefined,
    );
  }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (password !== again) {
      setError(t('Die beiden Passwörter sind nicht gleich.'));
      return;
    }
    const problem = passwordProblem(password, await strength(password), rules);
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    try {
      const minimum = info.policy?.minimumKdf;
      const kdf = minimum ? kdfForMinimum(DEFAULT_KDFS.argon2id, minimum) : DEFAULT_KDFS.argon2id;
      await setInitialPassword({ email, password, hint, kdf });
      onDone(await unlock(password));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="welcome">
      <section className="welcome-art" aria-hidden>
        <NyuScene name="keys" className="welcome-scene" />
        <p className="welcome-title">{t('Willkommen ✧')}</p>
        <p className="welcome-text">
          {t(
            'Du bist über SSO angemeldet. Dein Tresor braucht jetzt noch sein Master-Passwort: Nur damit lässt er sich öffnen, und nur du kennst es – der Server nicht, und der Anmeldedienst auch nicht.',
          )}
        </p>
      </section>
      <section className="welcome-card">
        <form className="form" onSubmit={submit} aria-busy={busy}>
          <h1 className="card-title">{t('Master-Passwort festlegen')}</h1>
          <p className="form-note">{t('Konto: {email}', { email })}</p>
          <label className="field">
            <span>{t('Master-Passwort')}</span>
            <PasswordInput
              label={t('Master-Passwort')}
              value={password}
              onChange={setPassword}
              autoFocus
              disabled={busy}
              autoComplete="new-password"
            />
          </label>
          <label className="field">
            <span>{t('Master-Passwort wiederholen')}</span>
            <PasswordInput
              label={t('Master-Passwort wiederholen')}
              value={again}
              onChange={setAgain}
              disabled={busy}
              autoComplete="new-password"
            />
          </label>
          {info.passwordHints && (
            <label className="field">
              <span>{t('Hinweis (freiwillig)')}</span>
              <input value={hint} onChange={(e) => setHint(e.target.value)} disabled={busy} />
            </label>
          )}
          <p className="form-note">
            {t(
              'Vergisst du es, kann niemand deinen Tresor öffnen – auch kein Admin. Schreib es dir auf, zum Beispiel auf das Notfallblatt.',
            )}
          </p>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <div className="form-actions">
            <button type="button" className="quiet" onClick={() => void logout()} disabled={busy}>
              {t('Abmelden')}
            </button>
            <span className="spacer" />
            <button className="primary" type="submit" disabled={busy || !password || !again}>
              {busy ? t('Nyu macht deine Schlüssel …') : t('Festlegen und öffnen')}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

/**
 * Another client's SSO login, which opened the web vault at `#/sso?clientId=…` (Bitwarden's
 * browser extension, desktop app, CLI): on to the provider at once.
 */
export function SsoForward({ query }: { query: URLSearchParams }) {
  useLanguage();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    forwardSso(query).catch((e: unknown) => setError(errorText(e)));
  }, [query]);

  return (
    <div className="lock">
      <div className="lock-card">
        <NyuScene name="keys" className="lock-scene" />
        <h1 className="card-title">{t('Anmeldung über SSO')}</h1>
        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : (
          <p className="dialog-lead">{t('Weiter zum Anmeldedienst …')}</p>
        )}
      </div>
    </div>
  );
}
