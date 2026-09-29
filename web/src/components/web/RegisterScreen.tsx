import { useEffect, useState, type FormEvent } from 'react';
import { login, type Status } from '../../lib/api';
import {
  DEFAULT_KDFS,
  DEFAULT_RULES,
  invitation,
  passwordProblem,
  register,
  serverInfo,
  strength,
  type Invitation,
  type Kdf,
  type PasswordRules,
} from '../../lib/account';
import { errorText } from '../../lib/errors';
import { t, useLanguage } from '../../lib/i18n';
import { NyuScene } from '../nyu/scenes';
import { PasswordInput } from '../PasswordInput';
import { radioArrows } from './controls';

type Props = {
  token: string;
  email: string;
  /** Registering with a family's invitation, in place of the server's: its link's values. */
  family?: { token: string; memberId: string; name: string };
  onDone: (status: Status) => void;
};

/** How a password's strength reads, from its bits. */
function strengthLabel(bits: number): { text: string; level: number } {
  if (bits < 50) return { text: t('zu schwach'), level: 0 };
  if (bits < 65) return { text: t('geht so'), level: 1 };
  if (bits < 80) return { text: t('gut'), level: 2 };
  return { text: t('sehr gut'), level: 3 };
}

/**
 * The page an invitation's link opens: the address is known, the rest is chosen here — a
 * name, the master password, a hint. The keys are made in this browser; the server gets the
 * password's hash and the keys wrapped under it, and logs the new account in right after.
 */
export function RegisterScreen({ token, email, family, onDone }: Props) {
  useLanguage();
  const [invited, setInvited] = useState<Invitation | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [repeat, setRepeat] = useState('');
  const [hint, setHint] = useState('');
  const [kdf, setKdf] = useState<Kdf['kind']>('argon2id');
  const [bits, setBits] = useState(0);
  const [rules, setRules] = useState<PasswordRules>(DEFAULT_RULES);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // A family's link carries its own token; the server checks it with the registration.
    if (family) return;
    if (!token) {
      setProblem(t('In diesem Link fehlt die Einladung. Öffne den Link aus der Mail noch einmal.'));
      return;
    }
    invitation(token).then(setInvited, () =>
      setProblem(t('Diese Einladung gilt nicht (mehr). Bitte um eine neue.')),
    );
  }, [token, family]);

  useEffect(() => {
    void strength(password).then(setBits, () => setBits(0));
  }, [password]);

  // The server's rules for master passwords; Bitwarden's 12 characters without them.
  useEffect(() => {
    serverInfo().then(
      (info) => setRules({ ...DEFAULT_RULES, ...info.policies?.masterPassword }),
      () => undefined,
    );
  }, []);

  const address = invited?.email ?? email;
  const weak = passwordProblem(password, bits, rules);
  const mismatch = repeat.length > 0 && repeat !== password;
  const hintGivesAway = hint.trim() !== '' && password.includes(hint.trim());
  const level = strengthLabel(bits);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (password !== repeat || hintGivesAway) return;
    // The meter may still show the bits of a few keys ago: the check takes them now.
    const refused = passwordProblem(password, await strength(password).catch(() => 0), rules);
    if (refused) {
      setError(refused);
      return;
    }
    setError(null);
    setBusy(t('Nyu macht deine Schlüssel …'));
    try {
      await register({
        token,
        email: address,
        name,
        password,
        hint,
        kdf: DEFAULT_KDFS[kdf],
        family: family ? { token: family.token, memberId: family.memberId } : undefined,
      });
      setBusy(t('Meldet an …'));
      const step = await login({ kind: 'self-hosted' }, address, password);
      if (step.step === 'done') onDone(step.status);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="welcome">
      <section className="welcome-art" aria-hidden>
        <NyuScene name="keys" className="welcome-scene" />
        <p className="welcome-title">{t('Willkommen bei UwULock ✧')}</p>
        <p className="welcome-text">
          {t(
            'Dein Master-Passwort verlässt diesen Browser nie: Daraus entsteht der Schlüssel zu deinem Tresor, und niemand – auch nicht die Verwaltung dieses Servers – kann es dir zurückholen. Such dir eines aus, das du dir merken kannst.',
          )}
        </p>
      </section>

      <section className="welcome-card">
        {problem ? (
          <div className="form">
            <h1 className="card-title">{t('Konto anlegen')}</h1>
            <p className="form-error" role="alert">
              {problem}
            </p>
            <div className="form-actions">
              <span className="spacer" />
              <a className="button-link" href="/">
                {t('Zur Anmeldung')}
              </a>
            </div>
          </div>
        ) : (
          <form className="form" onSubmit={submit} aria-busy={Boolean(busy)}>
            <h1 className="card-title">{t('Konto anlegen')}</h1>
            {family && (
              <p className="dialog-lead">
                {t(
                  'Du bist in die Familie „{name}“ eingeladen. Mit dem Konto nimmst du die Einladung an; ein Eigentümer bestätigt dich danach.',
                  { name: family.name },
                )}
              </p>
            )}
            <label className="field">
              <span>{t('E-Mail-Adresse')}</span>
              <input value={address} readOnly autoComplete="username" />
            </label>
            <label className="field">
              <span>{t('Name')}</span>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
                maxLength={50}
                disabled={Boolean(busy)}
              />
            </label>
            <label className="field">
              <span>{t('Master-Passwort')}</span>
              <PasswordInput
                value={password}
                onChange={setPassword}
                autoComplete="new-password"
                autoFocus
                disabled={Boolean(busy)}
                invalid={Boolean(error) || Boolean(password && weak)}
                describedBy={
                  [password && weak ? 'register-weak' : '', error ? 'register-error' : '']
                    .filter(Boolean)
                    .join(' ') || undefined
                }
              />
              {password && (
                <span className="strength" data-level={level.level}>
                  <span className="strength-bar">
                    <span
                      style={{
                        width: `${Math.min(100, (bits / 100) * 100)}%`,
                      }}
                    />
                  </span>
                  <small>{t('Stärke: {level}', { level: level.text })}</small>
                </span>
              )}
              {password && weak && (
                <small className="field-hint" id="register-weak">
                  {weak}
                </small>
              )}
            </label>
            <label className="field">
              <span>{t('Master-Passwort wiederholen')}</span>
              <PasswordInput
                value={repeat}
                onChange={setRepeat}
                autoComplete="new-password"
                disabled={Boolean(busy)}
                invalid={mismatch}
                describedBy={mismatch ? 'register-mismatch' : undefined}
              />
              {mismatch && (
                <small className="field-hint" id="register-mismatch">
                  {t('Die beiden stimmen nicht überein.')}
                </small>
              )}
            </label>
            <label className="field">
              <span>{t('Hinweis (freiwillig)')}</span>
              <input
                value={hint}
                onChange={(e) => setHint(e.target.value)}
                maxLength={50}
                disabled={Boolean(busy)}
                aria-invalid={hintGivesAway || undefined}
                aria-describedby="register-hint"
              />
              <small className="field-hint" id="register-hint">
                {hintGivesAway
                  ? t('Der Hinweis darf nicht das Passwort verraten.')
                  : t(
                      'Kommt per Mail, wenn du „Passwort vergessen“ wählst. Er hilft nur dir beim Erinnern.',
                    )}
              </small>
            </label>
            <details className="advanced">
              <summary>{t('Schlüsselableitung')}</summary>
              <div
                className="segmented wide"
                role="radiogroup"
                aria-label={t('Schlüsselableitung')}
                onKeyDown={radioArrows}
              >
                {(['argon2id', 'pbkdf2'] as const).map((kind) => (
                  <button
                    key={kind}
                    type="button"
                    role="radio"
                    aria-checked={kdf === kind}
                    tabIndex={kdf === kind ? 0 : -1}
                    onClick={() => setKdf(kind)}
                  >
                    {kind === 'argon2id' ? 'Argon2id' : 'PBKDF2'}
                  </button>
                ))}
              </div>
              <small className="field-hint">
                {kdf === 'argon2id'
                  ? t(
                      'Argon2id mit 64 MiB: schwer zu erraten, von allen aktuellen Bitwarden-Apps verstanden.',
                    )
                  : t('PBKDF2 mit 600.000 Runden: für sehr alte Apps und Browser-Erweiterungen.')}
              </small>
            </details>
            {error && (
              <p className="form-error" role="alert" id="register-error">
                {error}
              </p>
            )}
            <div className="form-actions">
              <span className="spacer" />
              <button
                className="primary"
                type="submit"
                disabled={
                  Boolean(busy) || Boolean(weak) || password !== repeat || hintGivesAway || !invited
                }
              >
                {busy ?? t('Konto anlegen')}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}
