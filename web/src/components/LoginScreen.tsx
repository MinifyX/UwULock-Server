import { useEffect, useRef, useState, type FormEvent } from 'react';
import {
  checkDeviceLogin,
  login,
  loginCancel,
  loginPasskey,
  loginSecurityKey,
  loginSendEmail,
  loginSso,
  loginTwoFactor,
  startDeviceLogin,
  type DeviceLogin,
  type LoginStep,
  type Status,
  type TwoFactorMethod,
} from '../lib/api';
import { available as webauthnAvailable } from '../lib/web/webauthn';
import { passwordHintByMail, serverInfo, type ServerInfo } from '../lib/account';
import { useRoute } from '../lib/route';
import { startSso, takeStarted } from '../lib/sso';
import { errorText } from '../lib/errors';
import { N_, t, useLanguage } from '../lib/i18n';
import { updateSettings, useSettings } from '../lib/settings';
import { Icon } from './Icon';
import { NyuScene } from './nyu/scenes';
import { PasswordInput } from './PasswordInput';
import { WelcomeMark } from './TitleBar';
import { radioArrows } from './web/controls';

type Props = {
  onDone: (status: Status) => void;
  /** Where an SSO login comes back to: the vault, or the admin portal. */
  target?: 'vault' | 'admin';
};

const METHOD_LABEL: Record<TwoFactorMethod['kind'], string> = {
  authenticator: N_('Authenticator-App'),
  email: N_('E-Mail'),
  yubikey: 'YubiKey OTP',
  duo: 'Duo',
  webauthn: 'Passkey / FIDO2',
  u2f: 'FIDO U2F',
  other: '?',
};

/**
 * The first screen: the account. Then, if the account wants it, the two-step code. The master
 * password is turned into the master key and its hash right in the page's WebAssembly; only the
 * hash goes to the server.
 */
export function LoginScreen({ onDone, target = 'vault' }: Props) {
  useLanguage();
  const route = useRoute();
  const [sso, setSso] = useState<ServerInfo['sso'] | null>(null);
  const settings = useSettings();
  const [email, setEmail] = useState(settings.lastEmail);
  const [password, setPassword] = useState('');
  const [step, setStep] = useState<LoginStep | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hintSent, setHintSent] = useState(false);
  const [device, setDevice] = useState<DeviceLogin | null>(null);

  const finish = (next: LoginStep) => {
    setPassword('');
    if (next.step === 'done') {
      updateSettings({ lastEmail: email.trim() });
      onDone(next.status);
      return;
    }
    setStep(next);
  };

  useEffect(() => {
    serverInfo().then(
      (info) => setSso(info.sso?.enabled ? info.sso : null),
      () => setSso(null),
    );
  }, []);

  // Back from the provider, through the connector page: `#/sso?code=…&state=…` (or `error=…`).
  const ssoBack = route.path === '/sso' && !route.query.get('clientId');
  useEffect(() => {
    if (!ssoBack) return;
    const code = route.query.get('code');
    const state = route.query.get('state') ?? '';
    const refusal = route.query.get('error_description') || route.query.get('error');
    history.replaceState(null, '', location.pathname);
    const verifier = takeStarted(state);
    if (!code || !verifier) {
      setError(
        refusal
          ? t('Die Anmeldung über SSO wurde abgelehnt: {reason}', { reason: refusal })
          : t('Diese Anmeldung über SSO wurde nicht in diesem Tab begonnen. Fang sie hier neu an.'),
      );
      return;
    }
    setBusy(t('Anmeldung über SSO …'));
    loginSso(code, verifier).then(
      (next) => {
        setBusy(null);
        finish(next);
      },
      (e) => {
        setBusy(null);
        setError(errorText(e));
      },
    );
    // Once, for the code in the address when the page came up.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const withSso = async () => {
    setError(null);
    setBusy(t('Weiter zu {provider} …', { provider: sso?.label ?? 'SSO' }));
    try {
      await startSso(target);
    } catch (e) {
      setBusy(null);
      setError(errorText(e));
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(t('Nyu leitet deinen Schlüssel ab …'));
    try {
      finish(await login({ kind: 'self-hosted' }, email.trim(), password));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const sendHint = async () => {
    setError(null);
    try {
      await passwordHintByMail(email);
      setHintSent(true);
    } catch (e) {
      setError(errorText(e));
    }
  };

  const passkey = async () => {
    setError(null);
    setBusy(t('Wartet auf den Passkey …'));
    try {
      finish(await loginPasskey());
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const askDevice = async () => {
    setError(null);
    try {
      setDevice(await startDeviceLogin(email));
    } catch (e) {
      setError(errorText(e));
    }
  };

  const back = () => {
    void loginCancel();
    setStep(null);
    setError(null);
  };

  return (
    <div className="welcome">
      <section className="welcome-art" aria-hidden>
        <WelcomeMark
          fallback={<NyuScene name={step ? 'keys' : 'welcome'} className="welcome-scene" />}
        />
        <p className="welcome-title">{t('Hallo! Ich bin Nyu ✧')}</p>
        <p className="welcome-text">
          {t(
            'Das ist der Web-Tresor von {server}. Dein Master-Passwort verlässt diesen Browser nie – der Server bekommt nur einen Hash davon.',
            { server: location.host },
          )}
        </p>
      </section>

      <section className="welcome-card">
        {!step && device && (
          <DeviceWait started={device} onDone={finish} onBack={() => setDevice(null)} />
        )}
        {!step && !device && (
          <form className="form" onSubmit={submit} aria-busy={Boolean(busy)}>
            <h1 className="card-title">{t('Anmelden')}</h1>
            <label className="field">
              <span>{t('E-Mail-Adresse')}</span>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="username"
                spellCheck={false}
                required
                disabled={Boolean(busy)}
              />
            </label>
            <label className="field">
              <span>{t('Master-Passwort')}</span>
              <PasswordInput
                value={password}
                onChange={setPassword}
                autoFocus={Boolean(email)}
                disabled={Boolean(busy)}
                autoComplete="current-password"
                invalid={Boolean(error)}
                describedBy={error ? 'login-error' : undefined}
              />
            </label>
            {error && (
              <p className="form-error" role="alert" id="login-error">
                {error}
              </p>
            )}
            {hintSent && (
              <p className="form-note" role="status">
                {t(
                  'Wenn es für diese Adresse ein Konto mit Hinweis gibt, ist er per Mail unterwegs.',
                )}
              </p>
            )}
            <div className="form-actions">
              <button
                type="button"
                className="quiet"
                onClick={() => void sendHint()}
                disabled={Boolean(busy) || !email.includes('@')}
              >
                {t('Passwort vergessen?')}
              </button>
              <span className="spacer" />
              <button className="primary" type="submit" disabled={Boolean(busy) || !password}>
                {busy ?? t('Anmelden')}
              </button>
            </div>
            <div className="login-other">
              {sso && (
                <button type="button" onClick={() => void withSso()} disabled={Boolean(busy)}>
                  <Icon name="shield" size={15} />
                  {t('Mit {provider} anmelden', { provider: sso.label })}
                </button>
              )}
              {webauthnAvailable() && (
                <button type="button" onClick={() => void passkey()} disabled={Boolean(busy)}>
                  <Icon name="key" size={15} />
                  {t('Mit Passkey anmelden')}
                </button>
              )}
              <button
                type="button"
                onClick={() => void askDevice()}
                disabled={Boolean(busy) || !email.includes('@')}
              >
                <Icon name="devices" size={15} />
                {t('Mit anderem Gerät anmelden')}
              </button>
            </div>
            <p className="welcome-beta">
              <Icon name="sparkles" size={14} />
              {sso
                ? t(
                    'Neu hier? Melde dich mit {provider} an, oder nimm den Link aus deiner Einladungsmail. Dein Master-Passwort legst du beim ersten Mal selbst fest.',
                    { provider: sso.label },
                  )
                : t(
                    'Neu hier? Konten gibt es auf diesem Server nur mit Einladung: Der Link aus der Einladungsmail führt zur Registrierung.',
                  )}
            </p>
          </form>
        )}

        {step?.step === 'two-factor' && (
          <TwoFactor methods={step.methods} message={step.message} onBack={back} onDone={finish} />
        )}
      </section>
    </div>
  );
}

function TwoFactor({
  methods,
  message,
  onBack,
  onDone,
}: {
  methods: TwoFactorMethod[];
  message: string | null;
  onBack: () => void;
  onDone: (step: LoginStep) => void;
}) {
  useLanguage();
  const usable = methods.filter((m) => m.supported);
  const [provider, setProvider] = useState<number | null>(usable[0]?.provider ?? null);
  const [code, setCode] = useState('');
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(message);
  const input = useRef<HTMLInputElement>(null);
  const method = usable.find((m) => m.provider === provider);

  useEffect(() => setError(message), [message]);
  useEffect(() => input.current?.focus(), [provider]);

  const withKey = async () => {
    if (!method) return;
    setBusy(true);
    setError(null);
    try {
      const next = await loginSecurityKey(method, remember);
      if (next.step === 'two-factor') setError(t('Der Schlüssel wurde nicht angenommen.'));
      else onDone(next);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (provider === null) return;
    if (method?.kind === 'webauthn') {
      await withKey();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const next = await loginTwoFactor(provider, code, remember);
      if (next.step === 'two-factor') {
        setError(t('Der Code wurde nicht angenommen.'));
        setCode('');
      } else onDone(next);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const sendEmail = async () => {
    setError(null);
    try {
      await loginSendEmail();
      setSent(true);
    } catch (e) {
      setError(errorText(e));
    }
  };

  if (!method) {
    return (
      <div className="form">
        <h1 className="card-title">{t('Zweistufige Anmeldung')}</h1>
        <p className="dialog-lead">
          {t(
            'Dein Konto verlangt eine Methode, die UwULock noch nicht kann ({methods}). Richte im Web-Tresor zusätzlich eine Authenticator-App oder E-Mail-Codes ein.',
            {
              methods: methods.map((m) => t(METHOD_LABEL[m.kind])).join(', '),
            },
          )}
        </p>
        <div className="form-actions">
          <button type="button" onClick={onBack}>
            {t('Zurück')}
          </button>
        </div>
      </div>
    );
  }

  return (
    <form className="form" onSubmit={submit}>
      <h1 className="card-title">{t('Zweistufige Anmeldung')}</h1>
      {usable.length > 1 && (
        <div
          className="segmented wide"
          role="radiogroup"
          aria-label={t('Methode')}
          onKeyDown={radioArrows}
        >
          {usable.map((m) => (
            <button
              key={m.provider}
              type="button"
              role="radio"
              aria-checked={m.provider === provider}
              tabIndex={m.provider === provider ? 0 : -1}
              onClick={() => {
                setProvider(m.provider);
                setCode('');
                setError(null);
              }}
            >
              {t(METHOD_LABEL[m.kind])}
            </button>
          ))}
        </div>
      )}
      <p className="dialog-lead">
        {method.kind === 'authenticator' &&
          t('Gib den sechsstelligen Code aus deiner Authenticator-App ein.')}
        {method.kind === 'email' &&
          (sent
            ? t('Der Code ist unterwegs an {email}.', {
                email: method.hint ?? t('deine E-Mail-Adresse'),
              })
            : t('Lass dir einen Code an {email} schicken und gib ihn hier ein.', {
                email: method.hint ?? t('deine E-Mail-Adresse'),
              }))}
        {method.kind === 'yubikey' && t('Stecke deinen YubiKey ein und tippe ihn an.')}
        {method.kind === 'webauthn' &&
          t('Nimm deinen Sicherheitsschlüssel oder Passkey; der Browser fragt gleich danach.')}
      </p>
      {methods.some((m) => !m.supported) && (
        <p className="field-hint">
          {t('Noch nicht unterstützt: {methods}.', {
            methods: methods
              .filter((m) => !m.supported)
              .map((m) => t(METHOD_LABEL[m.kind]))
              .join(', '),
          })}
        </p>
      )}
      {method.kind !== 'webauthn' && (
        <label className="field">
          <span>{t('Code')}</span>
          <input
            ref={input}
            className="code-input"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode={method.kind === 'yubikey' ? 'text' : 'numeric'}
            autoComplete="one-time-code"
            spellCheck={false}
            required
            disabled={busy}
            aria-invalid={Boolean(error) || undefined}
            aria-describedby={error ? 'two-factor-error' : undefined}
          />
        </label>
      )}
      <label className="check">
        <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
        <span>{t('Auf diesem Gerät merken')}</span>
      </label>
      {error && (
        <p className="form-error" role="alert" id="two-factor-error">
          {error}
        </p>
      )}
      <div className="form-actions">
        <button type="button" className="quiet" onClick={onBack} disabled={busy}>
          {t('Zurück')}
        </button>
        <span className="spacer" />
        {method.kind === 'email' && (
          <button type="button" onClick={() => void sendEmail()} disabled={busy}>
            {sent ? t('Nochmal senden') : t('Code senden')}
          </button>
        )}
        <button
          className="primary"
          type="submit"
          disabled={busy || (method.kind !== 'webauthn' && !code.trim())}
        >
          {busy
            ? t('Prüft …')
            : method.kind === 'webauthn'
              ? t('Schlüssel verwenden')
              : t('Weiter')}
        </button>
      </div>
    </form>
  );
}

/** Waiting for another device to let this one in, with the phrase both show. */
function DeviceWait({
  started,
  onDone,
  onBack,
}: {
  started: DeviceLogin;
  onDone: (step: LoginStep) => void;
  onBack: () => void;
}) {
  useLanguage();
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let stopped = false;
    const look = async () => {
      if (stopped) return;
      try {
        const answer = await checkDeviceLogin(started);
        if (answer === 'denied') {
          setError(t('Das andere Gerät hat abgelehnt.'));
          return;
        }
        if (answer) {
          onDone(answer);
          return;
        }
      } catch (e) {
        setError(errorText(e));
      }
      if (!stopped) window.setTimeout(() => void look(), 4000);
    };
    const first = window.setTimeout(() => void look(), 4000);
    return () => {
      stopped = true;
      window.clearTimeout(first);
    };
  }, [started, onDone]);
  return (
    <div className="form">
      <h1 className="card-title">{t('Mit anderem Gerät anmelden')}</h1>
      <p className="dialog-lead">
        {t(
          'Öffne UwULock oder die Bitwarden-App auf einem Gerät, auf dem du angemeldet bist, und bestätige dort die Anfrage. Prüf vorher, dass dort derselbe Satz steht:',
        )}
      </p>
      <p className="fingerprint">{started.fingerprint}</p>
      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : (
        <p className="field-hint" role="status">
          {t('Wartet auf die Antwort …')}
        </p>
      )}
      <div className="form-actions">
        <button type="button" className="quiet" onClick={onBack}>
          {t('Zurück')}
        </button>
      </div>
    </div>
  );
}
