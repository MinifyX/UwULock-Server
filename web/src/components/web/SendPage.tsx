import { useEffect, useState, type FormEvent } from 'react';
import { errorText } from '../../lib/errors';
import {
  downloadSendFile,
  openSend,
  type OpenedSend,
  type SendProof,
  type SendRefusal,
} from '../../lib/features';
import { bytes, when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import { NyuScene } from '../nyu/scenes';
import { PasswordInput } from '../PasswordInput';
import { save } from './controls';
import { WelcomeMark } from '../TitleBar';

/** What the page asks for before the Send opens. */
type Asking = 'password' | 'email' | 'code' | null;

/**
 * A Send, for whoever has its link: `#/send/<access id>/<key>`. The key never goes to the
 * server — it is after the `#` — so the text or the file is opened here, in the browser. A Send
 * may want its password first, or — when only given addresses may open it — an address and the
 * code the server mails there.
 */
export function SendPage({ accessId, urlKey }: { accessId: string; urlKey: string }) {
  useLanguage();
  const [send, setSend] = useState<OpenedSend | null>(null);
  const [asking, setAsking] = useState<Asking>(null);
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState(false);

  const load = async (proof: SendProof = {}) => {
    setBusy(true);
    setError(null);
    try {
      const opened = await openSend(accessId, urlKey, proof);
      setSend(opened);
      setShown(!opened.hidden);
      setAsking(null);
    } catch (e) {
      const refusal = (e as Partial<SendRefusal>).kind;
      if (refusal === 'password' || refusal === 'wrong-password') {
        setAsking('password');
        if (refusal === 'wrong-password') setError(t('Das Passwort stimmt nicht.'));
      } else if (refusal === 'email') {
        setAsking('email');
      } else if (refusal === 'code' || refusal === 'wrong-code') {
        setAsking('code');
        if (refusal === 'wrong-code') setError(t('Der Code stimmt nicht oder ist abgelaufen.'));
      } else if (refusal === 'gone') {
        setAsking(null);
      } else {
        setError(errorText(e));
      }
    } finally {
      setBusy(false);
    }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => void load(), [accessId, urlKey]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (asking === 'password' && password) void load({ password });
    else if (asking === 'email' && email.trim()) void load({ email });
    else if (asking === 'code' && code.trim()) void load({ email, otp: code });
  };

  const errorLine = error && (
    <p className="form-error" role="alert">
      {error}
    </p>
  );

  const download = async () => {
    if (!send) return;
    setBusy(true);
    try {
      save(await downloadSendFile(send, urlKey), send.fileName ?? 'send');
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="welcome">
      <section className="welcome-art" aria-hidden>
        <WelcomeMark fallback={<NyuScene name="keys" className="welcome-scene" />} />
        <p className="welcome-title">{t('Jemand hat dir etwas geschickt ✧')}</p>
        <p className="welcome-text">
          {t(
            'Mit UwULock Send, Ende-zu-Ende verschlüsselt: Der Schlüssel steckt im Link, der Server kann den Inhalt nicht lesen.',
          )}
        </p>
      </section>
      <section className="welcome-card">
        {asking === 'password' ? (
          <form className="form" onSubmit={submit}>
            <h1 className="card-title">{t('Passwort nötig')}</h1>
            <p className="dialog-lead">{t('Dieser Send ist mit einem Passwort geschützt.')}</p>
            <label className="field">
              <span>{t('Passwort')}</span>
              <PasswordInput
                label={t('Passwort')}
                value={password}
                onChange={setPassword}
                autoFocus
                disabled={busy}
              />
            </label>
            {errorLine}
            <div className="form-actions">
              <span className="spacer" />
              <button className="primary" type="submit" disabled={busy || !password}>
                {busy ? t('Prüft …') : t('Öffnen')}
              </button>
            </div>
          </form>
        ) : asking === 'email' ? (
          <form className="form" onSubmit={submit}>
            <h1 className="card-title">{t('Nur für bestimmte Adressen')}</h1>
            <p className="dialog-lead">
              {t(
                'Diesen Send dürfen nur bestimmte Leute öffnen. Gib deine E-Mail-Adresse ein: Steht sie auf der Liste, bekommst du einen Code.',
              )}
            </p>
            <label className="field">
              <span>{t('E-Mail-Adresse')}</span>
              <input
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoFocus
                required
                disabled={busy}
              />
            </label>
            {errorLine}
            <div className="form-actions">
              <span className="spacer" />
              <button className="primary" type="submit" disabled={busy || !email.trim()}>
                {busy ? t('Schickt …') : t('Code schicken')}
              </button>
            </div>
          </form>
        ) : asking === 'code' ? (
          <form className="form" onSubmit={submit}>
            <h1 className="card-title">{t('Code aus der Mail')}</h1>
            <p className="dialog-lead" role="status">
              {t(
                'Steht {email} auf der Liste, ist ein Code unterwegs. Er gilt 5 Minuten. Keine Mail? Schau in den Spam oder frag den Absender.',
                { email: email.trim() },
              )}
            </p>
            <label className="field">
              <span>{t('Code')}</span>
              <input
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9 ]*"
                maxLength={10}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoFocus
                required
                disabled={busy}
              />
            </label>
            {errorLine}
            <div className="form-actions">
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  setCode('');
                  setError(null);
                  setAsking('email');
                }}
              >
                {t('Andere Adresse')}
              </button>
              <span className="spacer" />
              <button className="primary" type="submit" disabled={busy || !code.trim()}>
                {busy ? t('Prüft …') : t('Öffnen')}
              </button>
            </div>
          </form>
        ) : send ? (
          <div className="form">
            <h1 className="card-title">{send.name || t('Send')}</h1>
            {send.creator && <p className="field-hint">{t('Von {who}', { who: send.creator })}</p>}
            {send.kind === 0 ? (
              shown ? (
                <>
                  <pre className="send-text">{send.text}</pre>
                  <div className="form-actions">
                    <span className="spacer" />
                    <button
                      className="primary"
                      onClick={() =>
                        void navigator.clipboard
                          .writeText(send.text ?? '')
                          .then(() => toast(t('Kopiert ✧')))
                      }
                    >
                      <Icon name="copy" size={15} />
                      {t('Kopieren')}
                    </button>
                  </div>
                </>
              ) : (
                <button className="primary" onClick={() => setShown(true)}>
                  <Icon name="eye" size={15} />
                  {t('Text zeigen')}
                </button>
              )
            ) : (
              <div className="form-actions">
                <span className="send-file">
                  <Icon name="file" size={16} />
                  {send.fileName} {send.size && `(${bytes(Number(send.size))})`}
                </span>
                <span className="spacer" />
                <button className="primary" disabled={busy} onClick={() => void download()}>
                  <Icon name="download" size={15} />
                  {busy ? t('Lädt …') : t('Herunterladen')}
                </button>
              </div>
            )}
            {send.expirationDate && (
              <p className="field-hint">
                {t('Läuft ab {when}', { when: when(send.expirationDate) ?? '' })}
              </p>
            )}
          </div>
        ) : (
          <div className="form">
            <h1 className="card-title">{busy ? t('Öffnet …') : t('Nicht (mehr) da')}</h1>
            {error && <p className="dialog-lead">{error}</p>}
          </div>
        )}
      </section>
    </div>
  );
}
