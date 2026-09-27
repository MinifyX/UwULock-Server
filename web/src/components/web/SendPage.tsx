import { useEffect, useState, type FormEvent } from 'react';
import { errorText } from '../../lib/errors';
import { downloadSendFile, openSend, type OpenedSend } from '../../lib/features';
import { bytes, when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import { NyuScene } from '../nyu/scenes';
import { PasswordInput } from '../PasswordInput';
import { save } from './controls';

/**
 * A Send, for whoever has its link: `#/send/<access id>/<key>`. The key never goes to the
 * server — it is after the `#` — so the text or the file is opened here, in the browser.
 */
export function SendPage({ accessId, urlKey }: { accessId: string; urlKey: string }) {
  useLanguage();
  const [send, setSend] = useState<OpenedSend | null>(null);
  const [needsPassword, setNeedsPassword] = useState(false);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState(false);

  const load = async (withPassword?: string) => {
    setBusy(true);
    setError(null);
    try {
      const opened = await openSend(accessId, urlKey, withPassword);
      setSend(opened);
      setShown(!opened.hidden);
      setNeedsPassword(false);
    } catch (e) {
      if ((e as { kind?: string }).kind === 'password') setNeedsPassword(true);
      else setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => void load(), [accessId, urlKey]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (password) void load(password);
  };

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
        <NyuScene name="keys" className="welcome-scene" />
        <p className="welcome-title">{t('Jemand hat dir etwas geschickt ✧')}</p>
        <p className="welcome-text">
          {t(
            'Mit UwULock Send, Ende-zu-Ende verschlüsselt: Der Schlüssel steckt im Link, der Server kann den Inhalt nicht lesen.',
          )}
        </p>
      </section>
      <section className="welcome-card">
        {needsPassword ? (
          <form className="form" onSubmit={submit}>
            <h1 className="card-title">{t('Passwort nötig')}</h1>
            <p className="dialog-lead">{t('Dieser Send ist mit einem Passwort geschützt.')}</p>
            <label className="field">
              <span>{t('Passwort')}</span>
              <PasswordInput value={password} onChange={setPassword} autoFocus disabled={busy} />
            </label>
            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}
            <div className="form-actions">
              <span className="spacer" />
              <button className="primary" type="submit" disabled={busy || !password}>
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
