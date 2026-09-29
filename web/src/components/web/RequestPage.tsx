import { useEffect, useRef, useState, type FormEvent } from 'react';
import { errorText } from '../../lib/errors';
import { bytes, when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { openRequest, requestAccess, submit, type OpenedRequest } from '../../lib/requests';
import { Icon } from '../Icon';
import { NyuScene } from '../nyu/scenes';
import { PasswordInput } from '../PasswordInput';
import { WelcomeMark } from '../TitleBar';

/**
 * A file request, for whoever has its link: `#/request/<access id>/<secret>` on the server, or
 * `/r/<access id>#<secret>` on a send domain. The secret never goes to the server; with it the
 * page opens the request's details and encrypts what is sent for its owner, here in the browser.
 */
export function RequestPage({ accessId, secret }: { accessId: string; secret: string }) {
  useLanguage();
  const [opened, setOpened] = useState<OpenedRequest | null>(null);
  const [needsPassword, setNeedsPassword] = useState(false);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [gone, setGone] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const [text, setText] = useState('');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [progress, setProgress] = useState<number | null>(null);
  const [sent, setSent] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const open = async (withPassword?: string) => {
    setBusy(true);
    setError(null);
    try {
      setOpened(await openRequest(accessId, secret, withPassword));
      setNeedsPassword(false);
    } catch (e) {
      const kind = (e as { kind?: string }).kind;
      if (kind === 'password') {
        setNeedsPassword(true);
        if (withPassword) setError(t('Das Passwort stimmt nicht.'));
      } else if ((e as { status?: number }).status === 404) setGone(true);
      else setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    void requestAccess(accessId).then(
      (access) => (access.passwordRequired ? setNeedsPassword(true) : void open()),
      (e) => ((e as { status?: number }).status === 404 ? setGone(true) : setError(errorText(e))),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessId, secret]);

  const tooLarge = opened ? files.find((file) => file.size > opened.maxFileBytes) : undefined;
  const tooMany = opened ? files.length > opened.maxFiles : false;
  const ready = opened && !tooLarge && !tooMany && (files.length > 0 || text.trim());

  const send = async (event: FormEvent) => {
    event.preventDefault();
    if (!opened || !ready || busy) return;
    setBusy(true);
    setError(null);
    setProgress(0);
    try {
      await submit(accessId, secret, opened, { text, name, email, files }, setProgress);
      setSent(true);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  const owner = opened?.owner;
  return (
    <div className="welcome">
      <section className="welcome-art" aria-hidden>
        <WelcomeMark fallback={<NyuScene name="keys" className="welcome-scene" />} />
        <p className="welcome-title">
          {owner ? t('{owner} bittet um Dateien ✧', { owner }) : t('Jemand bittet um Dateien ✧')}
        </p>
        <p className="welcome-text">
          {t(
            'Mit UwULock verschlüsselt, hier in deinem Browser: Nur wer um die Dateien bittet, kann sie öffnen – der Server nicht.',
          )}
        </p>
      </section>
      <section className="welcome-card">
        {gone ? (
          <div className="form">
            <h1 className="card-title">{t('Nicht (mehr) da')}</h1>
            <p className="dialog-lead">
              {t('Dieser Link nimmt nichts (mehr) an: abgelaufen, voll oder zurückgezogen.')}
            </p>
          </div>
        ) : sent ? (
          <div className="form">
            <h1 className="card-title">{t('Angekommen ✧')}</h1>
            <p className="dialog-lead">
              {owner
                ? t('{owner} bekommt Bescheid. Nur {owner} kann öffnen, was du geschickt hast.', {
                    owner,
                  })
                : t('Der Empfänger bekommt Bescheid. Nur er kann öffnen, was du geschickt hast.')}
            </p>
          </div>
        ) : needsPassword && !opened ? (
          <form
            className="form"
            onSubmit={(event) => {
              event.preventDefault();
              if (password) void open(password);
            }}
          >
            <h1 className="card-title">{t('Passwort nötig')}</h1>
            <p className="dialog-lead">{t('Dieser Link ist mit einem Passwort geschützt.')}</p>
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
        ) : opened ? (
          <form className="form" onSubmit={(event) => void send(event)}>
            <h1 className="card-title">{opened.title}</h1>
            {opened.note && <p className="dialog-lead multiline">{opened.note}</p>}
            {opened.maxFiles > 0 && (
              <div className="field">
                <span>
                  {t('Dateien (bis {n}, je höchstens {size})', {
                    n: opened.maxFiles,
                    size: bytes(opened.maxFileBytes),
                  })}
                </span>
                <input
                  ref={input}
                  type="file"
                  multiple
                  hidden
                  onChange={(event) => setFiles([...(event.target.files ?? [])])}
                />
                <button type="button" disabled={busy} onClick={() => input.current?.click()}>
                  <Icon name="upload" size={15} />
                  {files.length ? t('Andere Dateien wählen …') : t('Dateien wählen …')}
                </button>
                {files.length > 0 && (
                  <ul className="picked-files">
                    {files.map((file) => (
                      <li
                        key={`${file.name}-${file.size}`}
                        data-bad={file.size > opened.maxFileBytes || undefined}
                      >
                        <Icon name="file" size={14} />
                        {file.name} ({bytes(file.size)})
                      </li>
                    ))}
                  </ul>
                )}
                {tooLarge && (
                  <p className="form-error">{t('{name} ist zu groß.', { name: tooLarge.name })}</p>
                )}
                {tooMany && (
                  <p className="form-error">
                    {t('Höchstens {n} Dateien.', { n: opened.maxFiles })}
                  </p>
                )}
              </div>
            )}
            {opened.textAllowed && (
              <label className="field">
                <span>{t('Nachricht (freiwillig)')}</span>
                <textarea
                  rows={4}
                  value={text}
                  maxLength={100_000}
                  disabled={busy}
                  onChange={(e) => setText(e.target.value)}
                />
              </label>
            )}
            <div className="field-pair">
              <label className="field">
                <span>{t('Dein Name (freiwillig)')}</span>
                <input
                  value={name}
                  maxLength={100}
                  disabled={busy}
                  onChange={(e) => setName(e.target.value)}
                />
              </label>
              <label className="field">
                <span>{t('Deine E-Mail (freiwillig)')}</span>
                <input
                  type="email"
                  value={email}
                  maxLength={200}
                  disabled={busy}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </label>
            </div>
            <p className="field-hint">
              {t('Nimmt an bis {when}.', { when: when(opened.expirationDate) ?? '' })}
            </p>
            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}
            <div className="form-actions">
              <span className="spacer" />
              <button className="primary" type="submit" disabled={!ready || busy}>
                <Icon name="send" size={15} />
                {progress !== null && files.length
                  ? t('Sendet {done} von {n} …', { done: progress, n: files.length })
                  : busy
                    ? t('Verschlüsselt …')
                    : t('Verschlüsselt senden')}
              </button>
            </div>
          </form>
        ) : (
          <div className="form">
            <h1 className="card-title">{t('Öffnet …')}</h1>
            {error && <p className="dialog-lead">{error}</p>}
          </div>
        )}
      </section>
    </div>
  );
}
