import { useState, type FormEvent } from 'react';
import { logout, unlock, type Status } from '../lib/api';
import { errorText } from '../lib/errors';
import { ago } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { Modal } from './Modal';
import { NyuScene } from './nyu/scenes';
import { PasswordInput } from './PasswordInput';

type Props = {
  status: Status;
  onUnlocked: (status: Status) => void;
  onLoggedOut: () => void;
};

/**
 * The locked vault. The master password opens it right here, from the copy
 * on this device — no server needed; the sync follows in the background.
 *
 * The web vault is this server's, for one account at a time: no other account and no other
 * server to switch to (the desktop app has those).
 */
export function LockScreen({ status, onUnlocked, onLoggedOut }: Props) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmLogout, setConfirmLogout] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const next = await unlock(password);
      setPassword('');
      onUnlocked(next);
    } catch (e) {
      setError(errorText(e));
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="lock">
      <form className="lock-card" onSubmit={submit} aria-busy={busy}>
        <NyuScene name="sleepy" className="lock-scene" />
        <h1 className="card-title">{t('Dein Tresor ist gesperrt')}</h1>
        <p className="lock-account">
          <b>{status.email}</b>
          <span>
            {status.label !== status.server ? `${status.label} · ` : ''}
            {status.server}
          </span>
        </p>
        <label className="field">
          <span>{t('Master-Passwort')}</span>
          <PasswordInput
            label={t('Master-Passwort')}
            value={password}
            onChange={setPassword}
            autoFocus
            disabled={busy}
            invalid={Boolean(error)}
            describedBy={error ? 'lock-error' : undefined}
          />
        </label>
        {error && (
          <p className="form-error" role="alert" id="lock-error">
            {error}
          </p>
        )}
        <button className="primary lock-button" type="submit" disabled={busy || !password}>
          {busy ? t('Entsperrt …') : t('Entsperren')}
        </button>
        <p className="lock-meta">
          {t('Zuletzt synchronisiert: {when}', { when: ago(status.lastSync) })}
          {' · '}
          <button type="button" className="link-button" onClick={() => setConfirmLogout(true)}>
            {t('Abmelden')}
          </button>
        </p>
      </form>

      {confirmLogout && (
        <Modal
          title={t('Von diesem Gerät abmelden?')}
          onCancel={() => setConfirmLogout(false)}
          footer={
            <>
              <span className="spacer" />
              <button
                className="danger"
                data-secondary
                onClick={async () => {
                  try {
                    await logout();
                    onLoggedOut();
                  } catch (e) {
                    setError(errorText(e));
                  }
                  setConfirmLogout(false);
                }}
              >
                {t('Abmelden')}
              </button>
              <button className="primary" data-autofocus onClick={() => setConfirmLogout(false)}>
                {t('Abbrechen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Die Anmeldung und die verschlüsselte Kopie des Tresors werden von diesem Gerät gelöscht. Dein Tresor auf dem Server bleibt, wie er ist.',
            )}
          </p>
        </Modal>
      )}
    </div>
  );
}
