import { useState, type FormEvent } from 'react';
import { logout, switchAccount, unlock, type Status } from '../lib/api';
import { errorText } from '../lib/errors';
import { ago } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import { Icon } from './Icon';
import { Modal } from './Modal';
import { NyuScene } from './nyu/scenes';
import { PasswordInput } from './PasswordInput';

type Props = {
  status: Status;
  onUnlocked: (status: Status) => void;
  onLoggedOut: () => void;
  onAddAccount: () => void;
};

/**
 * The locked vault. The master password opens it right here, from the copy
 * on this device — no server needed; the sync follows in the background.
 *
 * With more than one account, the others are a click away: an account that is
 * still open shows its vault straight away, a locked one asks here.
 */
export function LockScreen({ status, onUnlocked, onLoggedOut, onAddAccount }: Props) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmLogout, setConfirmLogout] = useState(false);
  const others = status.accounts.filter((account) => !account.active);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
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
          <PasswordInput value={password} onChange={setPassword} autoFocus disabled={busy} />
        </label>
        {error && (
          <p className="form-error" role="alert">
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

        <div className="lock-accounts">
          {others.map((account) => (
            <button
              key={account.id}
              type="button"
              className="quiet lock-account-row"
              onClick={() =>
                void switchAccount(account.id).catch((e) => toast(errorText(e), 'error'))
              }
            >
              <Icon name={account.unlocked ? 'unlock' : 'lock'} size={14} />
              <span>{account.label}</span>
              <small>{account.unlocked ? t('offen') : t('gesperrt')}</small>
            </button>
          ))}
          <button type="button" className="quiet lock-account-row" onClick={onAddAccount}>
            <Icon name="plus" size={14} />
            <span>{t('Konto hinzufügen')}</span>
          </button>
        </div>
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
