import { useCallback, useEffect, useState } from 'react';
import { errorText } from '../../lib/errors';
import {
  addPasskey,
  enablePasskeyUnlock,
  passkeys,
  removePasskey,
  type Passkey,
} from '../../lib/features';
import { when } from '../../lib/format';
import { N_, t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { available } from '../../lib/web/webauthn';
import { PasswordPrompt, Row } from './controls';

const PRF: Record<number, string> = {
  0: N_('Meldet an und entsperrt den Tresor.'),
  1: N_('Meldet an; kann auch entsperren – schalt es ein.'),
  2: N_('Meldet an; zum Entsperren braucht es dann das Master-Passwort.'),
};

type Dialog = { kind: 'add' } | { kind: 'unlock' } | { kind: 'remove'; passkey: Passkey } | null;

/**
 * Passkeys that log in to this web vault without the master password — and, where the passkey
 * can (the PRF extension), unlock it too.
 */
export function PasskeySettings() {
  useLanguage();
  const [list, setList] = useState<Passkey[]>([]);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [name, setName] = useState('');

  const reload = useCallback(() => {
    passkeys().then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(reload, [reload]);

  if (!available()) {
    return <p className="settings-lead">{t('Dieser Browser kann keine Passkeys.')}</p>;
  }

  return (
    <>
      <p className="settings-lead">
        {t(
          'Mit einem Passkey meldest du dich hier ohne Master-Passwort an: mit dem Fingerabdruck, dem Gesicht oder der PIN deines Geräts, oder einem Sicherheitsschlüssel. Die Browser-Erweiterung und die Apps fragen weiter nach dem Master-Passwort.',
        )}
      </p>
      {list.map((passkey) => (
        <Row
          key={passkey.id}
          label={passkey.name}
          description={`${t(PRF[passkey.prfStatus] ?? '')} ${t('Seit {when}.', { when: when(passkey.creationDate) ?? '' })}`}
        >
          {passkey.prfStatus === 1 && (
            <button onClick={() => setDialog({ kind: 'unlock' })}>
              {t('Entsperren einschalten …')}
            </button>
          )}
          <button
            className="quiet danger-text"
            onClick={() => setDialog({ kind: 'remove', passkey })}
          >
            {t('Entfernen …')}
          </button>
        </Row>
      ))}
      <Row label={t('Passkey hinzufügen')} description={t('Bis zu fünf.')}>
        <button
          className="primary"
          disabled={list.length >= 5}
          onClick={() => setDialog({ kind: 'add' })}
        >
          {t('Hinzufügen …')}
        </button>
      </Row>

      {dialog?.kind === 'add' && (
        <PasswordPrompt
          title={t('Passkey hinzufügen')}
          lead={t('Gib ihm einen Namen, dann fragt der Browser nach dem Passkey.')}
          confirm={t('Weiter')}
          onCancel={() => setDialog(null)}
          action={async (password) => {
            const unlocks = await addPasskey(name.trim() || t('Passkey'), password);
            setDialog(null);
            setName('');
            toast(
              unlocks ? t('Passkey hinzugefügt – er entsperrt auch ✧') : t('Passkey hinzugefügt ✧'),
            );
            reload();
          }}
        >
          <label className="field">
            <span>{t('Name')}</span>
            <input value={name} maxLength={50} onChange={(e) => setName(e.target.value)} />
          </label>
        </PasswordPrompt>
      )}
      {dialog?.kind === 'unlock' && (
        <PasswordPrompt
          title={t('Entsperren mit Passkey')}
          lead={t('Der Browser fragt gleich nach dem Passkey, der auch entsperren soll.')}
          confirm={t('Weiter')}
          onCancel={() => setDialog(null)}
          action={async (password) => {
            const done = await enablePasskeyUnlock(password);
            setDialog(null);
            toast(
              done
                ? t('Dieser Passkey entsperrt jetzt auch ✧')
                : t('Der Passkey hat es nicht angeboten.'),
              done ? 'info' : 'error',
            );
            reload();
          }}
        />
      )}
      {dialog?.kind === 'remove' && (
        <PasswordPrompt
          title={t('Passkey entfernen?')}
          tone="warning"
          lead={t('„{name}“ meldet danach nicht mehr an.', { name: dialog.passkey.name })}
          confirm={t('Entfernen')}
          onCancel={() => setDialog(null)}
          action={async (password) => {
            await removePasskey(dialog.passkey.id, password);
            setDialog(null);
            toast(t('Entfernt.'));
            reload();
          }}
        />
      )}
    </>
  );
}
