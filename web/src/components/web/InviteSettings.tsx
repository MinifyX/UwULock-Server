import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Button, Icon, ICONS } from '@uwusuite/design';
import {
  invitePerson,
  myInvitations,
  withdrawInvitation,
  type MyInvitation,
  type MyInvitations,
} from '../../lib/account';
import { errorText } from '../../lib/errors';
import { when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { EmptyNote } from '../NyuStates';

/**
 * Inviting people to this server, when an admin lets everybody: up to a quota, and never as an
 * admin. The link comes back only when the server cannot mail it (or to an admin): whoever
 * holds it can register the address.
 */
export function InviteSettings() {
  useLanguage();
  const [mine, setMine] = useState<MyInvitations | null>(null);
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [made, setMade] = useState<{ email: string; link: string | null; mailed: boolean } | null>(
    null,
  );
  const load = useCallback(() => {
    myInvitations().then(setMine, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  const send = async (address: string) => {
    setBusy(true);
    try {
      setMade(await invitePerson(address));
      setEmail('');
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
    }
  };

  if (!mine) return null;
  const left = mine.quota === null ? null : Math.max(0, mine.quota - mine.used);
  return (
    <div>
      <p className="settings-lead">
        {left === null
          ? t(
              'Wer hier ein Konto haben soll, braucht eine Einladung. Du kannst so viele verschicken, wie du willst.',
            )
          : t(
              'Wer hier ein Konto haben soll, braucht eine Einladung. Du kannst noch {n} Leute einladen; offene Einladungen zählen mit, zurückgezogene nicht.',
              { n: left },
            )}
      </p>
      <form
        className="invite-form"
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          void send(email.trim());
        }}
      >
        <input
          type="email"
          required
          placeholder="name@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={busy || left === 0}
          aria-label={t('E-Mail-Adresse')}
        />
        <Button
          variant="primary"
          type="submit"
          disabled={busy || left === 0 || !email.includes('@')}
        >
          {t('Einladen')}
        </Button>
      </form>
      {made && (
        <div className="notice invite-made" role="status">
          <Icon icon={made.mailed ? ICONS.done : ICONS.invitation} />
          <span>
            {!made.link
              ? t('Die Einladung an {email} ist per Mail unterwegs.', { email: made.email })
              : made.mailed
                ? t(
                    'Die Einladung an {email} ist per Mail unterwegs. Der Link, falls sie nicht ankommt:',
                    { email: made.email },
                  )
                : t('Gib {email} diesen Link – er ist der einzige Weg zur Registrierung:', {
                    email: made.email,
                  })}
            {made.link && <code className="invite-link">{made.link}</code>}
          </span>
          {made.link && (
            <Button
              onClick={() => {
                void navigator.clipboard
                  .writeText(made.link ?? '')
                  .then(() => toast(t('Kopiert ✧'), 'info'));
              }}
            >
              {t('Kopieren')}
            </Button>
          )}
        </div>
      )}
      <h3 className="settings-heading">{t('Meine offenen Einladungen')}</h3>
      {mine.invitations.length === 0 ? (
        <EmptyNote>{t('Keine offenen Einladungen.')}</EmptyNote>
      ) : (
        <ul className="device-list">
          {mine.invitations.map((invitation: MyInvitation) => (
            <li key={invitation.email} className="device">
              <Icon icon={ICONS.invitation} size="lg" />
              <span className="device-text">
                <b>{invitation.email}</b>
                <small>
                  {invitation.expired
                    ? t('abgelaufen')
                    : t('gilt bis {when}', { when: when(invitation.expires) ?? '' })}
                </small>
              </span>
              <Button disabled={busy} onClick={() => void send(invitation.email)}>
                {t('Neu senden')}
              </Button>
              <Button
                variant="ghost"
                className="text-danger-ink"
                onClick={async () => {
                  try {
                    await withdrawInvitation(invitation.email);
                    load();
                  } catch (e) {
                    toast(errorText(e), 'error');
                  }
                }}
              >
                {t('Zurückziehen')}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
