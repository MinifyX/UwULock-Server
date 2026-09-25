import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Icon } from '../components/Icon';
import { invitations, invite, uninvite, type Invitation } from '../lib/admin';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';

/**
 * Nobody registers without an invitation. One goes out by mail when the server can send any;
 * the link is shown either way, to pass on by hand.
 */
export function Invitations() {
  useLanguage();
  const [list, setList] = useState<Invitation[] | null>(null);
  const [email, setEmail] = useState('');
  const [admin, setAdmin] = useState(false);
  const [busy, setBusy] = useState(false);
  const [made, setMade] = useState<{ email: string; link: string; mailed: boolean } | null>(null);
  const load = useCallback(() => {
    invitations().then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      setMade(await invite(email.trim(), admin));
      setEmail('');
      setAdmin(false);
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
    }
  };

  const again = async (invitation: Invitation) => {
    try {
      setMade(await invite(invitation.email, invitation.admin));
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  return (
    <>
      <form className="invite-form" onSubmit={submit}>
        <input
          type="email"
          required
          placeholder="name@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={busy}
          aria-label={t('E-Mail-Adresse')}
        />
        <label className="check">
          <input type="checkbox" checked={admin} onChange={(e) => setAdmin(e.target.checked)} />
          <span>{t('als Admin')}</span>
        </label>
        <button className="primary" type="submit" disabled={busy || !email.includes('@')}>
          {t('Einladen')}
        </button>
      </form>
      {made && (
        <div className="notice invite-made" role="status">
          <Icon name={made.mailed ? 'check' : 'sparkles'} size={16} />
          <span>
            {made.mailed
              ? t(
                  'Die Einladung an {email} ist per Mail unterwegs. Der Link, falls sie nicht ankommt:',
                  { email: made.email },
                )
              : t('Gib {email} diesen Link – er ist der einzige Weg zur Registrierung:', {
                  email: made.email,
                })}
            <code className="invite-link">{made.link}</code>
          </span>
          <button
            onClick={() => {
              void navigator.clipboard
                .writeText(made.link)
                .then(() => toast(t('Kopiert ✧'), 'info'));
            }}
          >
            {t('Kopieren')}
          </button>
        </div>
      )}
      <table className="admin-table">
        <thead>
          <tr>
            <th>{t('Adresse')}</th>
            <th>{t('Eingeladen von')}</th>
            <th>{t('Gilt bis')}</th>
            <th aria-label={t('Aktionen')} />
          </tr>
        </thead>
        <tbody>
          {list?.map((invitation) => (
            <tr key={invitation.email} data-disabled={invitation.expired || undefined}>
              <td>
                <b>{invitation.email}</b>
                <span className="badges">
                  {invitation.admin && <span className="badge">{t('Admin')}</span>}
                  {invitation.expired && <span className="badge alarm">{t('abgelaufen')}</span>}
                </span>
              </td>
              <td>{invitation.invitedBy ?? t('Kommandozeile')}</td>
              <td>{when(invitation.expires)}</td>
              <td className="row-actions">
                <button onClick={() => void again(invitation)}>{t('Neu senden')}</button>
                <button
                  className="danger"
                  onClick={async () => {
                    try {
                      await uninvite(invitation.email);
                      load();
                    } catch (e) {
                      toast(errorText(e), 'error');
                    }
                  }}
                >
                  {t('Zurückziehen')}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {list?.length === 0 && <p className="empty-note">{t('Keine offenen Einladungen.')}</p>}
    </>
  );
}
