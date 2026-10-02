import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Badge, Button, Callout, Checkbox, Section, Table, TextField } from '../components/ui';
import { invitations, invite, uninvite, type Invitation } from '../lib/admin';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import { EmptyNote } from '../components/NyuStates';

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
      <Section
        heading={t('Jemanden einladen')}
        lead={t(
          'Die Einladung geht per Mail, wenn ein Mailserver eingerichtet ist. Den Link bekommst du in jedem Fall, zum Weitergeben von Hand.',
        )}
      >
        <form className="invite-form" onSubmit={submit}>
          <TextField
            label={t('E-Mail-Adresse')}
            type="email"
            required
            placeholder="name@example.com"
            value={email}
            onChange={setEmail}
            disabled={busy}
          />
          <Checkbox label={t('als Admin')} checked={admin} onChange={setAdmin} />
          <Button variant="primary" type="submit" disabled={busy || !email.includes('@')}>
            {t('Einladen')}
          </Button>
        </form>
        {made && (
          <Callout
            tone={made.mailed ? 'ok' : 'accent'}
            actions={
              <Button
                size="small"
                icon="copy"
                onClick={() => {
                  void navigator.clipboard
                    .writeText(made.link)
                    .then(() => toast(t('Kopiert ✧'), 'info'));
                }}
              >
                {t('Kopieren')}
              </Button>
            }
          >
            <p role="status">
              {made.mailed
                ? t(
                    'Die Einladung an {email} ist per Mail unterwegs. Der Link, falls sie nicht ankommt:',
                    { email: made.email },
                  )
                : t('Gib {email} diesen Link – er ist der einzige Weg zur Registrierung:', {
                    email: made.email,
                  })}
            </p>
            <code className="invite-link">{made.link}</code>
          </Callout>
        )}
      </Section>
      <Section heading={t('Offene Einladungen')}>
        {list?.length === 0 ? (
          <EmptyNote>{t('Keine offenen Einladungen.')}</EmptyNote>
        ) : (
          <Table
            label={t('Offene Einladungen')}
            head={
              <>
                <th>{t('Adresse')}</th>
                <th>{t('Eingeladen von')}</th>
                <th>{t('Gilt bis')}</th>
                <th>
                  <span className="sr-only">{t('Aktionen')}</span>
                </th>
              </>
            }
          >
            {list?.map((invitation) => (
              <tr key={invitation.email} data-disabled={invitation.expired || undefined}>
                <td>
                  <b>{invitation.email}</b>
                  <span className="badges">
                    {invitation.admin && <Badge>{t('Admin')}</Badge>}
                    {invitation.expired && <Badge tone="alarm">{t('abgelaufen')}</Badge>}
                  </span>
                </td>
                <td>{invitation.invitedBy ?? t('Kommandozeile')}</td>
                <td>{when(invitation.expires)}</td>
                <td className="row-actions">
                  <Button size="small" onClick={() => void again(invitation)}>
                    {t('Neu senden')}
                    <span className="sr-only">{invitation.email}</span>
                  </Button>
                  <Button
                    size="small"
                    variant="quiet-danger"
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
                    <span className="sr-only">{invitation.email}</span>
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Section>
    </>
  );
}
