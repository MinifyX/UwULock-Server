import { useCallback, useEffect, useState } from 'react';
import { Modal } from '../components/Modal';
import {
  deleteUser,
  deleteUserDevice,
  userAction,
  userDevices,
  users,
  type User,
  type UserAction,
  type UserDevice,
} from '../lib/admin';
import { errorText } from '../lib/errors';
import { ago, seconds, when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';

type Confirm = { user: User; action: UserAction | 'delete' } | null;

/** Every account, with what an admin may do to it. What is in a vault an admin never sees. */
export function Users({ me }: { me: string }) {
  useLanguage();
  const [list, setList] = useState<User[] | null>(null);
  const [filter, setFilter] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Confirm>(null);
  const load = useCallback(() => {
    users().then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  const run = async (user: User, action: UserAction | 'delete') => {
    try {
      if (action === 'delete') await deleteUser(user.id);
      else await userAction(user.id, action);
      toast(t('Erledigt ✧'), 'info');
      load();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  const words = filter.trim().toLowerCase();
  const shown = list?.filter(
    (u) => !words || `${u.email} ${u.name ?? ''}`.toLowerCase().includes(words),
  );

  return (
    <>
      <input
        className="search admin-search"
        placeholder={t('Suchen …')}
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <table className="admin-table">
        <thead>
          <tr>
            <th>{t('Konto')}</th>
            <th>{t('Einträge')}</th>
            <th>{t('Geräte')}</th>
            <th>{t('Zuletzt angemeldet')}</th>
            <th aria-label={t('Aktionen')} />
          </tr>
        </thead>
        <tbody>
          {shown?.map((user) => (
            <UserRow
              key={user.id}
              user={user}
              self={user.email === me}
              open={open === user.id}
              onToggle={() => setOpen(open === user.id ? null : user.id)}
              onAction={(action) =>
                action === 'enable' || action === 'make-admin'
                  ? void run(user, action)
                  : setConfirm({ user, action })
              }
            />
          ))}
        </tbody>
      </table>
      {shown?.length === 0 && <p className="empty-note">{t('Niemand gefunden.')}</p>}
      {confirm && (
        <Modal
          title={t('Sicher?')}
          tone={confirm.action === 'delete' ? 'warning' : 'default'}
          onCancel={() => setConfirm(null)}
          footer={
            <>
              <span className="spacer" />
              <button onClick={() => setConfirm(null)} data-secondary>
                {t('Abbrechen')}
              </button>
              <button
                className={confirm.action === 'delete' ? 'danger' : 'primary'}
                onClick={() => {
                  void run(confirm.user, confirm.action);
                  setConfirm(null);
                }}
              >
                {t('Ja')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {confirm.action === 'delete' &&
              t(
                '{email} und der ganze Tresor darin werden gelöscht. Das lässt sich nicht rückgängig machen.',
                { email: confirm.user.email },
              )}
            {confirm.action === 'disable' &&
              t(
                '{email} wird überall abgemeldet und kann sich nicht mehr anmelden, bis du das Konto wieder freigibst.',
                { email: confirm.user.email },
              )}
            {confirm.action === 'remove-admin' &&
              t('{email} ist danach kein Admin mehr.', { email: confirm.user.email })}
            {confirm.action === 'log-out' &&
              t('Jedes Gerät von {email} muss sich neu anmelden.', {
                email: confirm.user.email,
              })}
            {confirm.action === 'reset-two-factor' &&
              t(
                'Die Zwei-Schritt-Anmeldung von {email} wird ausgeschaltet. Mach das nur, wenn du sicher bist, dass wirklich diese Person fragt.',
                { email: confirm.user.email },
              )}
          </p>
        </Modal>
      )}
    </>
  );
}

function UserRow({
  user,
  self,
  open,
  onToggle,
  onAction,
}: {
  user: User;
  self: boolean;
  open: boolean;
  onToggle: () => void;
  onAction: (action: UserAction | 'delete') => void;
}) {
  useLanguage();
  const [devices, setDevices] = useState<UserDevice[] | null>(null);
  useEffect(() => {
    if (open) userDevices(user.id).then(setDevices, (e) => toast(errorText(e), 'error'));
  }, [open, user.id]);
  return (
    <>
      <tr data-disabled={user.disabled || undefined}>
        <td>
          <button className="row-toggle" onClick={onToggle} aria-expanded={open}>
            <b>{user.name ?? user.email}</b>
            <small>{user.email}</small>
          </button>
          <span className="badges">
            {user.admin && <span className="badge">{t('Admin')}</span>}
            {user.disabled && <span className="badge alarm">{t('gesperrt')}</span>}
            {user.twoFactor && <span className="badge">2FA</span>}
            {self && <span className="badge">{t('du')}</span>}
          </span>
        </td>
        <td>{user.ciphers}</td>
        <td>{user.devices}</td>
        <td title={when(user.lastLogin) ?? ''}>{ago(seconds(user.lastLogin))}</td>
        <td className="row-actions">
          <button onClick={onToggle}>{open ? t('Weniger') : t('Mehr')}</button>
        </td>
      </tr>
      {open && (
        <tr className="row-detail">
          <td colSpan={5}>
            <p className="row-facts">
              {t('Angelegt {date} · Sprache {language} · {kdf}', {
                date: when(user.created) ?? '',
                language: user.language,
                kdf: user.kdf,
              })}
            </p>
            <div className="row-buttons">
              {user.disabled ? (
                <button onClick={() => onAction('enable')}>{t('Freigeben')}</button>
              ) : (
                <button onClick={() => onAction('disable')} disabled={self}>
                  {t('Sperren')}
                </button>
              )}
              {user.admin ? (
                <button onClick={() => onAction('remove-admin')}>{t('Admin-Recht nehmen')}</button>
              ) : (
                <button onClick={() => onAction('make-admin')}>{t('Zum Admin machen')}</button>
              )}
              <button onClick={() => onAction('log-out')}>{t('Überall abmelden')}</button>
              <button onClick={() => onAction('reset-two-factor')} disabled={!user.twoFactor}>
                {t('Zwei-Schritt-Anmeldung zurücksetzen')}
              </button>
              <span className="spacer" />
              <button className="danger" onClick={() => onAction('delete')} disabled={self}>
                {t('Löschen')}
              </button>
            </div>
            <ul className="device-list compact">
              {devices?.map((device) => (
                <li key={device.id} className="device">
                  <span className="device-text">
                    <b>
                      {device.name} <small>· {device.typeName}</small>
                      {!device.loggedIn && <span className="badge">{t('abgemeldet')}</span>}
                    </b>
                    <small>
                      {t('Zuletzt {when}', {
                        when: ago(seconds(device.lastSeen)),
                      })}
                      {device.lastIp ? ` · ${device.lastIp}` : ''}
                    </small>
                  </span>
                  <button
                    onClick={async () => {
                      try {
                        await deleteUserDevice(user.id, device.id);
                        setDevices((all) => all?.filter((d) => d.id !== device.id) ?? null);
                      } catch (e) {
                        toast(errorText(e), 'error');
                      }
                    }}
                  >
                    {t('Entfernen')}
                  </button>
                </li>
              ))}
              {devices?.length === 0 && <li className="empty-note">{t('Keine Geräte.')}</li>}
            </ul>
          </td>
        </tr>
      )}
    </>
  );
}
