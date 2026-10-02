import { useCallback, useEffect, useState } from 'react';
import { Badge, Button, DangerZone, Field, Modal, Table } from '../components/ui';
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
import { ago, bytes, seconds, when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { useRoute } from '../lib/route';
import { toast } from '../lib/toast';
import { EmptyNote } from '../components/NyuStates';

type Confirm = { user: User; action: UserAction | 'delete' } | null;

/** Every account, with what an admin may do to it. What is in a vault an admin never sees. */
export function Users({ me }: { me: string }) {
  useLanguage();
  const [list, setList] = useState<User[] | null>(null);
  // `#/users?q=…`: the failed logins link to an account this way.
  const asked = useRoute().query.get('q') ?? '';
  const [filter, setFilter] = useState(asked);
  useEffect(() => setFilter(asked), [asked]);
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
      <Field label={t('Konten durchsuchen')} hideLabel className="list-search">
        <input
          type="search"
          placeholder={t('Name oder Adresse suchen …')}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </Field>
      <Table
        label={t('Konten')}
        head={
          <>
            <th>{t('Konto')}</th>
            <th>{t('Einträge')}</th>
            <th>{t('Geräte')}</th>
            <th>{t('Dateien')}</th>
            <th>{t('Zuletzt angemeldet')}</th>
            <th>
              <span className="sr-only">{t('Aktionen')}</span>
            </th>
          </>
        }
      >
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
      </Table>
      {shown?.length === 0 && <EmptyNote mood="puzzled">{t('Niemand gefunden.')}</EmptyNote>}
      {confirm && (
        <Modal
          title={t('Sicher?')}
          tone={confirm.action === 'delete' ? 'warning' : 'default'}
          onCancel={() => setConfirm(null)}
          footer={
            <>
              <span className="spacer" />
              <Button onClick={() => setConfirm(null)} data-secondary>
                {t('Abbrechen')}
              </Button>
              <Button
                variant={
                  confirm.action === 'delete' || confirm.action === 'reset-two-factor'
                    ? 'danger'
                    : 'primary'
                }
                onClick={() => {
                  void run(confirm.user, confirm.action);
                  setConfirm(null);
                }}
              >
                {t('Ja')}
              </Button>
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
            {user.admin && <Badge>{t('Admin')}</Badge>}
            {user.disabled && <Badge tone="alarm">{t('gesperrt')}</Badge>}
            {user.twoFactor && <Badge tone="ok">2FA</Badge>}
            {self && <Badge tone="neutral">{t('du')}</Badge>}
          </span>
        </td>
        <td>{user.ciphers}</td>
        <td>{user.devices}</td>
        <td>{user.storageBytes ? bytes(user.storageBytes) : '–'}</td>
        <td title={when(user.lastLogin) ?? ''}>{ago(seconds(user.lastLogin))}</td>
        <td className="row-actions">
          <Button size="small" onClick={onToggle} aria-expanded={open}>
            {open ? t('Weniger') : t('Verwalten')}
            <span className="sr-only">{user.email}</span>
          </Button>
        </td>
      </tr>
      {open && (
        <tr className="row-detail">
          <td colSpan={6}>
            <p className="row-facts">
              {t('Angelegt {date} · Sprache {language} · {kdf}', {
                date: when(user.created) ?? '',
                language: user.language,
                kdf: user.kdf,
              })}
            </p>
            <div className="row-buttons">
              {user.disabled ? (
                <Button size="small" onClick={() => onAction('enable')}>
                  {t('Freigeben')}
                </Button>
              ) : (
                <Button size="small" onClick={() => onAction('disable')} disabled={self}>
                  {t('Sperren')}
                </Button>
              )}
              {user.admin ? (
                <Button size="small" onClick={() => onAction('remove-admin')}>
                  {t('Admin-Recht nehmen')}
                </Button>
              ) : (
                <Button size="small" onClick={() => onAction('make-admin')}>
                  {t('Zum Admin machen')}
                </Button>
              )}
              <Button size="small" onClick={() => onAction('log-out')}>
                {t('Überall abmelden')}
              </Button>
            </div>
            <p className="row-facts">{t('Angemeldete Geräte')}</p>
            <ul className="device-list compact">
              {devices?.map((device) => (
                <li key={device.id} className="device">
                  <span className="device-text">
                    <b>
                      {device.name} <small>· {device.typeName}</small>
                      {!device.loggedIn && <Badge tone="neutral">{t('abgemeldet')}</Badge>}
                    </b>
                    <small>
                      {t('Zuletzt {when}', {
                        when: ago(seconds(device.lastSeen)),
                      })}
                      {device.lastIp ? ` · ${device.lastIp}` : ''}
                    </small>
                  </span>
                  <Button
                    size="small"
                    variant="quiet"
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
                    <span className="sr-only">{device.name}</span>
                  </Button>
                </li>
              ))}
              {devices?.length === 0 && <li className="empty-note">{t('Keine Geräte.')}</li>}
            </ul>
            <DangerZone
              heading={t('Gefährlich')}
              lead={t('Das lässt sich nicht oder nur mit Mühe rückgängig machen.')}
            >
              <div className="row-buttons">
                <Button
                  size="small"
                  variant="danger"
                  onClick={() => onAction('reset-two-factor')}
                  disabled={!user.twoFactor}
                >
                  {t('Zwei-Schritt-Anmeldung zurücksetzen')}
                </Button>
                <Button
                  size="small"
                  variant="danger"
                  onClick={() => onAction('delete')}
                  disabled={self}
                >
                  {t('Konto löschen …')}
                </Button>
              </div>
            </DangerZone>
          </td>
        </tr>
      )}
    </>
  );
}
