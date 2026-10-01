import { useEffect, useState } from 'react';
import { lock, logout, syncNow, type Status } from '../lib/api';
import { errorText } from '../lib/errors';
import { ago } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import { ContextMenu, type MenuItem } from './ContextMenu';
import { Icon } from './Icon';
import { Modal } from './Modal';

export function initialOf(account: { name?: string | null; label?: string; email: string }) {
  return (account.name || account.label || account.email || '?').trim().charAt(0).toUpperCase();
}

/**
 * The account at the foot of the sidebar: whose vault this is, when it was last synced, and
 * its menu (lock, log out). The web vault is this server's and opens one account's vault: it
 * offers no other account and no other server, unlike the desktop app's card it comes from.
 */
export function AccountCard({ status }: { status: Status }) {
  useLanguage();
  const [, force] = useState(0);
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null);
  // The address of the account to log out of, once asked.
  const [leaving, setLeaving] = useState<string | null>(null);

  // "vor 3 Min." keeps itself up to date.
  useEffect(() => {
    const timer = window.setInterval(() => force((n) => n + 1), 30_000);
    return () => window.clearInterval(timer);
  }, []);

  // The account this page is logged in to; the page knows no other.
  const email = status.email;

  const open = (event: { currentTarget: HTMLElement }) => {
    const rect = event.currentTarget.getBoundingClientRect();
    setMenu({ x: rect.left, y: rect.bottom + 4 });
  };

  const items: MenuItem[] = email
    ? [
        { label: t('Sperren'), icon: 'lock', onSelect: () => void lock() },
        { label: t('Abmelden'), icon: 'logout', danger: true, onSelect: () => setLeaving(email) },
      ]
    : [];

  return (
    <>
      <div className="account-card">
        <button
          className="account-switch"
          aria-haspopup="menu"
          aria-expanded={Boolean(menu)}
          title={t('Konto')}
          onClick={open}
        >
          <span className="avatar" aria-hidden>
            {initialOf({
              name: status.name,
              label: status.label ?? '',
              email: status.email ?? '',
            })}
          </span>
          <span className="account-text">
            <span className="account-email" title={status.email ?? ''}>
              {status.label}
            </span>
            <span
              className="account-sync"
              data-tone={status.syncError ? 'error' : undefined}
              title={status.email ?? undefined}
            >
              {status.syncing
                ? t('Synchronisiert …')
                : status.syncError
                  ? t('Sync fehlgeschlagen')
                  : t('Synchronisiert {when}', { when: ago(status.lastSync) })}
            </span>
          </span>
          <Icon name="chevron" size={14} className="account-chevron" />
        </button>
        <button
          className="icon-button"
          disabled={status.syncing}
          aria-label={t('Jetzt synchronisieren')}
          title={status.syncError ?? t('Jetzt synchronisieren')}
          onClick={() =>
            void syncNow()
              .then(() => toast(t('Synchronisiert ✧')))
              .catch((e) => toast(errorText(e), 'error'))
          }
        >
          <Icon name="refresh" size={15} className={status.syncing ? 'spin' : undefined} />
        </button>
      </div>

      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          items={items}
          label={t('Konto')}
          onClose={() => setMenu(null)}
        />
      )}

      {leaving && (
        <Modal
          title={t('Abmelden?')}
          tone="warning"
          onCancel={() => setLeaving(null)}
          footer={
            <>
              <span className="spacer" />
              <button
                className="danger"
                data-secondary
                onClick={() => {
                  setLeaving(null);
                  void logout()
                    .then(() => toast(t('Abgemeldet.')))
                    .catch((e) => toast(errorText(e), 'error'));
                }}
              >
                {t('Abmelden')}
              </button>
              <button className="primary" data-autofocus onClick={() => setLeaving(null)}>
                {t('Bleiben')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              '{email} wird von diesem Gerät entfernt – die Sitzung, die Schlüssel und der zwischengespeicherte Tresor. Auf dem Server bleibt alles, wie es ist.',
              { email: leaving },
            )}
          </p>
        </Modal>
      )}
    </>
  );
}
