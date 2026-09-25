import { useEffect, useState } from 'react';
import {
  lock,
  logout,
  renameAccount,
  switchAccount,
  syncNow,
  type AccountBrief,
  type Status,
} from '../lib/api';
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
 * The account at the foot of the sidebar: whose vault this is, when it was
 * last synced — and the way to the other accounts. One account is open at a
 * time; the others keep their own keys and their own vault.
 */
export function AccountCard({
  status,
  onAddAccount,
}: {
  status: Status;
  onAddAccount: () => void;
}) {
  useLanguage();
  const [, force] = useState(0);
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null);
  const [renaming, setRenaming] = useState<AccountBrief | null>(null);
  const [leaving, setLeaving] = useState<AccountBrief | null>(null);

  // "vor 3 Min." keeps itself up to date.
  useEffect(() => {
    const timer = window.setInterval(() => force((n) => n + 1), 30_000);
    return () => window.clearInterval(timer);
  }, []);

  const others = status.accounts.filter((account) => !account.active);
  const current = status.accounts.find((account) => account.active) ?? null;

  const open = (event: { currentTarget: HTMLElement }) => {
    const rect = event.currentTarget.getBoundingClientRect();
    setMenu({ x: rect.left, y: rect.bottom + 4 });
  };

  const items: MenuItem[] = [
    ...others.map((account): MenuItem => ({
      label: account.unlocked ? account.label : t('{label} (gesperrt)', { label: account.label }),
      icon: account.unlocked ? 'unlock' : 'lock',
      onSelect: () => void switchAccount(account.id).catch((e) => toast(errorText(e), 'error')),
    })),
    ...(others.length ? (['separator'] as MenuItem[]) : []),
    { label: t('Konto hinzufügen'), icon: 'plus', onSelect: onAddAccount },
    ...(current
      ? ([
          {
            label: t('Konto umbenennen'),
            icon: 'pencil',
            onSelect: () => setRenaming(current),
          },
          { label: t('Sperren'), icon: 'lock', onSelect: () => void lock() },
          {
            label: t('Abmelden'),
            icon: 'logout',
            danger: true,
            onSelect: () => setLeaving(current),
          },
        ] as MenuItem[])
      : []),
  ];

  return (
    <>
      <div className="account-card">
        <button
          className="account-switch"
          aria-haspopup="menu"
          aria-expanded={Boolean(menu)}
          title={t('Konto wechseln')}
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
          label={t('Konten')}
          onClose={() => setMenu(null)}
        />
      )}

      {renaming && <RenameAccount account={renaming} onClose={() => setRenaming(null)} />}

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
                  const id = leaving.id;
                  setLeaving(null);
                  void logout(id)
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
              { email: leaving.email },
            )}
          </p>
        </Modal>
      )}
    </>
  );
}

function RenameAccount({ account, onClose }: { account: AccountBrief; onClose: () => void }) {
  useLanguage();
  const [label, setLabel] = useState(account.label);
  const save = () => {
    void renameAccount(account.id, label.trim()).catch((e) => toast(errorText(e), 'error'));
    onClose();
  };
  return (
    <Modal
      title={t('Konto umbenennen')}
      onCancel={onClose}
      footer={
        <>
          <button className="quiet" data-secondary onClick={onClose}>
            {t('Abbrechen')}
          </button>
          <span className="spacer" />
          <button className="primary" onClick={save}>
            {t('Übernehmen')}
          </button>
        </>
      }
    >
      <p className="dialog-lead">
        {t('Nur hier auf diesem Gerät. Leer lassen: dann steht wieder {server} da.', {
          server: account.server,
        })}
      </p>
      <label className="field">
        <span>{t('Name')}</span>
        <input
          type="text"
          value={label}
          maxLength={40}
          autoFocus
          placeholder={account.server}
          onChange={(e) => setLabel(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && save()}
        />
      </label>
    </Modal>
  );
}
