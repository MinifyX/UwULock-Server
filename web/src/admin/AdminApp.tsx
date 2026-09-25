import { useEffect, useState } from 'react';
import { Icon, type IconName } from '../components/Icon';
import { LoginScreen } from '../components/LoginScreen';
import { NyuScene } from '../components/nyu/scenes';
import { TitleBar } from '../components/TitleBar';
import { account, type AccountInfo } from '../lib/account';
import { logout, vaultStatus, type Status } from '../lib/api';
import { listen } from '../lib/events';
import { N_, t, useLanguage } from '../lib/i18n';
import { go, useRoute } from '../lib/route';
import { useToast } from '../lib/toast';
import { AdminSettings } from './AdminSettings';
import { Backups } from './Backups';
import { Events } from './Events';
import { Invitations } from './Invitations';
import { Logs } from './Logs';
import { Overview } from './Overview';
import { Users } from './Users';

const PAGES: { path: string; label: string; icon: IconName }[] = [
  { path: '/', label: N_('Übersicht'), icon: 'house' },
  { path: '/users', label: N_('Nutzer'), icon: 'user' },
  { path: '/invitations', label: N_('Einladungen'), icon: 'sparkles' },
  { path: '/settings', label: N_('Einstellungen'), icon: 'shield' },
  { path: '/events', label: N_('Ereignisse'), icon: 'history' },
  { path: '/logs', label: N_('Log'), icon: 'terminal' },
  { path: '/backups', label: N_('Backups'), icon: 'drive' },
];

/**
 * The admin portal at `/admin`. It needs a login like the vault — admins are ordinary accounts
 * with the admin right — but not the vault's keys: after a reload the session is enough.
 */
export function AdminApp() {
  useLanguage();
  const route = useRoute();
  const toast = useToast();
  const [status, setStatus] = useState<Status | null>(null);
  const [info, setInfo] = useState<AccountInfo | null | 'none'>(null);

  useEffect(() => {
    void vaultStatus().then(setStatus);
    const stop = listen<Status>('vault-status', ({ payload }) => setStatus(payload));
    return () => void stop.then((unlisten) => unlisten());
  }, []);

  useEffect(() => {
    if (!status || status.state === 'logged-out') return;
    account().then(setInfo, () => setInfo('none'));
  }, [status]);

  const page = PAGES.find((p) => p.path === route.path) ?? PAGES[0]!;

  let body;
  if (status === null) body = null;
  else if (status.state === 'logged-out') body = <LoginScreen onDone={setStatus} />;
  else if (info === null) body = null;
  else if (info === 'none' || !info.admin) {
    body = (
      <div className="lock">
        <div className="lock-card">
          <NyuScene name="sleepy" className="lock-scene" />
          <h1 className="card-title">{t('Nur für Admins')}</h1>
          <p className="dialog-lead">
            {t('Dein Konto hat kein Admin-Recht. Ein Admin kann es dir im Admin-Portal geben.')}
          </p>
          <div className="form-actions">
            <a className="button-link" href="/">
              {t('Zum Tresor')}
            </a>
            <span className="spacer" />
            <button onClick={() => void logout()}>{t('Abmelden')}</button>
          </div>
        </div>
      </div>
    );
  } else {
    body = (
      <div className="admin">
        <nav className="admin-nav" aria-label={t('Admin-Portal')}>
          {PAGES.map((p) => (
            <button
              key={p.path}
              type="button"
              aria-current={p.path === page.path ? 'page' : undefined}
              onClick={() => go(p.path)}
            >
              <Icon name={p.icon} size={16} />
              {t(p.label)}
            </button>
          ))}
          <span className="spacer" />
          <p className="admin-who">{t('Angemeldet als {email}', { email: status.email ?? '' })}</p>
        </nav>
        <section className="admin-page">
          <h1 className="admin-title">{t(page.label)}</h1>
          {page.path === '/' && <Overview />}
          {page.path === '/users' && <Users me={status.email ?? ''} />}
          {page.path === '/invitations' && <Invitations />}
          {page.path === '/settings' && <AdminSettings me={status.email ?? ''} />}
          {page.path === '/events' && <Events />}
          {page.path === '/logs' && <Logs />}
          {page.path === '/backups' && <Backups />}
        </section>
      </div>
    );
  }

  return (
    <div className="shell">
      <div className="background">
        <TitleBar area={t('Admin')}>
          <a className="titlebar-link" href="/">
            <Icon name="lock" size={15} />
            {t('Zum Tresor')}
          </a>
          {status && status.state !== 'logged-out' && (
            <button
              className="titlebar-action"
              onClick={() => void logout()}
              title={t('Abmelden')}
              aria-label={t('Abmelden')}
            >
              <Icon name="logout" size={17} />
            </button>
          )}
        </TitleBar>
        <main className="stage">{body}</main>
      </div>
      {toast && (
        <div className="toast" data-tone={toast.tone} role="status" key={toast.id}>
          {toast.text}
        </div>
      )}
    </div>
  );
}
