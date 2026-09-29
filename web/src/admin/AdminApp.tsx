import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Icon, type IconName } from '../components/Icon';
import { LoginScreen } from '../components/LoginScreen';
import { Modal } from '../components/Modal';
import { NyuScene } from '../components/nyu/scenes';
import { Appearance } from '../components/SettingsDialog';
import { ShortcutsDialog } from '../components/ShortcutsDialog';
import { SkipLink, TitleBar } from '../components/TitleBar';
import { Toasts } from '../components/Toasts';
import { account, type AccountInfo } from '../lib/account';
import { lock, logout, vaultStatus, type Status } from '../lib/api';
import { listen } from '../lib/events';
import { N_, t, useLanguage } from '../lib/i18n';
import { go, useRoute } from '../lib/route';
import { useServerInfo } from '../lib/branding';
import { switchedOff, type SwitchId } from '../lib/switches';
import { ADMIN_SHORTCUTS, singleKey } from '../lib/shortcuts';
import { AdminSettings } from './AdminSettings';
import { Backups } from './Backups';
import { Branding } from './Branding';
import { Diagnosis } from './Diagnosis';
import { Events } from './Events';
import { Families } from './Families';
import { Features } from './Features';
import { Invitations } from './Invitations';
import { Logs } from './Logs';
import { Notifications } from './Notifications';
import { Overview } from './Overview';
import { SendDomains } from './SendDomains';
import { SsoPage } from './SsoPage';
import { Users } from './Users';

/** The portal's pages; one that `needs` a feature switch is there only while it is on. */
const PAGES: { path: string; label: string; icon: IconName; needs?: SwitchId }[] = [
  { path: '/', label: N_('Übersicht'), icon: 'house' },
  { path: '/users', label: N_('Nutzer'), icon: 'user' },
  { path: '/invitations', label: N_('Einladungen'), icon: 'sparkles' },
  { path: '/families', label: N_('Familien'), icon: 'house', needs: 'families' },
  { path: '/features', label: N_('Funktionen'), icon: 'grid' },
  { path: '/settings', label: N_('Einstellungen'), icon: 'shield' },
  { path: '/login', label: N_('Anmeldung'), icon: 'key', needs: 'sso' },
  { path: '/branding', label: N_('Aussehen'), icon: 'eye' },
  { path: '/send-domains', label: N_('Send-Domains'), icon: 'globe', needs: 'send-domains' },
  { path: '/events', label: N_('Ereignisse'), icon: 'history' },
  { path: '/logs', label: N_('Log'), icon: 'terminal' },
  { path: '/backups', label: N_('Backups'), icon: 'drive' },
  {
    path: '/notifications',
    label: N_('Benachrichtigungen'),
    icon: 'bell',
    needs: 'admin-notifications',
  },
  { path: '/diagnosis', label: N_('Diagnose'), icon: 'lifebuoy' },
];

/**
 * The admin portal at `/admin`. It needs a login like the vault — admins are ordinary accounts
 * with the admin right — but not the vault's keys: after a reload the session is enough.
 */
export function AdminApp() {
  useLanguage();
  const route = useRoute();
  const [status, setStatus] = useState<Status | null>(null);
  const [info, setInfo] = useState<AccountInfo | null | 'none'>(null);
  const [appearance, setAppearance] = useState(false);
  const [shortcuts, setShortcuts] = useState(false);
  const backgroundRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    void vaultStatus().then(setStatus);
    const stop = listen<Status>('vault-status', ({ payload }) => setStatus(payload));
    return () => void stop.then((unlisten) => unlisten());
  }, []);

  useEffect(() => {
    if (!status || status.state === 'logged-out') return;
    account().then(setInfo, () => setInfo('none'));
  }, [status]);

  // Pages of switched-off features are not there (docs/features.md).
  const serverInfo = useServerInfo();
  const pages = PAGES.filter((p) => !p.needs || !switchedOff(serverInfo, p.needs));
  const page = pages.find((p) => p.path === route.path) ?? pages[0]!;
  const portal = Boolean(status && status.state !== 'logged-out' && info && info !== 'none');
  const modalOpen = appearance || shortcuts;

  // As in the vault: the background is inert under a dialog, and stops being so before the
  // dialog hands focus back.
  useLayoutEffect(() => {
    if (backgroundRef.current) backgroundRef.current.inert = modalOpen;
  }, [modalOpen]);

  // The keyboard (see lib/shortcuts.ts): the overview, the look, and the pages by number or in
  // order.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const mod = event.ctrlKey || event.metaKey;
      if (mod && !event.altKey && event.key === ',') {
        event.preventDefault();
        setAppearance(true);
        return;
      }
      if (!singleKey(event)) return;
      const key = event.key.toLowerCase();
      const index = pages.indexOf(page);
      if (key === '?') setShortcuts(true);
      else if (portal && /^[1-9]$/.test(key) && !event.shiftKey && pages[Number(key) - 1])
        go(pages[Number(key) - 1]!.path);
      else if (portal && (key === 'j' || key === 'k'))
        go(pages[(index + (key === 'j' ? 1 : -1) + pages.length) % pages.length]!.path);
      else return;
      event.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [page, pages, portal]);

  let body;
  if (status === null) body = null;
  // The portal needs the session, not the vault: logging in opens the vault, and it is locked
  // again at once, so no key and nothing decrypted stays in an admin tab.
  else if (status.state === 'logged-out')
    body = <LoginScreen target="admin" onDone={() => void lock()} />;
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
  } else if (info.adminNeedsSso && !info.sso) {
    body = (
      <div className="lock">
        <div className="lock-card">
          <NyuScene name="sleepy" className="lock-scene" />
          <h1 className="card-title">{t('Nur mit SSO')}</h1>
          <p className="dialog-lead">
            {t(
              'Das Admin-Portal nimmt auf diesem Server nur Anmeldungen über SSO. Melde dich ab und wieder an, diesmal über SSO.',
            )}
          </p>
          <div className="form-actions">
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
          {pages.map((p, index) => (
            <button
              key={p.path}
              type="button"
              aria-current={p.path === page.path ? 'page' : undefined}
              aria-keyshortcuts={index < 9 ? String(index + 1) : undefined}
              onClick={() => go(p.path)}
            >
              <Icon name={p.icon} size={16} />
              {t(p.label)}
            </button>
          ))}
          <span className="spacer" />
          <p className="admin-who">{t('Angemeldet als {email}', { email: status.email ?? '' })}</p>
        </nav>
        <section className="admin-page" tabIndex={-1} data-main-content>
          <h1 className="admin-title">{t(page.label)}</h1>
          {page.path === '/' && <Overview />}
          {page.path === '/users' && <Users me={status.email ?? ''} />}
          {page.path === '/invitations' && <Invitations />}
          {page.path === '/families' && <Families />}
          {page.path === '/features' && <Features />}
          {page.path === '/settings' && <AdminSettings me={status.email ?? ''} />}
          {page.path === '/login' && <SsoPage sso={info.sso ?? false} />}
          {page.path === '/branding' && <Branding />}
          {page.path === '/send-domains' && <SendDomains />}
          {page.path === '/events' && <Events />}
          {page.path === '/logs' && <Logs />}
          {page.path === '/backups' && <Backups />}
          {page.path === '/notifications' && <Notifications />}
          {page.path === '/diagnosis' && <Diagnosis />}
        </section>
      </div>
    );
  }

  return (
    <div className="shell">
      <div className="background" ref={backgroundRef}>
        <SkipLink />
        <TitleBar
          area={t('Admin')}
          onSettings={() => setAppearance(true)}
          settingsLabel={t('Darstellung')}
        >
          <a className="titlebar-link" href="/">
            <Icon name="lock" size={15} />
            <span className="titlebar-link-text">{t('Zum Tresor')}</span>
          </a>
          <button
            className="titlebar-action"
            onClick={() => setShortcuts(true)}
            title={t('Tastenkürzel (?)')}
            aria-label={t('Tastenkürzel')}
          >
            <Icon name="keyboard" size={17} />
          </button>
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
        <main className="stage" id="main" tabIndex={-1}>
          {body}
        </main>
      </div>
      <Toasts />
      {shortcuts && (
        <ShortcutsDialog groups={ADMIN_SHORTCUTS} onClose={() => setShortcuts(false)} />
      )}
      {appearance && (
        <Modal
          title={t('Darstellung')}
          onCancel={() => setAppearance(false)}
          footer={
            <>
              <span className="spacer" />
              <button className="primary" data-autofocus onClick={() => setAppearance(false)}>
                {t('Schließen')}
              </button>
            </>
          }
        >
          <div className="settings-content">
            <Appearance vault={false} />
          </div>
        </Modal>
      )}
    </div>
  );
}
