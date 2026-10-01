import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { initialOf } from '../components/AccountCard';
import { Icon } from '../components/Icon';
import { LoginScreen } from '../components/LoginScreen';
import { NyuScene } from '../components/nyu/scenes';
import { Appearance } from '../components/SettingsDialog';
import { ShortcutsDialog } from '../components/ShortcutsDialog';
import { SkipLink, TitleBar } from '../components/TitleBar';
import { Toasts } from '../components/Toasts';
import { Button, Modal, TabPanel, Tabs, useTabsId } from '../components/ui';
import { account, type AccountInfo } from '../lib/account';
import { lock, logout, vaultStatus, type Status } from '../lib/api';
import { listen } from '../lib/events';
import { t, useLanguage } from '../lib/i18n';
import { go, useRoute } from '../lib/route';
import { useServerInfo } from '../lib/branding';
import { switchedOff } from '../lib/switches';
import { ADMIN_SHORTCUTS, singleKey } from '../lib/shortcuts';
import { locate, MOVED, visibleAreas, type TabId } from './areas';
import { InvitationRules, MailServerTab, PushTab, StorageTab } from './AdminSettings';
import { Backups } from './Backups';
import { Branding } from './Branding';
import { ComfortSettings } from './ComfortSettings';
import { Diagnosis } from './Diagnosis';
import { SaveBar, SettingsProvider } from './draft';
import { Events } from './Events';
import { FailedLogins } from './FailedLogins';
import { Families } from './Families';
import { FamilySettings } from './FamilySettings';
import { Features } from './Features';
import { Invitations } from './Invitations';
import { IpBlocks } from './IpBlocks';
import { Logs } from './Logs';
import { MaskedServerSettings } from './MaskedServerSettings';
import { Notifications } from './Notifications';
import { Offsite } from './Offsite';
import {
  AdminAccessTab,
  MasterPasswordTab,
  MonitoringTab,
  SignInTab,
  UserMailsTab,
} from './OperationsSettings';
import { Overview } from './Overview';
import { SendDomains } from './SendDomains';
import { ScimTab, SsoProvider, SsoProviderTab, SsoRulesTab } from './SsoPage';
import { Users } from './Users';

/** What a tab shows. */
function content(tab: TabId, me: string, info: AccountInfo) {
  switch (tab) {
    case 'overview':
      return <Overview />;
    case 'accounts':
      return <Users me={me} />;
    case 'invitations':
      return (
        <>
          <Invitations />
          <InvitationRules />
        </>
      );
    case 'families':
      return (
        <>
          <Families />
          <FamilySettings />
        </>
      );
    case 'sign-in':
      return <SignInTab />;
    case 'master-password':
      return <MasterPasswordTab />;
    case 'admin-access':
      return <AdminAccessTab />;
    case 'failed-logins':
      return <FailedLogins />;
    case 'ip-blocks':
      return <IpBlocks />;
    case 'sso':
      return <SsoProviderTab />;
    case 'sso-rules':
      return <SsoRulesTab sso={info.sso ?? false} />;
    case 'scim':
      return <ScimTab />;
    case 'features':
      return <Features />;
    case 'storage':
      return <StorageTab />;
    case 'icons':
      return <ComfortSettings />;
    case 'masked':
      return <MaskedServerSettings />;
    case 'send-domains':
      return <SendDomains />;
    case 'mail-server':
      return <MailServerTab me={me} />;
    case 'user-mails':
      return <UserMailsTab />;
    case 'push':
      return <PushTab />;
    case 'alerts':
      return <Notifications />;
    case 'local-backups':
      return <Backups />;
    case 'offsite':
      return <Offsite />;
    case 'branding':
      return <Branding />;
    case 'diagnosis':
      return <Diagnosis />;
    case 'events':
      return <Events />;
    case 'log':
      return <Logs />;
    case 'monitoring':
      return <MonitoringTab />;
  }
}

/**
 * The admin portal at `/admin`. It needs a login like the vault — admins are ordinary accounts
 * with the admin right — but not the vault's keys: after a reload the session is enough.
 *
 * Its shell is the web vault's: the bar on top, the sidebar with the areas (areas.ts), and the
 * page with the area's tabs.
 */
export function AdminApp() {
  useLanguage();
  const route = useRoute();
  const tabsId = useTabsId();
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

  // Areas and tabs of switched-off features are not there (docs/features.md).
  const serverInfo = useServerInfo();
  const areas = visibleAreas((id) => !switchedOff(serverInfo, id));
  const { area, tab } = locate(route.path, areas);
  const portal = Boolean(status && status.state !== 'logged-out' && info && info !== 'none');
  const modalOpen = appearance || shortcuts;

  // An address of 0.6.0-beta.1 shows where its page is now.
  useEffect(() => {
    if (portal && MOVED[route.path]) location.replace(`#${tab.path}`);
  }, [portal, route.path, tab.path]);

  // As in the vault: the background is inert under a dialog, and stops being so before the
  // dialog hands focus back.
  useLayoutEffect(() => {
    if (backgroundRef.current) backgroundRef.current.inert = modalOpen;
  }, [modalOpen]);

  // The keyboard (see lib/shortcuts.ts): the overview, the look, and the areas by number or in
  // order; the arrow keys move between an area's tabs.
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
      const index = areas.indexOf(area);
      if (key === '?') setShortcuts(true);
      else if (portal && /^[1-9]$/.test(key) && !event.shiftKey && areas[Number(key) - 1])
        go(areas[Number(key) - 1]!.tabs[0]!.path);
      else if (portal && (key === 'j' || key === 'k'))
        go(areas[(index + (key === 'j' ? 1 : -1) + areas.length) % areas.length]!.tabs[0]!.path);
      else return;
      event.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [area, areas, portal]);

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
            <Button onClick={() => void logout()}>{t('Abmelden')}</Button>
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
            <Button onClick={() => void logout()}>{t('Abmelden')}</Button>
          </div>
        </div>
      </div>
    );
  } else {
    const me = status.email ?? '';
    const shown = content(tab.id, me, info);
    body = (
      <SettingsProvider>
        <SsoProvider>
          <div className="admin">
            <nav className="sidebar admin-sidebar" aria-label={t('Admin-Portal')}>
              <ul className="nav-list">
                {areas.map((each, index) => (
                  <li key={each.id}>
                    <button
                      type="button"
                      className="nav-row"
                      aria-current={each === area ? 'page' : undefined}
                      aria-keyshortcuts={index < 9 ? String(index + 1) : undefined}
                      onClick={() => go(each.tabs[0]!.path)}
                    >
                      <Icon name={each.icon} size={16} />
                      <span className="nav-label">{t(each.label)}</span>
                    </button>
                  </li>
                ))}
              </ul>
              <span className="spacer" />
              <div className="account-card admin-account">
                <span className="avatar" aria-hidden>
                  {initialOf({ name: status.name, email: me })}
                </span>
                <span className="account-text">
                  <span className="account-email" title={me}>
                    {me}
                  </span>
                  <span className="account-sync">{t('Angemeldet als Admin')}</span>
                </span>
              </div>
            </nav>
            <section
              className="admin-page"
              tabIndex={-1}
              data-main-content
              aria-labelledby={`${tabsId}-title`}
            >
              <div className="admin-main">
                <header className="page-head">
                  <h1 className="page-title" id={`${tabsId}-title`}>
                    {t(area.label)}
                  </h1>
                  <p className="page-lead">{t(area.lead)}</p>
                </header>
                {area.tabs.length > 1 ? (
                  <>
                    <Tabs
                      label={t(area.label)}
                      idPrefix={tabsId}
                      value={tab.id}
                      onChange={(id) => go(area.tabs.find((each) => each.id === id)!.path)}
                      tabs={area.tabs.map((each) => ({ id: each.id, label: t(each.label) }))}
                    />
                    <TabPanel idPrefix={tabsId} tab={tab.id} className="admin-panel" key={tab.id}>
                      <h2 className="sr-only">{t(tab.label)}</h2>
                      {shown}
                    </TabPanel>
                  </>
                ) : (
                  <div className="admin-panel" key={tab.id}>
                    {shown}
                  </div>
                )}
              </div>
              <SaveBar />
            </section>
          </div>
        </SsoProvider>
      </SettingsProvider>
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
              <Button variant="primary" data-autofocus onClick={() => setAppearance(false)}>
                {t('Schließen')}
              </Button>
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
