import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { GeneratorDialog } from './components/GeneratorDialog';
import { Icon } from './components/Icon';
import { LockScreen } from './components/LockScreen';
import { LoginScreen } from './components/LoginScreen';
import { SettingsDialog, type SettingsSection } from './components/SettingsDialog';
import { ShortcutsDialog } from './components/ShortcutsDialog';
import { SkipLink, TitleBar } from './components/TitleBar';
import { Toasts } from './components/Toasts';
import { VaultScreen } from './components/VaultScreen';
import { lacksTwoFactor, PolicyBanners, TwoFactorRequired } from './components/web/Policies';
import { RegisterScreen } from './components/web/RegisterScreen';
import { SetPasswordScreen, SsoForward } from './components/web/SetPasswordScreen';
import { RequestPage } from './components/web/RequestPage';
import { SendPage } from './components/web/SendPage';
import { Unavailable } from './components/web/Unavailable';
import { connectFailureText } from './components/web/MaskedSettings';
import { errorText } from './lib/errors';
import { publicLinkOf } from './lib/links';
import { connectResultOf, reloadMaskedConnection } from './lib/masked';
import { acceptContact } from './lib/features';
import { acceptInvitation } from './lib/families';
import { toast } from './lib/toast';
import { lock, setSecurity, syncNow, touch, vaultStatus, type Status } from './lib/api';
import { account, type AccountInfo } from './lib/account';
import { listen } from './lib/events';
import { t, useLanguage } from './lib/i18n';
import { useRoute } from './lib/route';
import { useServerInfo } from './lib/branding';
import { switchedOff, switchOfLink } from './lib/switches';
import { useSettings } from './lib/settings';
import { singleKey, VAULT_SHORTCUTS } from './lib/shortcuts';

/** The web vault: login or unlock, the vault, the settings — and registering by invitation. */
export function App() {
  useLanguage();
  const settings = useSettings();
  const route = useRoute();
  const [status, setStatus] = useState<Status | null>(null);
  const [info, setInfo] = useState<AccountInfo | null>(null);
  const [settingsOpen, setSettingsOpen] = useState<SettingsSection | null>(null);
  const [generator, setGenerator] = useState(false);
  const [shortcuts, setShortcuts] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const backgroundRef = useRef<HTMLDivElement>(null);
  // A link by its path: what a send domain answers (`/<access id>#<key>` for a Send,
  // `/r/<access id>#<secret>` for a file request). The page then shows only that — a send
  // domain has no vault, no login and no account to ask about.
  const [byPath] = useState(() => publicLinkOf(location.pathname, location.hash));
  const publicPage = byPath !== null;

  // ── Vault state ──────────────────────────────────────────
  useEffect(() => {
    void vaultStatus().then(setStatus);
    const stop = listen<Status>('vault-status', ({ payload }) => setStatus(payload));
    return () => void stop.then((unlisten) => unlisten());
  }, []);

  const unlocked = status?.state === 'unlocked';

  // What the server says about the account beyond Bitwarden's profile: admin or not, mail.
  useEffect(() => {
    if (status?.state === 'logged-out' || publicPage) setInfo(null);
    else if (status) void account().then(setInfo, () => setInfo(null));
  }, [status, publicPage]);

  useEffect(() => {
    void setSecurity(settings.autoLock || null, settings.clipboardClear || null);
  }, [settings.autoLock, settings.clipboardClear]);

  // What counts as activity for auto-lock: keys, clicks, the wheel.
  useEffect(() => {
    let last = 0;
    const active = () => {
      const now = Date.now();
      if (now - last < 20_000) return;
      last = now;
      void touch();
    };
    for (const type of ['keydown', 'pointerdown', 'wheel'] as const)
      window.addEventListener(type, active, { passive: true, capture: true });
    return () => {
      for (const type of ['keydown', 'pointerdown', 'wheel'] as const)
        window.removeEventListener(type, active, { capture: true });
    };
  }, []);

  const modalOpen = Boolean(settingsOpen || generator || shortcuts);

  // Before the dialog's own effects run: a closing dialog hands focus back to its opener in the
  // background, and an element that is still inert does not take it.
  useLayoutEffect(() => {
    if (backgroundRef.current) backgroundRef.current.inert = modalOpen;
  }, [modalOpen]);

  // ── Keyboard ─────────────────────────────────────────────
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === '?' && singleKey(event)) {
        event.preventDefault();
        setShortcuts(true);
        return;
      }
      const mod = event.ctrlKey || event.metaKey;
      if (!mod || event.altKey) return;
      const key = event.key.toLowerCase();
      if (key === ',') {
        event.preventDefault();
        setSettingsOpen((open) => open ?? 'appearance');
      } else if (modalOpen) {
        return;
      } else if (key === 'l' && unlocked) {
        event.preventDefault();
        void lock();
      } else if (key === 'f' && unlocked) {
        event.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      } else if (key === 'g') {
        event.preventDefault();
        setGenerator(true);
      }
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [modalOpen, unlocked]);

  const registering = route.path === '/finish-signup' || route.path === '/register';
  const sendLink =
    route.path.match(/^\/send\/([^/]+)\/([^/]+)$/) ??
    (byPath?.kind === 'send' ? ['', byPath.accessId, byPath.key] : null);
  // A file request's link: `#/request/<access id>/<secret>` here, `/r/<access id>#<secret>` on a
  // send domain.
  const requestLink =
    route.path.match(/^\/request\/([^/]+)\/([^/]+)$/) ??
    (byPath?.kind === 'request' ? ['', byPath.accessId, byPath.secret] : null);
  const fileRequest = route.path.match(/^\/file-requests\/([^/]+)$/)?.[1] ?? null;
  // A family's page: the desktop app and the mails link here.
  const family = route.path.match(/^\/organizations\/([^/]+)$/)?.[1] ?? null;
  // The link from a family's invitation: somebody without an account registers with it.
  const joining = route.path === '/accept-organization' ? route.query : null;
  const joinNew =
    joining?.get('orgUserHasExistingUser') === 'False' && status?.state === 'logged-out';
  // Bitwarden's extension, desktop app and CLI start their SSO login here.
  const ssoForward = route.path === '/sso' && route.query.get('clientId') ? route.query : null;
  // A link to something the server has switched off: said so, instead of a page that fails.
  const serverInfo = useServerInfo();
  const needs =
    byPath?.kind === 'request' ? 'file-requests' : switchOfLink(route.path, route.query);
  const unavailable = needs !== null && switchedOff(serverInfo, needs);

  // The link from an emergency access invitation: accepted once the vault is open.
  useEffect(() => {
    if (route.path !== '/accept-emergency' || !unlocked) return;
    const id = route.query.get('id') ?? '';
    const token = route.query.get('token') ?? '';
    location.hash = '';
    void acceptContact(id, token).then(
      () =>
        toast(
          t('Du bist jetzt Notfallkontakt ✧ Sobald du bestätigt bist, kannst du Zugriff anfragen.'),
        ),
      (e) => toast(errorText(e), 'error'),
    );
  }, [route, unlocked]);

  // The link from a family's invitation: accepted once the vault is open.
  useEffect(() => {
    if (route.path !== '/accept-organization' || !unlocked || unavailable) return;
    const orgId = route.query.get('organizationId') ?? '';
    const memberId = route.query.get('organizationUserId') ?? '';
    const token = route.query.get('token') ?? '';
    location.hash = '';
    void acceptInvitation(orgId, memberId, token).then(
      () => toast(t('Angenommen ✧ Sobald dich jemand bestätigt, siehst du, was geteilt ist.')),
      (e) => toast(errorText(e), 'error'),
    );
  }, [route, unlocked, unavailable]);

  // Links into the settings — a security notice's mail, the desktop app's travel mode button —
  // once the vault is open.
  useEffect(() => {
    const section = route.path.match(/^\/settings(?:\/([a-z-]+))?$/);
    if (!section || !unlocked || unavailable) return;
    // The way back from UwUMail (§13.2): read before the address is cleared.
    const connected = section[1] === 'masked' ? connectResultOf(route.query) : null;
    location.hash = '';
    if (connected?.ok) {
      void reloadMaskedConnection();
      toast(t('Mit UwUMail verbunden ✧'));
    } else if (connected) {
      toast(connectFailureText(connected.reason), 'error');
    }
    const known: SettingsSection[] = [
      'security',
      'travel',
      'account',
      'two-factor',
      'devices',
      'transfer',
      'masked',
    ];
    const wanted = (section[1] ?? 'appearance') as SettingsSection;
    setSettingsOpen(known.includes(wanted) ? wanted : 'appearance');
  }, [route, unlocked, unavailable]);

  const unseen = unlocked ? (info?.securityNoticesUnseen ?? 0) : 0;
  // Two-step login is required, the date has passed, and there is none: only its setup shows.
  const mustSetUp = unlocked && info && lacksTwoFactor(info) && info.policy?.twoFactorEnforced;
  // Until then the server hands out no vault; once it is set up, fetch it.
  const wasSetUp = useRef(false);
  useEffect(() => {
    if (wasSetUp.current && !mustSetUp && unlocked) void syncNow().then(setStatus, () => undefined);
    wasSetUp.current = Boolean(mustSetUp);
  }, [mustSetUp, unlocked]);

  return (
    <div className="shell">
      <div className="background" ref={backgroundRef}>
        <SkipLink />
        <TitleBar
          badge={unseen}
          onSettings={() => setSettingsOpen(unseen > 0 ? 'security' : 'appearance')}
        >
          {info?.admin && (
            <a className="titlebar-link" href="/admin">
              <Icon name="shield" size={15} />
              <span className="titlebar-link-text">{t('Admin-Portal')}</span>
            </a>
          )}
          <button
            className="titlebar-action"
            onClick={() => setShortcuts(true)}
            title={t('Tastenkürzel (?)')}
            aria-label={t('Tastenkürzel')}
          >
            <Icon name="keyboard" size={17} />
          </button>
          <button
            className="titlebar-action"
            onClick={() => setGenerator(true)}
            title={t('Passwort-Generator (Strg+G)')}
            aria-label={t('Passwort-Generator')}
            aria-keyshortcuts="Control+G"
          >
            <Icon name="dice" size={17} />
          </button>
          {unlocked && (
            <button
              className="titlebar-action"
              onClick={() => void lock()}
              title={t('Sperren (Strg+L)')}
              aria-label={t('Sperren')}
              aria-keyshortcuts="Control+L"
            >
              <Icon name="lock" size={17} />
            </button>
          )}
        </TitleBar>

        <main className="stage" id="main" tabIndex={-1}>
          {ssoForward ? (
            <SsoForward query={ssoForward} />
          ) : unavailable ? (
            <Unavailable vault={!requestLink} />
          ) : sendLink ? (
            <SendPage accessId={sendLink[1]!} urlKey={sendLink[2]!} />
          ) : requestLink ? (
            <RequestPage accessId={requestLink[1]!} secret={requestLink[2]!} />
          ) : joinNew && joining ? (
            <RegisterScreen
              token=""
              email={joining.get('email') ?? ''}
              family={{
                token: joining.get('token') ?? '',
                memberId: joining.get('organizationUserId') ?? '',
                name: joining.get('organizationName') ?? '',
              }}
              onDone={(next) => {
                location.hash = '';
                setStatus(next);
              }}
            />
          ) : registering ? (
            <RegisterScreen
              token={route.query.get('token') ?? ''}
              email={route.query.get('email') ?? ''}
              onDone={(next) => {
                location.hash = '';
                setStatus(next);
              }}
            />
          ) : status === null ? null : status.state === 'logged-out' ? (
            <LoginScreen onDone={setStatus} />
          ) : status.state === 'locked' && info?.hasMasterPassword === false ? (
            <SetPasswordScreen status={status} info={info} onDone={setStatus} />
          ) : status.state === 'locked' ? (
            <LockScreen
              status={status}
              onUnlocked={setStatus}
              onLoggedOut={() => void vaultStatus().then(setStatus)}
              onAddAccount={() => undefined}
            />
          ) : mustSetUp ? (
            <TwoFactorRequired status={status} info={info} onInfo={setInfo} />
          ) : (
            <div className="vault-frame">
              <PolicyBanners status={status} info={info} onSettings={setSettingsOpen} />
              <VaultScreen
                status={status}
                searchRef={searchRef}
                onAddAccount={() => undefined}
                openRequest={fileRequest}
                openDue={route.path === '/vault' && route.query.get('due') === '1'}
                openItem={route.path === '/vault' ? route.query.get('itemId') : null}
                openFamily={family}
                familyRules={info?.families ?? null}
              />
            </div>
          )}
        </main>
      </div>

      <Toasts />

      {generator && <GeneratorDialog onClose={() => setGenerator(false)} />}

      {shortcuts && (
        <ShortcutsDialog groups={VAULT_SHORTCUTS} onClose={() => setShortcuts(false)} />
      )}

      {settingsOpen && status && (
        <SettingsDialog
          initial={settingsOpen}
          status={status}
          info={info}
          onInfo={setInfo}
          onClose={() => setSettingsOpen(null)}
        />
      )}
    </div>
  );
}
