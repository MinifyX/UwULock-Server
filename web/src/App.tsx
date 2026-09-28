import { useEffect, useRef, useState } from 'react';
import { GeneratorDialog } from './components/GeneratorDialog';
import { Icon } from './components/Icon';
import { LockScreen } from './components/LockScreen';
import { LoginScreen } from './components/LoginScreen';
import { SettingsDialog, type SettingsSection } from './components/SettingsDialog';
import { TitleBar } from './components/TitleBar';
import { VaultScreen } from './components/VaultScreen';
import { lacksTwoFactor, PolicyBanners, TwoFactorRequired } from './components/web/Policies';
import { RegisterScreen } from './components/web/RegisterScreen';
import { RequestPage } from './components/web/RequestPage';
import { SendPage } from './components/web/SendPage';
import { errorText } from './lib/errors';
import { acceptContact } from './lib/features';
import { toast } from './lib/toast';
import { lock, setSecurity, touch, vaultStatus, type Status } from './lib/api';
import { account, type AccountInfo } from './lib/account';
import { listen } from './lib/events';
import { t, useLanguage } from './lib/i18n';
import { useRoute } from './lib/route';
import { useSettings } from './lib/settings';
import { useToast } from './lib/toast';

/** The web vault: login or unlock, the vault, the settings — and registering by invitation. */
export function App() {
  useLanguage();
  const settings = useSettings();
  const route = useRoute();
  const [status, setStatus] = useState<Status | null>(null);
  const [info, setInfo] = useState<AccountInfo | null>(null);
  const [settingsOpen, setSettingsOpen] = useState<SettingsSection | null>(null);
  const [generator, setGenerator] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const backgroundRef = useRef<HTMLDivElement>(null);
  const current = useToast();

  // ── Vault state ──────────────────────────────────────────
  useEffect(() => {
    void vaultStatus().then(setStatus);
    const stop = listen<Status>('vault-status', ({ payload }) => setStatus(payload));
    return () => void stop.then((unlisten) => unlisten());
  }, []);

  const unlocked = status?.state === 'unlocked';

  // What the server says about the account beyond Bitwarden's profile: admin or not, mail.
  useEffect(() => {
    if (status?.state === 'logged-out') setInfo(null);
    else if (status) void account().then(setInfo, () => setInfo(null));
  }, [status]);

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

  const modalOpen = Boolean(settingsOpen || generator);

  useEffect(() => {
    if (backgroundRef.current) backgroundRef.current.inert = modalOpen;
  }, [modalOpen]);

  // ── Keyboard ─────────────────────────────────────────────
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
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
  const sendLink = route.path.match(/^\/send\/([^/]+)\/([^/]+)$/);
  // A file request's link: `#/request/<access id>/<secret>` here, `/r/<access id>#<secret>` on a
  // send domain.
  const requestLink =
    route.path.match(/^\/request\/([^/]+)\/([^/]+)$/) ??
    (() => {
      const path = location.pathname.match(/^\/r\/([A-Za-z0-9_-]+)$/);
      return path ? [path[0], path[1], location.hash.replace(/^#/, '')] : null;
    })();
  const fileRequest = route.path.match(/^\/file-requests\/([^/]+)$/)?.[1] ?? null;

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

  // The link in a security notice's mail: the list, once the vault is open.
  useEffect(() => {
    if (route.path !== '/settings/security' || !unlocked) return;
    location.hash = '';
    setSettingsOpen('security');
  }, [route, unlocked]);

  const unseen = unlocked ? (info?.securityNoticesUnseen ?? 0) : 0;
  // Two-step login is required, the date has passed, and there is none: only its setup shows.
  const mustSetUp = unlocked && info && lacksTwoFactor(info) && info.policy?.twoFactorEnforced;

  return (
    <div className="shell">
      <div className="background" ref={backgroundRef}>
        <TitleBar
          badge={unseen}
          onSettings={() => setSettingsOpen(unseen > 0 ? 'security' : 'appearance')}
        >
          {info?.admin && (
            <a className="titlebar-link" href="/admin">
              <Icon name="shield" size={15} />
              {t('Admin-Portal')}
            </a>
          )}
          <button
            className="titlebar-action"
            onClick={() => setGenerator(true)}
            title={t('Passwort-Generator (Strg+G)')}
            aria-label={t('Passwort-Generator')}
          >
            <Icon name="dice" size={17} />
          </button>
          {unlocked && (
            <button
              className="titlebar-action"
              onClick={() => void lock()}
              title={t('Sperren (Strg+L)')}
              aria-label={t('Sperren')}
            >
              <Icon name="lock" size={17} />
            </button>
          )}
        </TitleBar>

        <main className="stage">
          {sendLink ? (
            <SendPage accessId={sendLink[1]!} urlKey={sendLink[2]!} />
          ) : requestLink ? (
            <RequestPage accessId={requestLink[1]!} secret={requestLink[2]!} />
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
              />
            </div>
          )}
        </main>
      </div>

      {current && (
        <div className="toast" data-tone={current.tone} role="status" key={current.id}>
          {current.text}
        </div>
      )}

      {generator && <GeneratorDialog onClose={() => setGenerator(false)} />}

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
