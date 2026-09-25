import { useEffect, useRef, useState } from 'react';
import { GeneratorDialog } from './components/GeneratorDialog';
import { Icon } from './components/Icon';
import { LockScreen } from './components/LockScreen';
import { LoginScreen } from './components/LoginScreen';
import { SettingsDialog, type SettingsSection } from './components/SettingsDialog';
import { TitleBar } from './components/TitleBar';
import { VaultScreen } from './components/VaultScreen';
import { RegisterScreen } from './components/web/RegisterScreen';
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

  return (
    <div className="shell">
      <div className="background" ref={backgroundRef}>
        <TitleBar onSettings={() => setSettingsOpen('appearance')}>
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
          {registering ? (
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
          ) : (
            <VaultScreen status={status} searchRef={searchRef} onAddAccount={() => undefined} />
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
