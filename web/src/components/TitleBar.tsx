import { type ReactNode } from 'react';
import { useBranding } from '../lib/branding';
import { t, useLanguage } from '../lib/i18n';
import { Nyu } from './nyu/Nyu';

type Props = {
  onSettings?: () => void;
  /** New security notices: a count on the settings button. */
  badge?: number;
  /** What the bar is for: nothing for the vault, "Admin" for the admin portal. */
  area?: string;
  children?: ReactNode;
};

const ICONS = {
  settings:
    'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z',
};

/**
 * The bar across the top: Nyu and the name, what this page is (the vault, or the admin
 * portal), its actions, and the settings. The same bar the desktop app draws, without the
 * window buttons: here the browser has those.
 */
export function TitleBar({ onSettings, badge = 0, area, children }: Props) {
  useLanguage();
  const branding = useBranding();
  const name = branding?.name ?? 'UwULock';
  return (
    <header className="titlebar">
      <a className="titlebar-brand" href="/" aria-label={name}>
        <BrandMark size={22} />
        {branding && branding.name !== 'UwULock' ? (
          <span className="wordmark">{branding.name}</span>
        ) : (
          <span className="wordmark">
            <span>UwU</span>Lock
          </span>
        )}
        {area && <span className="titlebar-area">{area}</span>}
      </a>
      <span className="spacer" />
      {children}
      {onSettings && (
        <button
          className="titlebar-action"
          onClick={onSettings}
          title={t('Einstellungen (Strg+,)')}
          aria-label={t('Einstellungen')}
          aria-describedby={badge > 0 ? 'settings-badge' : undefined}
        >
          <svg viewBox="0 0 24 24" aria-hidden>
            <path d={ICONS.settings} />
          </svg>
          {badge > 0 && (
            <span className="titlebar-badge" aria-hidden>
              {badge > 99 ? '99+' : badge}
            </span>
          )}
        </button>
      )}
      {onSettings && badge > 0 && (
        <span id="settings-badge" className="sr-only">
          {t('{n} neue Sicherheitshinweise', { n: badge })}
        </span>
      )}
    </header>
  );
}

/**
 * The server's logo — the light or the dark one, whichever fits the theme — or Nyu when the
 * server has none. Decorative: the name next to it says what it is.
 */
export function BrandMark({ size }: { size: number }) {
  const branding = useBranding();
  const light = branding?.logoLight ?? branding?.logoDark;
  const dark = branding?.logoDark ?? branding?.logoLight;
  if (!light || !dark) return <Nyu size={size} blink={false} title="" />;
  return (
    <>
      <img className="brand-logo brand-logo-light" src={light} alt="" style={{ height: size }} />
      <img className="brand-logo brand-logo-dark" src={dark} alt="" style={{ height: size }} />
    </>
  );
}

/**
 * The picture beside a welcome page (login, Send, file request): the server's logo, large, when
 * it has one; else `fallback`, Nyu's scene.
 */
export function WelcomeMark({ fallback }: { fallback: ReactNode }) {
  const branding = useBranding();
  if (!branding?.logoLight && !branding?.logoDark) return <>{fallback}</>;
  return (
    <div className="welcome-logo">
      <BrandMark size={96} />
    </div>
  );
}
