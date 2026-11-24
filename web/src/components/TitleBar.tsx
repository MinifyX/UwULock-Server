import { Icon, ICONS, Wordmark } from '@uwusuite/design';
import { type ReactNode } from 'react';
import { useBranding } from '../lib/branding';
import { t, useLanguage } from '../lib/i18n';
import { Nyu } from './nyu/Nyu';

type Props = {
  onSettings?: () => void;
  /** What the settings button opens: the settings, or in the admin portal only the look. */
  settingsLabel?: string;
  /** New security notices: a count on the settings button. */
  badge?: number;
  /** What the bar is for: nothing for the vault, "Admin" for the admin portal. */
  area?: string;
  children?: ReactNode;
};

/**
 * The bar across the top: Nyu and the name, what this page is (the vault, or the admin
 * portal), its actions, and the settings. The same bar the desktop app draws, without the
 * window buttons: here the browser has those.
 */
export function TitleBar({ onSettings, settingsLabel, badge = 0, area, children }: Props) {
  useLanguage();
  const branding = useBranding();
  const name = branding?.name ?? 'UwULock';
  return (
    <header className="titlebar">
      <a className="titlebar-brand" href="/" aria-label={name} data-uwu-reveal-origin>
        <BrandMark size={22} />
        {branding && branding.name !== 'UwULock' ? (
          <span className="wordmark">{branding.name}</span>
        ) : (
          <Wordmark product="Lock" />
        )}
        {area && <span className="titlebar-area">{area}</span>}
      </a>
      <span className="spacer" />
      {children}
      {onSettings && (
        <button
          className="titlebar-action"
          onClick={onSettings}
          title={settingsLabel ? `${settingsLabel} (${t('Strg')}+,)` : t('Einstellungen (Strg+,)')}
          aria-label={settingsLabel ?? t('Einstellungen')}
          aria-keyshortcuts="Control+,"
          aria-describedby={badge > 0 ? 'settings-badge' : undefined}
        >
          <Icon icon={ICONS.settings} size="md" />
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
 * The first thing Tab reaches: past the bar, straight to what the page is about — the element
 * marked `data-main-content` (the vault's list, the admin page), or else `<main>`. A plain link
 * to `#main` would change the route, which lives in the part after `#`.
 */
export function SkipLink() {
  useLanguage();
  return (
    <a
      className="skip-link"
      href="#main"
      onClick={(event) => {
        event.preventDefault();
        const target =
          document.querySelector<HTMLElement>('[data-main-content]') ??
          document.getElementById('main');
        target?.focus();
      }}
    >
      {t('Zum Inhalt springen')}
    </a>
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
