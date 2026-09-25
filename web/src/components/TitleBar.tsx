import { type ReactNode } from 'react';
import { t, useLanguage } from '../lib/i18n';
import { Nyu } from './nyu/Nyu';

type Props = {
  onSettings?: () => void;
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
export function TitleBar({ onSettings, area, children }: Props) {
  useLanguage();
  return (
    <header className="titlebar">
      <a className="titlebar-brand" href="/" aria-label="UwULock">
        <Nyu size={22} blink={false} title="UwULock" />
        <span className="wordmark">
          <span>UwU</span>Lock
        </span>
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
        >
          <svg viewBox="0 0 24 24" aria-hidden>
            <path d={ICONS.settings} />
          </svg>
        </button>
      )}
    </header>
  );
}
