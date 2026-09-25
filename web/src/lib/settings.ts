/**
 * The settings, kept in the page's own storage.
 *
 * Only preferences live here — how things look and behave. No secret and no
 * part of the vault: those stay on the Rust side. Settings Rust needs (the
 * update channel, auto-lock, clipboard clearing) are handed over on start and
 * on every change.
 */

import { useSyncExternalStore } from 'react';
import pkg from '../../package.json';
import { language } from './i18n';

export type ThemeSetting = 'system' | 'light' | 'dark';
/** German or English; "system" follows the language the system prefers. */
export type LanguageSetting = 'system' | 'de' | 'en';
/** Animations: follow the system's reduced-motion setting, or override it. */
export type MotionSetting = 'system' | 'on' | 'off';
/** Beta gets pre-releases (tags like v0.1.0-beta.1) before everyone else. */
export type UpdateChannel = 'stable' | 'beta';
/** Minutes without activity before the vault locks; 0 = only by hand or on restart. */
export type AutoLock = 0 | 1 | 5 | 15 | 30 | 60 | 240;
/** Seconds before a copied value leaves the clipboard; 0 = never. */
export type ClipboardClear = 0 | 10 | 30 | 60 | 120;

export type Settings = {
  language: LanguageSetting;
  theme: ThemeSetting;
  motion: MotionSetting;
  updateChannel: UpdateChannel;
  autoLock: AutoLock;
  clipboardClear: ClipboardClear;
  /** Items in the trash show up in their own section only. */
  showTrash: boolean;
  /** Where the last login went, to fill the login form next time. Not secret. */
  lastServerKind: 'bitwarden-us' | 'bitwarden-eu' | 'self-hosted';
  lastServerUrl: string;
  lastEmail: string;
};

export const DEFAULT_SETTINGS: Settings = {
  language: 'system',
  theme: 'dark',
  motion: 'system',
  // Someone who installed a beta wants the next beta too.
  updateChannel: pkg.version.includes('-') ? 'beta' : 'stable',
  autoLock: 15,
  clipboardClear: 30,
  showTrash: true,
  lastServerKind: 'self-hosted',
  lastServerUrl: '',
  lastEmail: '',
};

const KEY = 'uwulock.settings';

/** Stored values are checked one by one; anything unexpected falls back to its default. */
export function sanitize(raw: unknown): Settings {
  const input = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {};
  const oneOf = <T>(value: unknown, allowed: readonly T[], fallback: T): T =>
    allowed.includes(value as T) ? (value as T) : fallback;
  const bool = (value: unknown, fallback: boolean) =>
    typeof value === 'boolean' ? value : fallback;
  const text = (value: unknown, max: number) =>
    typeof value === 'string' ? value.slice(0, max) : '';
  const d = DEFAULT_SETTINGS;
  return {
    language: oneOf(input.language, ['system', 'de', 'en'] as const, d.language),
    theme: oneOf(input.theme, ['system', 'light', 'dark'] as const, d.theme),
    motion: oneOf(input.motion, ['system', 'on', 'off'] as const, d.motion),
    updateChannel: oneOf(input.updateChannel, ['stable', 'beta'] as const, d.updateChannel),
    autoLock: oneOf(input.autoLock, [0, 1, 5, 15, 30, 60, 240] as const, d.autoLock),
    clipboardClear: oneOf(input.clipboardClear, [0, 10, 30, 60, 120] as const, d.clipboardClear),
    showTrash: bool(input.showTrash, d.showTrash),
    lastServerKind: oneOf(
      input.lastServerKind,
      ['bitwarden-us', 'bitwarden-eu', 'self-hosted'] as const,
      d.lastServerKind,
    ),
    lastServerUrl: text(input.lastServerUrl, 300),
    lastEmail: text(input.lastEmail, 200),
  };
}

function load(): Settings {
  try {
    const raw = window.localStorage.getItem(KEY);
    return sanitize(raw ? JSON.parse(raw) : {});
  } catch {
    return DEFAULT_SETTINGS;
  }
}

let current = load();
const listeners = new Set<() => void>();

export function getSettings(): Settings {
  return current;
}

export function updateSettings(patch: Partial<Settings>) {
  current = sanitize({ ...current, ...patch });
  try {
    window.localStorage.setItem(KEY, JSON.stringify(current));
  } catch {
    // Private storage can be unavailable; the change still holds for this run.
  }
  for (const listener of listeners) listener();
}

export function subscribeSettings(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useSettings(): Settings {
  return useSyncExternalStore(subscribeSettings, getSettings);
}

const darkQuery = () => window.matchMedia('(prefers-color-scheme: dark)');
const reducedQuery = () => window.matchMedia('(prefers-reduced-motion: reduce)');

/** Whether animations should play right now, by setting and system. */
export function motionAllowed(): boolean {
  const { motion } = current;
  return motion === 'on' || (motion === 'system' && !reducedQuery().matches);
}

/** Puts theme and motion on <html>, now and whenever the setting or the system changes. */
export function applyAppearance() {
  const apply = () => {
    const { theme } = current;
    const dark = theme === 'dark' || (theme === 'system' && darkQuery().matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    document.documentElement.lang = language(current);
    if (motionAllowed()) delete document.documentElement.dataset.motion;
    else document.documentElement.dataset.motion = 'reduced';
  };
  apply();
  subscribeSettings(apply);
  darkQuery().addEventListener('change', apply);
  reducedQuery().addEventListener('change', apply);
}
