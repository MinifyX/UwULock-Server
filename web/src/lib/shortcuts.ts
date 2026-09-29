/**
 * Keyboard shortcuts: which keys do what — for the overview behind `?` — and when a key press
 * counts as a shortcut at all.
 *
 * Shortcuts with Ctrl are always on. Those of a single key (`?`, `/`, `N`, `J`, digits) only
 * work outside text fields, dialogs and menus, and can be switched off in the settings: they get
 * in the way of speech input and of screen readers that pass keys through (WCAG 2.1.4).
 */

import { N_ } from './i18n';
import { getSettings } from './settings';

/** One line of the overview: the keys (alternatives, each a chord of key names) and what they do. */
export type Shortcut = { keys: string[][]; label: string; single?: boolean };
export type ShortcutGroup = { title: string; shortcuts: Shortcut[] };

const CTRL = N_('Strg');

export const VAULT_SHORTCUTS: ShortcutGroup[] = [
  {
    title: N_('Überall'),
    shortcuts: [
      { keys: [['?']], label: N_('Diese Übersicht'), single: true },
      { keys: [[CTRL, ',']], label: N_('Einstellungen') },
      { keys: [[CTRL, 'G']], label: N_('Passwort-Generator') },
      { keys: [[CTRL, 'L']], label: N_('Tresor sperren') },
      { keys: [['Esc']], label: N_('Dialog oder Menü schließen, Suche leeren') },
    ],
  },
  {
    title: N_('Tresor'),
    shortcuts: [
      { keys: [[CTRL, 'F']], label: N_('Suchen') },
      { keys: [['/']], label: N_('Suchen'), single: true },
      { keys: [['N']], label: N_('Neuer Eintrag'), single: true },
      { keys: [['J'], ['K']], label: N_('Nächster, voriger Eintrag'), single: true },
      { keys: [['E']], label: N_('Eintrag bearbeiten'), single: true },
      { keys: [['Esc']], label: N_('Aus dem Eintrag zurück zur Liste') },
      { keys: [[CTRL, 'U']], label: N_('Benutzername kopieren') },
      { keys: [[CTRL, 'P']], label: N_('Passwort kopieren') },
      {
        keys: [['1'], ['2'], ['3'], ['4'], ['5']],
        label: N_('Alle Einträge, Favoriten, Sends, Datei-Anfragen, Passwortprüfung'),
        single: true,
      },
    ],
  },
  {
    title: N_('In einer Liste'),
    shortcuts: [
      { keys: [['↑'], ['↓']], label: N_('Nächster, voriger Eintrag') },
      { keys: [[N_('Pos1')], [N_('Ende')]], label: N_('Erster, letzter Eintrag') },
      { keys: [[N_('Eingabe')]], label: N_('Eintrag öffnen') },
      { keys: [[N_('Leertaste')]], label: N_('Eintrag markieren, für mehrere auf einmal') },
      { keys: [[N_('Umschalt'), 'F10']], label: N_('Menü eines Ordners') },
    ],
  },
];

export const ADMIN_SHORTCUTS: ShortcutGroup[] = [
  {
    title: N_('Überall'),
    shortcuts: [
      { keys: [['?']], label: N_('Diese Übersicht'), single: true },
      { keys: [[CTRL, ',']], label: N_('Darstellung') },
      { keys: [['Esc']], label: N_('Dialog schließen') },
    ],
  },
  {
    title: N_('Admin-Portal'),
    shortcuts: [
      {
        keys: [['1'], ['…'], ['9']],
        label: N_('Die ersten neun Seiten der Leiste, von Übersicht bis Backups'),
        single: true,
      },
      { keys: [['J'], ['K']], label: N_('Nächste, vorige Seite'), single: true },
    ],
  },
];

/** Whether `target` takes typing: a text field, a select, an editable area. */
export function typing(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  if (target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement) return true;
  if (target instanceof HTMLInputElement)
    return !['checkbox', 'radio', 'button', 'submit', 'reset', 'range', 'color', 'file'].includes(
      target.type,
    );
  return false;
}

/**
 * Whether `event` may be a shortcut of a single key: no Ctrl, Alt or Meta, nobody typing, no
 * dialog or menu open, not handled already — and single keys switched on.
 */
export function singleKey(event: KeyboardEvent): boolean {
  return (
    getSettings().singleKeys &&
    !event.defaultPrevented &&
    !event.ctrlKey &&
    !event.metaKey &&
    !event.altKey &&
    !event.isComposing &&
    !typing(event.target) &&
    !document.querySelector('.modal, .context-menu')
  );
}
