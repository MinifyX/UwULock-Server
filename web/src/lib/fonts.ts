/**
 * The font of the web vault and the admin portal (Settings → Darstellung → Schrift), the same
 * choice UwUMail offers. Kept on this device only, with the other settings (lib/settings.ts).
 *
 * The page gets the font through `--uwu-font` on <html>; the web fonts are declared in
 * styles/fonts.css (UwU Sans) and by @fontsource (imported in main.tsx). All of them come from
 * this server, and the browser only fetches the one in use.
 *
 * UwU Sans has no ligatures (`:3` and `<3` stay as typed). In a password manager no value may
 * look different from what it is, so app.css still switches contextual alternates off for the
 * whole page: JetBrains Mono, the font of values and code, would join "->", "!=" or "==".
 */

export const FONT_CHOICES = ['uwu', 'manrope', 'rubik', 'dmsans', 'system'] as const;
export type FontChoice = (typeof FONT_CHOICES)[number];

export const DEFAULT_FONT: FontChoice = 'uwu';

const SYSTEM_STACK =
  'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", "Noto Sans", Arial, sans-serif';

/** The family list for each choice; a web font falls back to the system's. */
export const FONT_STACKS: Record<FontChoice, string> = {
  uwu: `"UwU Sans", ${SYSTEM_STACK}`,
  manrope: `"Manrope Variable", "Manrope", ${SYSTEM_STACK}`,
  rubik: `"Rubik Variable", ${SYSTEM_STACK}`,
  dmsans: `"DM Sans Variable", ${SYSTEM_STACK}`,
  system: SYSTEM_STACK,
};

/** The names the picker shows; font names stay untranslated ("System" is translated there). */
export const FONT_NAMES: Record<Exclude<FontChoice, 'system'>, string> = {
  uwu: 'UwU Sans',
  manrope: 'Manrope',
  rubik: 'Rubik',
  dmsans: 'DM Sans',
};

/**
 * A little tighter than the fonts are set, for interface text. UwU Sans (Atkinson Hyperlegible) is
 * spaced generously for reading; the others are fine as they come. As in UwUMail.
 */
export const FONT_TRACKING: Record<FontChoice, string> = {
  uwu: '-0.008em',
  manrope: '0em',
  rubik: '0em',
  dmsans: '-0.004em',
  system: '0em',
};

export function isFontChoice(value: unknown): value is FontChoice {
  return (FONT_CHOICES as readonly unknown[]).includes(value);
}

/** Puts the chosen font on the whole page at once. */
export function applyFont(choice: FontChoice, root: HTMLElement = document.documentElement) {
  root.style.setProperty('--uwu-font', FONT_STACKS[choice]);
  root.style.setProperty('--uwu-tracking', FONT_TRACKING[choice]);
  root.dataset.font = choice;
}
