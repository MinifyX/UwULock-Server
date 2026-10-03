# Accessibility

The web vault and the admin portal aim at **WCAG 2.2 level AA**: everything works with the
keyboard alone, with a screen reader, and in a high-contrast mode. This page lists the keyboard
shortcuts, what the high-contrast mode does, notes for screen-reader users, how it is tested, and
what is known not to be there yet.

## Keyboard

Everything is reachable with Tab and Shift+Tab, in the order it is on screen, with a visible focus
ring. The first Tab on a page reaches **Skip to content**, which jumps past the bar and the
sidebar: to the item list in the vault, to the page in the admin portal.

- **Dialogs** take the focus when they open (their first field, or the safe choice of a warning),
  keep Tab inside while they are open, close with Escape, and hand the focus back to where it was.
- **Menus** (*New*, a folder's menu) move with the arrow keys, Home and End; Enter picks, Escape
  or Tab closes, and the focus goes back to where it was.
- **Lists** (items, Sends, file requests) are one stop for Tab: the arrow keys, Page Up/Down, Home
  and End move through them, Enter opens the entry, Space ticks it for doing something to several
  at once (Shift+Space ticks a range).
- **Choices** shown as buttons in a row (theme, language, …) are radio groups: Tab reaches the
  picked one, the arrow keys change it.

### Shortcuts

`?` shows all shortcuts, in both places; so does the keyboard button in the bar. Button tooltips
name their shortcut too.

Shortcuts with Ctrl (⌘ on a Mac) always work. Those of a **single key** only work outside text
fields, dialogs and menus, and can be switched off — *Settings → Appearance → Single-key
shortcuts*, or in the overview itself — for speech input and screen readers that pass keys
through (WCAG 2.1.4).

#### Web vault

| Keys                   | Action                                                       |
| ---------------------- | ------------------------------------------------------------ |
| `?`                    | The shortcut overview (single key)                           |
| `Ctrl`+`,`             | Settings                                                     |
| `Ctrl`+`G`             | Password generator                                           |
| `Ctrl`+`L`             | Lock the vault                                               |
| `Esc`                  | Close a dialog or menu, clear the search                     |
| `Ctrl`+`F`, `/`        | Search (`/` is a single key)                                 |
| `N`                    | New item (single key)                                        |
| `J`, `K`               | Next, previous item (single keys)                            |
| `E`                    | Edit the item (single key)                                   |
| `Esc` in an item       | Back to the list                                             |
| `Ctrl`+`U`, `Ctrl`+`P` | Copy the username, the password of the selected login        |
| `1` … `5`              | All items, Favorites, Sends, File requests, Password check   |
| `↑` `↓`, Home, End     | In a list: next, previous, first, last entry                 |
| Enter                  | In a list: open the entry                                    |
| Space                  | In a list: tick the entry (with Shift: everything up to it)  |
| Shift+`F10`, menu key  | On a folder in the sidebar: its menu (rename, delete)        |

The desktop app's `Ctrl`+`T` (copy the one-time code) does not exist in the browser: browsers
keep that key for a new tab.

#### Admin portal

| Keys       | Action                                                             |
| ---------- | ------------------------------------------------------------------ |
| `?`        | The shortcut overview (single key)                                 |
| `Ctrl`+`,` | Appearance (language, theme, contrast, animations)                 |
| `Esc`      | Close a dialog                                                     |
| `1` … `9`  | The areas of the sidebar, from the top (single)                    |
| `J`, `K`   | Next, previous area (single keys)                                  |
| `←`, `→`   | In an area's tabs: previous, next tab                              |

## High contrast

*Settings → Appearance → Contrast*: **System** (the default) follows the system's wish for more
contrast (`prefers-contrast: more`, e.g. macOS *Increase contrast*); **High** switches it on,
**Normal** off. In the admin portal the same setting is behind the gear in the bar; both share it,
like the theme.

High contrast replaces the colour tokens (`web/src/styles/tokens.css`) for the light and the dark
theme: black on white and white on black, quiet text and borders at 7:1 or more, an accent dark
(or light) enough to be text, a thicker focus ring in the text colour, underlined links, plain
outlined tiles, and a bar next to the selected item and the current page besides their tint. It
wins over the accent colour an admin chose under *Branding*: that colour stays for everybody else.

Windows' contrast themes (`forced-colors: active`) take over the colours entirely; there the
selected item, the current page and the switches are marked with outlines in the system's
highlight colour, since the backgrounds that normally show them are gone.

Outside high contrast, the normal themes meet AA too: text 4.5:1, and the outlines of fields,
selects, switches and check boxes 3:1 (their own token, `--uwu-control`).

## Screen readers

- Landmarks: the bar is a banner, the sidebars are navigation, the page is `main`; the vault has
  a (hidden) heading of its own, the admin portal a visible one per area and a hidden one per
  tab, and headings go in
  order below that.
- Every button that shows only an icon has a name; decorative pictures (Nyu, icons next to text)
  are hidden; logos have their text next to them. Buttons that switch something say whether it is
  on (`aria-pressed`, switches, radio groups), menus whether they are open, sidebars which entry
  is the current one.
- Lists are list boxes: the focus stays on the list and the reader announces the selected entry
  (and whether it is ticked). Enter opens it; in the vault the focus moves into the item, and
  Escape brings it back to the list.
- Errors of the login, unlock, registration and master-password forms are tied to their field
  (`aria-invalid`, `aria-describedby`) and read out when they appear; so are the Caps Lock hint and
  the password rules on registering.
- Notes at the bottom ("Copied", "Saved") are read out politely, errors at once: the live regions
  are always on the page, so readers notice what appears in them.
- The password generator says "New password generated" with each roll, not the password: it is
  never read out on its own, so nobody in the room hears it. Move to it to hear it.
- The page's language (`<html lang>`) follows the chosen language.
- Single-key shortcuts can be switched off (see above) if they get in the way of the reader's own
  keys.

## What is tested

The browser tests run **axe-core** (a devDependency of `scripts/e2e`, injected from the package,
never a CDN) through `scripts/e2e/axe.mjs`, with the rule tags `wcag2a`, `wcag2aa`, `wcag21a`,
`wcag21aa` and `wcag22aa`. Serious and critical findings fail the test; minor and moderate ones
are printed as notes. Each check takes 60–350 ms; together they add about three seconds.

| Script           | Checked                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| `web.mjs`        | Register page, vault with an item selected, settings (dark and light), login page, admin overview, accounts, master password, storage, and *Branding* in high contrast |
| `features.mjs`   | Sends view, the public Send page, the password check                    |
| `operations.mjs` | File requests view, the public file request page (with a wrong password, and open) |

`web.mjs` also drives the keyboard: `?` opens the overview and Escape gives the focus back to the
list, `N` opens the new-item menu and Escape gives it back again, Space ticks an entry of the
list, `7`, `8`, `J` and `K` switch areas of the admin portal.

## Known gaps

- axe finds what can be found automatically — perhaps half of all problems. Nothing has been
  tried yet with NVDA, JAWS, VoiceOver or TalkBack by people who use them daily; reports are
  welcome.
- Form errors outside the login, unlock, registration and master-password forms (the item editor,
  many admin forms) are announced (`role="alert"`) but not yet tied to a field.
- Results that appear under a setting ("Saved", test mails) are `role="status"` elements that
  appear with their text; some screen readers do not read those out.
- The charts of the admin overview are pictures with a summary as their name, not tables.
- The branding page's previews show the chosen colours as they are, in high contrast too.
- At 320 px (or 400 % zoom) the admin portal's sidebar and an area's tabs
  become rows that scroll sideways;
  everything else reflows.
