# Accessibility

The web vault and the admin portal aim at **WCAG 2.2 level AA**: everything works with the
keyboard alone, with a screen reader, and in a high-contrast mode. This page lists the keyboard
shortcuts, what the high-contrast mode does, notes for screen-reader users, how it is tested (also
with Orca, a real screen reader), and what is known not to be there yet.

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

- The page's title names the screen (*Anmelden – UwULock*, *Tresor – UwULock*, *Funktionen –
  Tresor & Funktionen – Admin-Portal – UwULock*). When the screen changes — logged in, unlocked,
  registered, another section by its number key, another admin area by its key — the focus moves
  to the new content (the vault's list, the admin area's page), so the reader says where it is
  instead of nothing; a screen that focuses a field of its own (the unlock screen) keeps that.
- Fields and buttons keep the focus while the form works: the login's, unlock's and code's fields
  are read-only, not switched off, while they wait for the server, so a wrong password is read out
  and the focus is still in the field for the next try. A button or switch that is switched off
  while it saves (a feature switch of the admin portal, *Nochmal prüfen*, the star of an item)
  hands the focus to the form or page around it and gets it back afterwards
  (`web/src/lib/focus.ts`).
- Landmarks: the bar is a banner, the sidebars are navigation, the page is `main`; the vault has
  a (hidden) heading of its own, the admin portal a visible one per area and a hidden one per
  tab, and headings go in
  order below that.
- Every button that shows only an icon has a name; decorative pictures (Nyu, icons next to text)
  are hidden; logos have their text next to them. Buttons that switch something say whether it is
  on (`aria-pressed`, switches, radio groups), menus whether they are open, sidebars which entry
  is the current one. A toggle button keeps one name and says its state only by being pressed or
  not (*Passwort zeigen*, *Favorit*, *Archiviert*); its tooltip may say what a click does.
  Buttons repeated per row name their row (*Öffnen: Shop*, *Feld hinzufügen: Text*).
- Password fields are named by their label alone. A `<label>` around a field names it with all
  its text, so `PasswordInput` inside one takes `label` too: otherwise the eye's *Passwort zeigen*
  and the strength line ended up in the field's name.
- Hidden secrets read *verborgen* instead of a row of dots; the one-time code's countdown says
  *noch 25 Sekunden gültig* rather than a bare number.
- A setting row's line about it is the description of its switch, select or choice, so the reader
  says what *Reisemodus* does along with *an* or *aus*. A row with buttons instead (*Einrichten …*)
  is a group named after the setting, so the reader says which setting the button belongs to.
- Lists are list boxes: the focus stays on the list and the reader announces the selected entry
  (and whether it is ticked). Enter opens it; in the vault the focus moves into the item, and
  Escape brings it back to the list.
- Errors of the login, unlock, registration and master-password forms are tied to their field
  (`aria-invalid`, `aria-describedby`) and read out when they appear; so are the Caps Lock hint and
  the password rules on registering.
- Notes at the bottom ("Copied", "Saved") are read out politely, errors at once: the live regions
  are always on the page, so readers notice what appears in them.
- Dialogs keep the focus inside even when something else tries to move it (a click on the page, a
  reader's own cursor), and take it on opening even when the button meant to have it waits for its
  content (the generator's *Übernehmen*).
- The password check's stack of cards says each move with the card's name (*2 von 3: Shop*);
  *Zurück* and *Weiter* at the ends are `aria-disabled`, not disabled, so they keep the focus.
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

What the Orca test below found is locked in where it is cheap (ARIA and focus checks on pages the
tests open anyway): `web.mjs` checks the password field's and the eye's names on registering, the
title and the focus on the vault after registering and after unlocking, a wrong unlock password
that leaves the focus in its field, *verborgen* and the star's state in an item, and the title and
the focus after `7` in the admin portal; `review.mjs` checks the card's name in the live region,
the focus kept by *Zurück* on the first card, and the focus in the generator. The unit tests in
`web/src/components/ui/a11y.test.tsx` check the setting rows, `PasswordInput`, `Masked` and the
focus kept through a busy button.

## Tested with Orca

On 2026-10-02 the web vault and the admin portal (0.7.0-beta.2 plus these fixes, German and once
in English) were gone through with **Orca 46.1**, the GNOME screen reader, in **Chromium 153**
(Chrome for Testing). Orca ran in a container: Ubuntu 24.04 with Xvfb, a D-Bus session,
at-spi2-core 2.52, speech-dispatcher with espeak-ng into PulseAudio's null sink, and Openbox;
Chromium with `--force-renderer-accessibility`. Keys went in as real X key events (`xdotool`), so
Orca saw them as a user's (Tab, Shift+Tab, Enter, Space, arrows, Escape, its browse mode's
arrows); what Orca said came from its debug log (`orca --debug-file`, the `SPEECH OUTPUT` lines).
Playwright only set things up over CDP (opening a page, typing text) and never sent keys Orca was
meant to hear.

Gone through: registering, logging in (a wrong password too), the unlock screen, the vault with
its list, search and sidebar, the new-item menu, the editor of a login (every field, a one-time
code, own fields), an item's details read in browse mode, the password generator, Sends and a new
text Send, the password check and its stack of cards, the settings (two-step login, emergency
access), the shortcut overview, toasts and errors, dialogs (focus inside, Escape, focus back), and
in the admin portal the areas, their tabs, the failed logins with their table and the feature
switches.

**Found and fixed:** the password fields were named "Master-Passwort Passwort zeigen Stärke: geht
so Mindestens 12 Zeichen"; the eye said "Passwort verbergen, gedrückt"; after logging in,
unlocking or registering the focus was on nothing and Orca said nothing; a wrong password at
login or unlock dropped the focus (fields switched off while waiting), so the next Tab started at
the page's top; the page's title was always *UwULock*; a feature switch, *Jetzt prüfen* and the
last *Weiter* of the cards dropped the focus; the generator opened from a card left the focus
behind the dialog; the section keys `1`–`5` dropped the focus with the list; seven *Öffnen* in
the password report without saying what; Bitwarden's English "Username or password is incorrect"
inside the German page; dots read one by one for hidden secrets and a bare number for the code's
countdown; *Einrichten …* three times without its setting; feature switches without what they do;
"1 neue Hinweise"; a missing space in "Passwort ändern(neues Fenster)"; the add buttons of own
fields named only *Text*, *Versteckt*, *Ja/Nein*, and the focus staying on them after adding one.

Before and after, as Orca said it (`|` between utterances):

```
Tab to the master password on registering
  before: Master-Passwort Passwort zeigen Stärke: geht so Mindestens 12 Zeichen. password text
  after:  Master-Passwort password text

Enter with a wrong master password at unlock
  before: Das Master-Passwort ist falsch.            (focus: the page's body)
  after:  Das Master-Passwort ist falsch.            (focus: still the password field)

Enter with the right one
  before: (nothing; focus on the page's body)
  after:  Alle Einträge region | List with 4 items | Bank nyu.bank.

Weiter on the last card of the password check
  before: 2 von 3                                    (focus: the page's body)
  after:  3 von 3: Mailkonto                         (focus: still on Weiter)
```

**What Orca does on its own:** in browse mode it takes single letters and digits for its own
navigation (`H`, `K`, `1`–`6`, …), so the single-key shortcuts reach the page only in focus mode
(Orca+A switches) — or switch them off. It does not say `aria-current`, so the current entry of a
sidebar is only seen, not heard, in Orca (NVDA and VoiceOver say it). Chromium gives tab panels
the role *scroll pane*, which Orca reads as such.

## Known gaps

- axe finds what can be found automatically — perhaps half of all problems. Orca has been tried
  (above), by script; NVDA, JAWS, VoiceOver and TalkBack not yet, and nothing by people who use a
  screen reader daily; reports are welcome.
- Form errors outside the login, unlock, registration and master-password forms (the item editor,
  many admin forms) are announced (`role="alert"`) but not yet tied to a field.
- Results that appear under a setting ("Saved", test mails) are `role="status"` elements that
  appear with their text; Orca reads them out, some other screen readers may not.
- The charts of the admin overview are pictures with a summary as their name, not tables.
- The branding page's previews show the chosen colours as they are, in high contrast too.
- At 320 px (or 400 % zoom) the admin portal's sidebar and an area's tabs
  become rows that scroll sideways;
  everything else reflows.
