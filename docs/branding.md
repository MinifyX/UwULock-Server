# Branding

UwULock comes pink, with Nyu the lock cat. When the server belongs to a club, a family business or
a school, it can wear their name and colour instead — in the web vault, on the login, on the pages
of Sends and file requests, and in the mails the server writes. The official Bitwarden apps stay
as they are: they have no way to show another look.

## What can be changed

Under *Admin portal → Branding*:

| | What it does |
|---|---|
| **Name** | Shown instead of "UwULock" in the title bar, the browser tab, and the mails: their heading, their footer, the subject where it names the server, and the sender's name when the mail settings give none of their own. At most 40 characters. |
| **Accent colour** | One colour, picked from the suggestions or freely. It needs at least 3:1 contrast against white and against the dark theme's background (`#141016`) — the page says the two numbers before you save. Every other shade for the light and the dark theme is worked out from it (the same palette code as UwUMail Server), and each is moved until its text reads at 4.5:1 or better. A preview shows a button, a link and a tint in both themes. |
| **Logo, light theme / dark theme** | Replaces Nyu in the title bar and beside the login, Send and file-request pages. With only one of the two, it is used for both themes. At most 512 KB; kept at most 512 pixels wide or high. |
| **Favicon** | The icon in the browser tab. At most 128 KB; kept at most 192 pixels. |

Pictures may be PNG, JPEG, WebP, GIF, ICO or SVG. The server recognises them by their content,
never by the name or the type the browser claims, and **draws each one again as a PNG**: whatever
else was in the file — metadata, a script in an SVG, a second image behind the first — never comes
out again. An SVG is drawn without fonts, text or anything it points to, so a logo cannot make a
visitor's browser load something from elsewhere. The pictures are served with `nosniff` and a
sandboxing Content-Security-Policy.

Leaving the name and colour empty (*Reset name and colour*) and removing the pictures gives
UwULock exactly as it comes: without a chosen colour, nothing is overridden and the built-in pink
stays as designed.

Everything is kept in the database, so it is part of every backup, and comes back with a restore.
Each change is written to the admin event log.

## How it works

- The web vault's page (`/`, `/admin`, `/r/<id>`) carries the branding before any script runs:
  the `<title>`, the favicon link, and a `<style id="uwu-branding">` with the accent tokens for
  both themes (`--uwu-pink`, `--uwu-pink-solid`, `--uwu-pink-ink`, …). The high-contrast mode
  still wins over them.
- `GET /uwu/v1/branding` (no login) and the `branding` object in `GET /uwu/v1/info` say
  `{ name, color, custom, logoLight, logoDark, favicon }`, the pictures as absolute URLs with a
  version, so browsers fetch them again only after a change. The pictures themselves are at
  `/uwu/v1/branding/logo/light`, `/logo/dark` and `/favicon`.
- The admin API: `GET|PUT /uwu/v1/admin/branding` (`{ name, color }`, `null` for UwULock's),
  `GET /uwu/v1/admin/branding/preview?color=%23…` for the shades and the contrast,
  `PUT|DELETE /uwu/v1/admin/branding/logo/{light|dark}` and `/favicon` with the file as the body.
  Details in [uwu-api.md §14.4](uwu-api.md).
- Mails take the name, and the shade of the colour made for white text on it for the heading and
  the buttons.

## Send domains

Branding is stored per *scope*: the server's own now, and one per send domain once send domains
arrive (Stufe 6) — a Send opened on `send.example.com` then shows that domain's name, colours and
logo, and the code mail for it carries them too. Until a domain has its own, it shows the
server's.
