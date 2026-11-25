# UI building blocks

The web vault, the admin portal and the public pages (Send, file request, register) are built on
[`@uwusuite/design`](https://github.com/MinifyX/UwUSuite-Design): its tokens, fonts, base styles
and motion come in through `web/src/styles/index.css` (Tailwind v4), its components (`Button`,
`IconButton`, `Icon`/`ICONS`, `Dialog`, `Toaster`, `Segmented`, `Switch`, `Card`, `Section`,
`SettingRow`, `Tabs`, `Tag`/`Badge`, `StatTile`, `NavIndicator`, Nyu …) are imported straight from
the package. Their props and rules are in the package docs:
[components](https://github.com/MinifyX/UwUSuite-Design/blob/main/docs/components.md),
[icons](https://github.com/MinifyX/UwUSuite-Design/blob/main/docs/icons.md),
[motion](https://github.com/MinifyX/UwUSuite-Design/blob/main/docs/motion.md),
[Nyu](https://github.com/MinifyX/UwUSuite-Design/blob/main/docs/nyu.md),
[typography](https://github.com/MinifyX/UwUSuite-Design/blob/main/docs/typography.md).
A shared look or a new icon meaning goes into the package first, never into this app.

The view CSS (`web/src/styles/*.css`, in the `components` layer) only places things; colours,
type and radii come from the package tokens.

## What this app adds

`web/src/components/ui/` holds what only this app has:

| Component | Notes |
|---|---|
| `Field`, `TextField`, `Select` | A labelled control with up to three `tools` (IconButtons) inside it, `hint`/`hintTone="warn"`, `error` (sets `aria-invalid`), `hideLabel`. |
| `Checkbox`, `FormRow`, `FieldGroup`, `RepeatRow` | Check boxes, fields side by side (`min` 120/180/240 px), groups of fields, repeated rows. |
| `ButtonRow`, `Table`, `DangerZone` | Wrapping buttons; a table that scrolls sideways on a phone; what cannot be undone, framed apart. |
| `Callout` | The package `Hint` with an icon, a title and actions (`tone` info/accent/ok/warning/error; `error` is announced). |
| `Modal` | The package `Dialog` with this app's rules: no closing by a click beside it, focus on `[data-autofocus]` or the first safe control (`data-secondary` marks the risky ones), focus back on close. Footer: `<span className="spacer" />`, the safe choice, then the main one. |
| `radioArrows`, `radioTab` | Arrow keys and the Tab stop for hand-made radio groups (the font picker). |

Also local: `TitleBar` (the web bar; the package one needs window controls), `ContextMenu`,
`PasswordInput`, `TotpCodes`, `FontPicker` and the Nyu scenes (`components/nyu/`).

## Password manager rule

No value may look different from what it is: contextual alternates are off on fields, code and
buttons (`font-variant-ligatures: no-contextual`) and secrets are set in the mono font.

## Theme and settings

Vault and admin portal share one set of settings (`web/src/lib/settings.ts`, `uwulock.settings`):
theme (*Dark* by default, like every UwU app), contrast, motion and font go through the package's
`applyAppearance`/`applyUiFont`; `/boot.js` (emitted by `web/vite.config.ts` from `bootScript`, external because
the CSP allows no inline script) applies them before the first paint. Older stored font names fall
back to UwU Sans. A change in one tab reaches the other open tabs (`storage` event). Check light,
dark and the phone with `scripts/e2e/local.sh theme`.

## The admin portal

The portal uses the vault's shell: the bar on top, the sidebar (`.nav-row`s with the package
`NavIndicator`, the account card at its foot) and a page with a title, a lead line and the area's
`Tabs`. Its areas and tabs are one list in `web/src/admin/areas.ts`. Every setting is a
`SettingRow`; `Explain` (`web/src/admin/fields.tsx`) adds the recommended value and `NumberInput`
spells the unit out. The settings of all tabs are one draft (`web/src/admin/draft.tsx`): changed on
any tab, the bar at the foot offers *Save* and *Discard*.
