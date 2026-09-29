# UI building blocks

The web vault and the admin portal are built from one set of components in
`web/src/components/ui/` (imported from `'../ui'` or `'./ui'`). Their styles live in
`web/src/styles/ui.css`, their sizes and gaps in `web/src/styles/tokens.css`. A view adds layout
(where things go) in its own CSS, never its own button, field, card or heading look.

## Tokens

| What | Tokens |
|---|---|
| Spacing (a 4 px scale) | `--uwu-space-1` 4 · `-2` 8 · `-3` 12 · `-4` 16 · `-5` 20 · `-6` 24 · `-8` 32 · `-10` 40 |
| Type | `--uwu-text-xs` 11 · `-sm` 12.5 (labels, hints) · `-md` 13 (descriptions) · `-base` 14 (body) · `-lg` 18 · `-xl` 22; `--uwu-leading` 1.5, `--uwu-leading-tight` 1.3 |
| Radius | `--uwu-radius-small` 8 · `-control` 10 · `-card` 16 · `-pill` |
| Controls | `--uwu-control-height` 36 (fields, selects and buttons alike) · `-small` 30 · `--uwu-icon-button` 28 · `-small` 24 (never less, WCAG 2.5.8) |
| Layout | `--uwu-label-gap` 6 · `--uwu-form-gap` 16 · `--uwu-card-pad-x` 16 / `-y` 12 · `--uwu-section-gap` 24 · `--uwu-dialog-pad` 24 |
| Shadows | `--uwu-shadow-float` (dialogs) · `--uwu-shadow-menu` (menus) |

A value that is not on these scales needs a reason in a comment.

## Components

| Component | Props | Notes |
|---|---|---|
| `Button` | `variant?: 'default' \| 'primary' \| 'danger' \| 'quiet' \| 'quiet-danger'`, `size?: 'default' \| 'small'`, `icon?: IconName`, button attributes | `type="button"` unless told otherwise. One `primary` per view. |
| `IconButton` | `label`, `icon`, `size?: 'default' \| 'small'`, button attributes | `label` is the accessible name and the tooltip. |
| `Field` | `label`, `hint?`, `hintTone?: 'default' \| 'warn'`, `error?`, `tools?`, `hideLabel?`, one control as child | Gives the control its id, `aria-describedby` and `aria-invalid`. `tools` (up to three IconButtons) sit inside the control, at its end. |
| `TextField` | `label`, `value`, `onChange(value)`, `hint?`, `error?`, `tools?`, `mono?`, input attributes | A Field around an input. |
| `Select` | `value`, `options: {value, label}[]`, `onChange(value)`, `label?`, `disabled?`, `id?` | Wrap in a Field for a visible label. |
| `Checkbox` | `label`, `checked`, `onChange(checked)`, `disabled?` | Several in a `<div className="checks">`. |
| `Toggle` | `label`, `checked`, `onChange(checked)`, `disabled?` | A switch; the row beside it says what it does. |
| `Segmented` | `label`, `value`, `options: {value, label}[]`, `onChange(value)`, `wide?` | A radio group with arrow keys. |
| `FormRow` | `min?: 'narrow' \| 'default' \| 'wide'` (120/180/240 px) | Fields side by side as they fit, stacked on a phone. |
| `FieldGroup` | `title`, `description?`, `actions?` | A group of fields under a small heading, with its "add" buttons below. |
| `RepeatRow` | `aux?: 'wide' \| 'narrow'` | A repeated row: main control, optional second one, remove button. |
| `Card` | `heading?`, `aside?`, `as?: 'section' \| 'div' \| 'li' \| 'article'` | A framed block with an optional head. |
| `Section` | `heading?`, `lead?` | A part of a page or settings section, with the shared small heading. |
| `SettingRow` | `label`, `description?`, children = the control | The control wraps below the text on a phone. |
| `ButtonRow` | `end?` | Buttons side by side that wrap. |
| `Tabs` | `label`, `tabs: {id, label, extra?, disabled?}[]`, `value`, `onChange(id)`, `variant?: 'line' \| 'segmented'`, `idPrefix?` | Arrow keys, Home and End; roving tab stop. With `idPrefix` (from `useTabsId()`), `TabPanel` names its tab. |
| `TabPanel` | `idPrefix`, `tab`, `className?` | The picked tab's content. |
| `Badge` | `tone?: 'accent' \| 'ok' \| 'alarm' \| 'neutral'`, `label?` | A count or a state on a pill; `label` explains a bare number. |
| `Callout` | `tone?: 'info' \| 'accent' \| 'ok' \| 'warning' \| 'error'`, `title?`, `icon?: IconName \| null`, `actions?` | A notice in a page or dialog; `error` is announced. |
| `Table` | `label?`, `head` (the `<th>`s), rows as children | Scrolls sideways inside its frame on a phone. |
| `Modal` | `title`, `onCancel`, `footer?`, `size?: 'default' \| 'wide'`, `tone?: 'default' \| 'warning'`, `closable?` | Focus trap, Escape, scroll hairlines on the body. Footer: `<span className="spacer" />`, then the safe choice (`data-secondary`), then the primary one. |

Plain classes for what needs no component: `.form` (a form's rows with even gaps),
`.form-note`, `.form-error`, `.field-hint`, `.checks`, `.button-link`, `.settings-heading` and
`.settings-lead`.
