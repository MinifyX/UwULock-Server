# UwU Sans

The interface font of UwUMail, and the default font of UwULock's web vault and admin portal: [Atkinson Hyperlegible Next](https://github.com/googlefonts/atkinson-hyperlegible-next)
with its letters untouched, plus Nyu (U+E000), a heart (U+2665), arrows
(U+2190-2193) and `calt` ligatures for `:3` and `<3`. Variable, weight
200-800, about 48 KB as WOFF2. License: SIL OFL 1.1 ([OFL.txt](OFL.txt)),
changes in [FONTLOG.txt](FONTLOG.txt).

## What changed

- Renamed per the OFL (family `UwU Sans`), MinifyX copyright line added.
- Subset to Latin, Latin Extended, punctuation, currency, arrows.
- New glyphs Nyu, heart and arrows, drawn as code in `build.py` with
  variation deltas so their stroke follows the weight.
- `:3` turns into Nyu and `<3` into a heart, but never next to a letter or
  digit: `10:30`, `9:30`, `3:33`, `x<3`, `1<35`, `3<3`, `a<3b` stay as they
  are. Turn it off with `font-variant-ligatures: no-contextual` (UwULock's web
  vault does this on the whole page: a password, a name or a value must
  always look exactly like what it is).
- Nothing else: letter shapes, spacing, kerning and `tnum` are upstream's.

## Copies

This folder is a copy from UwUMail (UwUMail-Client, `brand/fonts/uwu-sans/`),
where the font is built (`build.py`, see the README there). It holds only the
licence, the font log and this README; the build scripts stay in UwUMail.

The built font is used here at `web/src/assets/fonts/UwUSans[wght].woff2` and
must stay byte-identical with UwUMail's
(`apps/desktop/src/assets/fonts/UwUSans[wght].woff2` in UwUMail-Client,
`src/assets/fonts/UwUSans[wght].woff2` in UwUMail-Webmail). After a rebuild
in UwUMail, copy the WOFF2 and these three files over by hand.
