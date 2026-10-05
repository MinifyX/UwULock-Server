# UwU Sans

The interface font of UwUMail, and the default font of UwULock's web vault and admin portal: [Atkinson Hyperlegible Next](https://github.com/googlefonts/atkinson-hyperlegible-next)
with its letters untouched, plus Nyu (U+E000), a heart (U+2665), arrows
(U+2190-2193). Variable, weight
200-800, about 48 KB as WOFF2. License: SIL OFL 1.1 ([OFL.txt](OFL.txt)),
changes in [FONTLOG.txt](FONTLOG.txt).

## What changed

- Renamed per the OFL (family `UwU Sans`), MinifyX copyright line added.
- Subset to Latin, Latin Extended, punctuation, currency, arrows.
- New glyphs Nyu, heart and arrows, drawn as code in `build.py` with
  variation deltas so their stroke follows the weight.
- No ligatures. Nyu and the heart only appear where their code point is
  used; `:3` and `<3` stay as typed. (1.000 turned them into Nyu and a heart
  with `calt`; 1.100 dropped that because it changed what the symbols mean.)
- Nothing else: letter shapes, spacing, kerning and `tnum` are upstream's.

## Copies

This folder is a copy from UwUSuite-Design (`fonts/uwu-sans-source/`), where
the font is built (`build.py`, see the README there). It holds only the
licence, the font log and this README; the build scripts stay there.

The built font is used here at `web/src/assets/fonts/UwUSans[wght].woff2` and
must stay byte-identical with the package's `fonts/UwUSans[wght].woff2`. After
a rebuild there, copy the WOFF2 and these three files over by hand.
