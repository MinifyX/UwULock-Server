import { FONT_CHOICES, FONT_NAMES, FONT_STACKS, type FontChoice } from '../lib/fonts';
import { t } from '../lib/i18n';
import { updateSettings, useSettings } from '../lib/settings';
import { radioArrows, radioTab } from './ui';

function fontName(choice: FontChoice) {
  return choice === 'system' ? t('Systemschrift') : FONT_NAMES[choice];
}

/**
 * Darstellung → Schrift: every choice shown in itself, as in UwUMail. A radio group, so the arrow
 * keys move between the fonts.
 */
export function FontPicker() {
  const { font } = useSettings();
  return (
    <div
      className="font-picker"
      role="radiogroup"
      aria-label={t('Schrift')}
      onKeyDown={radioArrows}
    >
      {FONT_CHOICES.map((choice, index) => (
        <button
          key={choice}
          type="button"
          role="radio"
          aria-checked={font === choice}
          tabIndex={radioTab(font === choice, index === 0, true)}
          onClick={() => updateSettings({ font: choice })}
          style={{ fontFamily: FONT_STACKS[choice] }}
        >
          <span className="font-picker-name">{fontName(choice)}</span>
          {/* Letters that look alike in many fonts: how well this one tells them apart. */}
          <span className="font-picker-sample">{t('Tresor · 0O 1lI · Ää ✧')}</span>
        </button>
      ))}
    </div>
  );
}
