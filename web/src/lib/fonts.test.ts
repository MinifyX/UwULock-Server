import { describe, expect, it } from 'vitest';
import { applyFont, FONT_CHOICES, FONT_NAMES, FONT_STACKS, isFontChoice } from './fonts';

describe('the fonts', () => {
  it('knows its choices and nothing else', () => {
    for (const choice of FONT_CHOICES) expect(isFontChoice(choice)).toBe(true);
    for (const other of ['', 'Manrope', 'comic', undefined, null, 1, {}])
      expect(isFontChoice(other)).toBe(false);
  });

  it('falls back to the system font for every web font', () => {
    for (const choice of FONT_CHOICES)
      expect(FONT_STACKS[choice]).toMatch(/system-ui.*sans-serif$/);
    expect(FONT_STACKS.uwu.startsWith('"UwU Sans"')).toBe(true);
    expect(FONT_STACKS.manrope.startsWith('"Manrope Variable"')).toBe(true);
    expect(FONT_NAMES.dmsans).toBe('DM Sans');
  });

  it('puts the chosen font on the page', () => {
    const root = document.createElement('html');
    applyFont('rubik', root);
    expect(root.style.getPropertyValue('--uwu-font')).toBe(FONT_STACKS.rubik);
    expect(root.dataset.font).toBe('rubik');
    applyFont('system', root);
    expect(root.style.getPropertyValue('--uwu-font')).toBe(FONT_STACKS.system);
    expect(root.style.getPropertyValue('--uwu-tracking')).toBe('0em');
  });
});
