import { afterEach, describe, expect, it } from 'vitest';
import { anchored } from './ContextMenu';

const fit = (max: number, size: number) => (value: number) =>
  Math.max(8, Math.min(value, max - size - 8));

function place(anchor: { left: number; top: number; bottom: number }, height: number) {
  const size = { width: 210, height };
  return anchored(
    { ...anchor, right: anchor.left + 200 },
    size,
    fit(window.innerWidth, size.width),
    fit(window.innerHeight, size.height),
  );
}

describe('a menu opened from a button', () => {
  const { innerHeight, innerWidth } = window;
  afterEach(() => {
    Object.defineProperty(window, 'innerHeight', { value: innerHeight, configurable: true });
    Object.defineProperty(window, 'innerWidth', { value: innerWidth, configurable: true });
  });

  it('sits above the account card at the foot of the sidebar, not over it', () => {
    Object.defineProperty(window, 'innerHeight', { value: 800, configurable: true });
    const card = { left: 12, top: 730, bottom: 788 };
    const { x, y } = place(card, 90);
    expect(x).toBe(12);
    expect(y + 90).toBeLessThanOrEqual(card.top);
    expect(y).toBeGreaterThanOrEqual(8);
  });

  it('goes below a button with no room above it', () => {
    Object.defineProperty(window, 'innerHeight', { value: 800, configurable: true });
    const button = { left: 12, top: 20, bottom: 50 };
    const { y } = place(button, 90);
    expect(y).toBeGreaterThanOrEqual(button.bottom);
  });

  it('stays inside a small window when it fits neither above nor below', () => {
    Object.defineProperty(window, 'innerHeight', { value: 200, configurable: true });
    const { y } = place({ left: 12, top: 60, bottom: 140 }, 150);
    expect(y).toBeGreaterThanOrEqual(8);
    expect(y + 150).toBeLessThanOrEqual(200);
  });

  it('keeps its left edge inside a phone-wide window', () => {
    Object.defineProperty(window, 'innerWidth', { value: 360, configurable: true });
    const { x } = place({ left: 300, top: 700, bottom: 760 }, 90);
    expect(x + 210).toBeLessThanOrEqual(360 - 8);
  });
});
