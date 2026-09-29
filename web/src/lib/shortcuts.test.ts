import { afterEach, describe, expect, it } from 'vitest';
import { sanitize, updateSettings } from './settings';
import { singleKey, typing } from './shortcuts';

const key = (init: KeyboardEventInit, target: EventTarget = document.body) => {
  const event = new KeyboardEvent('keydown', { bubbles: true, cancelable: true, ...init });
  Object.defineProperty(event, 'target', { value: target });
  return event;
};

describe('shortcuts', () => {
  afterEach(() => {
    updateSettings({ singleKeys: true });
    document.body.innerHTML = '';
  });

  it('knows text fields from other controls', () => {
    const text = document.createElement('input');
    const box = document.createElement('input');
    box.type = 'checkbox';
    expect(typing(text)).toBe(true);
    expect(typing(document.createElement('textarea'))).toBe(true);
    expect(typing(document.createElement('select'))).toBe(true);
    expect(typing(box)).toBe(false);
    expect(typing(document.createElement('button'))).toBe(false);
  });

  it('takes a single key only outside fields and dialogs, and only when switched on', () => {
    expect(singleKey(key({ key: '?' }))).toBe(true);
    expect(singleKey(key({ key: 'n', ctrlKey: true }))).toBe(false);
    expect(singleKey(key({ key: 'n' }, document.createElement('input')))).toBe(false);

    const dialog = document.createElement('div');
    dialog.className = 'modal';
    document.body.append(dialog);
    expect(singleKey(key({ key: '?' }))).toBe(false);
    dialog.remove();

    updateSettings({ singleKeys: false });
    expect(singleKey(key({ key: '?' }))).toBe(false);
  });

  it('keeps the contrast setting to what it knows', () => {
    expect(sanitize({ contrast: 'high' }).contrast).toBe('high');
    expect(sanitize({ contrast: 'loud' }).contrast).toBe('system');
    expect(sanitize({}).singleKeys).toBe(true);
    expect(sanitize({ singleKeys: 'no' }).singleKeys).toBe(true);
  });
});
