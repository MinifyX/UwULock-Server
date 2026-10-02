import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { keepFocusThroughBusy } from '../../lib/focus';
import { t } from '../../lib/i18n';
import { PasswordInput } from '../PasswordInput';
import { Button, Masked, SettingRow, Toggle } from './index';

// React's act() outside a test library.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// What Orca read before these were fixed (docs/accessibility.md, "Tested with Orca").
let root: Root | null = null;
let host: HTMLElement | null = null;

function draw(element: React.ReactElement) {
  host = document.createElement('div');
  document.body.append(host);
  root = createRoot(host);
  act(() => root!.render(element));
  return host;
}

afterEach(() => {
  act(() => root?.unmount());
  host?.remove();
  root = null;
  host = null;
});

const text = (id: string | null) =>
  (id ?? '')
    .split(' ')
    .map((part) => document.getElementById(part)?.textContent ?? '')
    .join(' ');

describe('screen reader names', () => {
  it('a switch in a setting row is described by the row', () => {
    const page = draw(
      <SettingRow label="Reisemodus" description="Ordner auf Reisen ausblenden.">
        <Toggle label="Reisemodus" checked={false} onChange={() => undefined} />
      </SettingRow>,
    );
    const toggle = page.querySelector('[role="switch"]')!;
    expect(text(toggle.getAttribute('aria-describedby'))).toBe('Ordner auf Reisen ausblenden.');
    // It names itself: no group that says the name a second time.
    expect(page.querySelector('[role="group"]')).toBeNull();
  });

  it('a button in a setting row is in a group named after the setting', () => {
    const page = draw(
      <SettingRow label="Authenticator-App" description="Ein Code aus einer App.">
        <Button>Einrichten …</Button>
      </SettingRow>,
    );
    const group = page.querySelector('[role="group"]')!;
    expect(text(group.getAttribute('aria-labelledby'))).toBe('Authenticator-App');
    expect(group.contains(page.querySelector('button'))).toBe(true);
  });

  it('a password field inside its label is named by the label alone', () => {
    const page = draw(
      <label className="field">
        <span>Master-Passwort</span>
        <PasswordInput label="Master-Passwort" value="" onChange={() => undefined} />
        <small>Stärke: gut</small>
      </label>,
    );
    expect(page.querySelector('input')!.getAttribute('aria-label')).toBe('Master-Passwort');
    // The eye keeps one name; whether it is on is aria-pressed.
    const eye = page.querySelector('button')!;
    expect(eye.getAttribute('aria-label')).toBe(t('Passwort zeigen'));
    act(() => eye.click());
    expect(eye.getAttribute('aria-label')).toBe(t('Passwort zeigen'));
    expect(eye.getAttribute('aria-pressed')).toBe('true');
  });

  it('a busy password field stays focusable, and takes what a Field hands down', () => {
    const page = draw(
      <PasswordInput
        value="x"
        onChange={() => undefined}
        disabled
        aria-describedby="hint"
        aria-invalid
      />,
    );
    const input = page.querySelector('input')!;
    expect(input.disabled).toBe(false);
    expect(input.readOnly).toBe(true);
    expect(input.getAttribute('aria-describedby')).toBe('hint');
    expect(input.getAttribute('aria-invalid')).toBe('true');
  });

  it('a hidden secret is "verborgen", not dots', () => {
    const page = draw(<Masked />);
    expect(page.querySelector('[aria-hidden="true"]')!.textContent).toMatch(/^•+$/);
    expect(page.querySelector('.sr-only')!.textContent).toBe(t('verborgen'));
  });
});

describe('focus through busy', () => {
  it('a button switched off while it works gets the focus back', async () => {
    const stop = keepFocusThroughBusy();
    const page = draw(
      <form>
        <button type="button">Speichern</button>
      </form>,
    );
    const button = page.querySelector('button')!;
    button.focus();
    button.disabled = true;
    await Promise.resolve();
    // Meanwhile the form around it holds the focus, not the page's body.
    expect(document.activeElement).toBe(page.querySelector('form'));
    button.disabled = false;
    await Promise.resolve();
    expect(document.activeElement).toBe(button);
    stop();
  });
});
