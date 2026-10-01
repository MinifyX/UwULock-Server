import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import * as api from '../lib/api';
import { t } from '../lib/i18n';
import type { Status } from '../lib/api';
import { AccountCard } from './AccountCard';
import { LockScreen } from './LockScreen';

// React's act() outside a test library.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

/**
 * A status as the desktop app would have it, with a second account on another server. The web
 * vault must not offer it, nor a way to add one: it opens this server's vault, one account's.
 */
const status = (state: Status['state']): Status => ({
  state,
  accountId: 'nyu@example.com',
  label: 'nyu@example.com',
  email: 'nyu@example.com',
  name: 'Nyu',
  server: 'lock.example.com',
  serverKind: 'self-hosted',
  serverUrl: 'https://lock.example.com',
  lastSync: Date.now(),
  syncing: false,
  syncError: null,
  sessionExpired: false,
  accounts: [
    {
      id: 'other',
      label: 'Other vault',
      email: 'other@example.net',
      name: null,
      server: 'vault.example.org',
      serverKind: 'self-hosted',
      active: false,
      unlocked: true,
      lastSync: null,
    },
  ],
});

async function mount(node: React.ReactNode) {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  await act(async () => root.render(node));
  return { container, root };
}

afterEach(() => {
  document.body.innerHTML = '';
});

const ANOTHER = /hinzufügen|add account|anderes konto|another account|other vault|example\.org/i;

describe('the web vault opens one vault', () => {
  it('has no "Add account" and no other account in the account menu', async () => {
    const { container, root } = await mount(<AccountCard status={status('unlocked')} />);
    await act(async () => container.querySelector<HTMLButtonElement>('.account-switch')!.click());
    const menu = document.querySelector('[role="menu"]')!;
    const entries = [...menu.querySelectorAll('[role="menuitem"]')].map((e) => e.textContent);
    expect(entries).toEqual([t('Sperren'), t('Abmelden')]);
    expect(document.body.textContent).not.toMatch(ANOTHER);
    await act(async () => root.unmount());
  });

  it('offers no other account or server on the lock screen', async () => {
    const { container, root } = await mount(
      <LockScreen status={status('locked')} onUnlocked={() => {}} onLoggedOut={() => {}} />,
    );
    expect(container.textContent).not.toMatch(ANOTHER);
    const buttons = [...container.querySelectorAll('button')].map((b) => b.textContent);
    expect(buttons.every((text) => !ANOTHER.test(text ?? ''))).toBe(true);
    await act(async () => root.unmount());
  });

  it('has no call that switches to, adds or renames another account', () => {
    for (const name of ['switchAccount', 'addAccount', 'renameAccount', 'setServer']) {
      expect(name in api, name).toBe(false);
    }
  });

  it('logs in to this server only: the login page asks for no server address', () => {
    const source = readFileSync(join(process.cwd(), 'src/components/LoginScreen.tsx'), 'utf8');
    expect(source).not.toMatch(/serverUrl|Server-Adresse|setServer/);
    expect(source).toContain('location.host');
  });
});
