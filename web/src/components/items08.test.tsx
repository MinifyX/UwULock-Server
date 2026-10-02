import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Draft, ItemDetail, ItemSummary, PasskeyInfo, TotpCode } from '../lib/api';
import type { SharedEntry } from '../lib/entrySend';
import { t } from '../lib/i18n';

// React's act() outside a test library.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const summary: ItemSummary = {
  id: 'l1',
  kind: 'login',
  name: 'Shop',
  subtitle: 'nyu',
  host: 'shop.example.com',
  favorite: false,
  folderId: null,
  organizationId: null,
  collectionIds: [],
  deleted: false,
  archived: false,
  reprompt: false,
  hasTotp: true,
  hasPassword: true,
  hasUsername: true,
  broken: false,
  revisionDate: null,
};

const passkey: PasskeyInfo = {
  index: 0,
  readable: true,
  credentialId: 'cred-1',
  rpId: 'shop.example.com',
  rpName: 'Shop',
  userName: 'nyu@example.com',
  userDisplayName: 'Nyu',
  creationDate: '2026-09-28T12:00:00.000Z',
  discoverable: true,
};

const detail: ItemDetail = {
  summary,
  locked: false,
  login: {
    username: 'nyu',
    hasPassword: true,
    hasTotp: true,
    passwordRevisionDate: null,
    uris: [
      { uri: 'https://shop.example.com', match: null, host: 'shop.example.com', openable: true },
      { uri: 'https://login.example.net', match: null, host: 'login.example.net', openable: true },
      { uri: 'https://pay.example.org', match: null, host: 'pay.example.org', openable: true },
    ],
    passkeys: 1,
    passkeyList: [passkey],
  },
  fields: [],
};

let code: TotpCode = { code: '123456', next: '654321', remaining: 25, period: 30, showNext: false };
const saved: { id: string | null; clone: string | null; draft: Draft }[] = [];
const copied: string[] = [];

vi.mock('../lib/api', async (original) => ({
  ...(await original<typeof import('../lib/api')>()),
  vaultItem: async () => detail,
  totpCode: async () => code,
  saveItem: async (id: string | null, draft: Draft) => {
    saved.push({ id, clone: null, draft });
    return id ?? 'new';
  },
  saveClone: async (source: string, draft: Draft) => {
    saved.push({ id: null, clone: source, draft });
    return 'copy';
  },
  copyField: async (_id: string, field: string) => {
    copied.push(field);
  },
  copyGenerated: async (text: string) => {
    copied.push(text);
  },
}));

vi.mock('../lib/entrySend', async (original) => ({
  ...(await original<typeof import('../lib/entrySend')>()),
  entryCodes: async () => code,
}));

const { ItemDetail: Detail } = await import('./ItemDetail');
const { ItemEditor } = await import('./ItemEditor');
const { SharedEntryView } = await import('./web/SharedEntry');
const { ticked } = await import('./web/ShareAsSend');

async function mount(node: React.ReactNode) {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  await act(async () => root.render(node));
  return { container, root };
}

const button = (label: string) => {
  const found = [...document.querySelectorAll('button')].find(
    (b) => b.getAttribute('aria-label') === label || b.textContent?.trim() === label,
  );
  if (!found) throw new Error(`no button ${label}`);
  return found;
};

afterEach(() => {
  document.body.innerHTML = '';
  saved.length = 0;
  copied.length = 0;
  code = { code: '123456', next: '654321', remaining: 25, period: 30, showNext: false };
});

describe('an item in 0.8', () => {
  it('shows the first website and the others on a click', async () => {
    const { container, root } = await mount(
      <Detail summary={summary} overview={null} onEdit={() => {}} onClone={() => {}} />,
    );
    await vi.waitFor(() => expect(container.textContent).toContain('https://shop.example.com'));
    expect(container.textContent).not.toContain('https://login.example.net');
    await act(async () => button(t('+{n} weitere Websites', { n: 2 })).click());
    expect(container.textContent).toContain('https://login.example.net');
    expect(container.textContent).toContain('https://pay.example.org');
    await act(async () => root.unmount());
  });

  it('lists its passkeys instead of saying UwULock cannot use them', async () => {
    const { container, root } = await mount(
      <Detail summary={summary} overview={null} onEdit={() => {}} />,
    );
    await vi.waitFor(() => expect(container.textContent).toContain('nyu@example.com'));
    expect(container.textContent).toContain('shop.example.com');
    expect(button(t('Passkey für {site} löschen', { site: 'Shop' }))).toBeTruthy();
    await act(async () => root.unmount());
  });

  it('shows the next code only in the last seconds, with a copy button of its own', async () => {
    const { container, root } = await mount(
      <Detail summary={summary} overview={null} onEdit={() => {}} />,
    );
    await vi.waitFor(() => expect(container.textContent).toContain('123 456'));
    expect(container.querySelector('[data-totp-next]')).toBeNull();
    code = { ...code, remaining: 8, showNext: true };
    await vi.waitFor(() => expect(container.querySelector('[data-totp-next]')).not.toBeNull(), {
      timeout: 2500,
    });
    expect(container.textContent).toContain('654 321');
    await act(async () => button(t('Nächsten Code kopieren')).click());
    expect(copied).toContain('totp-next');
    await act(async () => root.unmount());
  });

  it('makes an item a favorite with the star in the editor', async () => {
    const { root } = await mount(
      <ItemEditor
        summary={summary}
        kind="login"
        overview={null}
        onClose={() => {}}
        onSaved={() => {}}
      />,
    );
    await vi.waitFor(() => button(t('Favorit')));
    const star = button(t('Favorit'));
    expect(star.getAttribute('aria-pressed')).toBe('false');
    await act(async () => star.click());
    expect(star.getAttribute('aria-pressed')).toBe('true');
    await act(async () => document.querySelector<HTMLFormElement>('#item-editor')!.requestSubmit());
    expect(saved[0]).toMatchObject({ id: 'l1', clone: null, draft: { favorite: true } });
    await act(async () => root.unmount());
  });

  it('duplicates an item as a new one, from the source', async () => {
    const { root } = await mount(
      <ItemEditor
        summary={summary}
        kind="login"
        clone
        overview={null}
        onClose={() => {}}
        onSaved={() => {}}
      />,
    );
    await vi.waitFor(() =>
      expect(document.querySelector<HTMLInputElement>('#item-editor input')?.value).toBe(
        t('{name} (Kopie)', { name: 'Shop' }),
      ),
    );
    await act(async () => document.querySelector<HTMLFormElement>('#item-editor')!.requestSubmit());
    expect(saved[0]!.clone).toBe('l1');
    // What the editor never saw comes from the source.
    expect(saved[0]!.draft.login?.password).toBeNull();
    await act(async () => root.unmount());
  });
});

describe('sharing an item as a Send', () => {
  it('never ticks the one-time codes on its own', () => {
    const chosen = ticked([
      { name: 'username', label: null },
      { name: 'password', label: null },
      { name: 'totp', label: null, entryOnly: true },
      { name: 'uri:0', label: null, uri: 'https://shop.example.com' },
    ]);
    expect([...chosen]).toEqual(['username', 'password', 'uri:0']);
    expect([
      ...ticked([
        { name: 'totp', label: null, entryOnly: true },
        { name: 'notes', label: null },
      ]),
    ]).toEqual(['notes']);
  });

  it('shows an entry Send as an entry with live codes, never the key', async () => {
    const entry: SharedEntry = {
      name: 'Shop',
      username: 'nyu',
      password: 'hunter2',
      websites: ['https://shop.example.com'],
      fields: [{ name: 'PIN', value: '1234', hidden: true }],
      totp: 'JBSWY3DPEHPK3PXP',
    };
    const { container, root } = await mount(<SharedEntryView entry={entry} />);
    await vi.waitFor(() => expect(container.textContent).toContain('123 456'));
    expect(container.textContent).toContain('nyu');
    expect(container.textContent).toContain('https://shop.example.com');
    expect(container.textContent).not.toContain('hunter2');
    expect(container.textContent).not.toContain('1234');
    expect(container.innerHTML).not.toContain('JBSWY3DPEHPK3PXP');
    await act(async () => button(t('{label} kopieren', { label: t('Passwort') })).click());
    expect(copied).toEqual(['hunter2']);
    await act(async () => root.unmount());
  });
});
