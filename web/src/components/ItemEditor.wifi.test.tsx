import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Draft, ItemDetail, ItemSummary } from '../lib/api';
import { t } from '../lib/i18n';

// React's act() outside a test library.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const saved: Draft[] = [];

const summary: ItemSummary = {
  id: 'w1',
  kind: 'wifi',
  name: 'Campus',
  subtitle: 'campus',
  host: null,
  favorite: false,
  folderId: null,
  organizationId: null,
  collectionIds: [],
  deleted: false,
  archived: false,
  reprompt: false,
  hasTotp: false,
  hasPassword: false,
  hasUsername: false,
  broken: false,
  revisionDate: null,
};

const field = (
  index: number,
  name: string,
  kind: 'text' | 'hidden' | 'boolean',
  value: string,
) => ({
  index,
  name,
  kind,
  value: kind === 'hidden' ? null : value,
  hasValue: true,
});

const detail: ItemDetail = {
  summary,
  locked: false,
  notes: 'Bibliothek',
  fields: [
    field(0, 'uwulock:type', 'text', 'wifi'),
    field(1, 'SSID', 'text', 'campus'),
    field(2, 'Password', 'hidden', 'secret'),
    field(3, 'Security', 'text', 'WPA2-Enterprise'),
    field(4, 'Hidden network', 'boolean', 'false'),
    field(5, 'EAP method', 'text', 'TTLS'),
    field(6, 'Identity', 'text', 'nyu@example.com'),
    field(7, 'Raum', 'text', '2.14'),
    field(8, 'PIN', 'hidden', '1234'),
  ],
};

vi.mock('../lib/api', async (original) => ({
  ...(await original<typeof import('../lib/api')>()),
  vaultItem: async () => detail,
  saveItem: async (_id: string | null, draft: Draft) => {
    saved.push(draft);
    return 'w1';
  },
  revealField: async () => 'secret',
}));

const { ItemEditor } = await import('./ItemEditor');

async function mount(node: React.ReactNode) {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  await act(async () => root.render(node));
  return { container, root };
}

/** The control a visible label names. */
function control<T extends HTMLElement>(label: string): T {
  const found = [...document.querySelectorAll('label')].find(
    (l) => l.textContent?.trim() === label,
  );
  const target = found?.control ?? found?.querySelector('input, select, textarea');
  if (!target) throw new Error(`no control for ${label}`);
  return target as T;
}

async function change(element: HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = Object.getPrototypeOf(element) as object;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(element, value);
  await act(async () => {
    element.dispatchEvent(
      new Event(element.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }),
    );
  });
}

afterEach(() => {
  document.body.innerHTML = '';
  saved.length = 0;
});

describe('the Wi-Fi editor', () => {
  it('shows the network, Enterprise fields only for Enterprise, and saves it unchanged', async () => {
    const { root } = await mount(
      <ItemEditor
        summary={summary}
        kind="wifi"
        overview={null}
        onClose={() => {}}
        onSaved={() => {}}
      />,
    );
    await vi.waitFor(() => control<HTMLInputElement>(t('Netzwerkname (SSID)')));
    expect(control<HTMLInputElement>(t('Netzwerkname (SSID)')).value).toBe('campus');
    expect(control<HTMLSelectElement>(t('Sicherheit')).value).toBe('WPA2-Enterprise');
    expect(control<HTMLSelectElement>(t('EAP-Methode')).value).toBe('TTLS');
    expect(control<HTMLInputElement>(t('Identität')).value).toBe('nyu@example.com');
    // The marker and the network's fields are not among the item's own fields.
    const own = [...document.querySelectorAll<HTMLInputElement>('input[placeholder]')].map(
      (input) => input.value,
    );
    expect(own).toContain('Raum');
    expect(own).not.toContain('uwulock:type');
    expect(own).not.toContain('SSID');

    await act(async () => document.querySelector<HTMLFormElement>('#item-editor')!.requestSubmit());
    expect(saved).toHaveLength(1);
    expect(saved[0]!.kind).toBe('note');
    expect(saved[0]!.notes).toBe('Bibliothek');
    expect(saved[0]!.fields.map((f) => [f.name, f.kind, f.value, f.from])).toEqual([
      ['uwulock:type', 'text', 'wifi', 0],
      ['SSID', 'text', 'campus', 1],
      ['Password', 'hidden', null, 2],
      ['Security', 'text', 'WPA2-Enterprise', 3],
      ['Hidden network', 'boolean', 'false', 4],
      ['EAP method', 'text', 'TTLS', 5],
      ['Identity', 'text', 'nyu@example.com', 6],
      ['Raum', 'text', '2.14', 7],
      ['PIN', 'hidden', null, 8],
    ]);
    await act(async () => root.unmount());
  });

  it('hides the Enterprise fields for a personal network and drops them on save', async () => {
    const { root } = await mount(
      <ItemEditor
        summary={summary}
        kind="wifi"
        overview={null}
        onClose={() => {}}
        onSaved={() => {}}
      />,
    );
    await vi.waitFor(() => control<HTMLSelectElement>(t('Sicherheit')));
    await change(control<HTMLSelectElement>(t('Sicherheit')), 'WPA3');
    expect(() => control(t('EAP-Methode'))).toThrow();
    await change(control<HTMLInputElement>(t('Netzwerkname (SSID)')), 'campus-5g');
    await act(async () => document.querySelector<HTMLFormElement>('#item-editor')!.requestSubmit());
    expect(saved[0]!.fields.map((f) => f.name)).toEqual([
      'uwulock:type',
      'SSID',
      'Password',
      'Security',
      'Hidden network',
      'Raum',
      'PIN',
    ]);
    expect(saved[0]!.fields[1]!.value).toBe('campus-5g');
    // The name was not the SSID, so it stays.
    expect(saved[0]!.name).toBe('Campus');
    await act(async () => root.unmount());
  });

  it('names a new network after its SSID', async () => {
    const { root } = await mount(
      <ItemEditor
        summary={null}
        kind="wifi"
        overview={null}
        onClose={() => {}}
        onSaved={() => {}}
      />,
    );
    await change(control<HTMLInputElement>(t('Netzwerkname (SSID)')), 'uwu-net');
    expect(control<HTMLInputElement>(t('Name')).value).toBe('uwu-net');
    await change(control<HTMLInputElement>(t('WLAN-Passwort')), 'pw');
    await act(async () => document.querySelector<HTMLFormElement>('#item-editor')!.requestSubmit());
    expect(saved[0]).toMatchObject({ kind: 'note', name: 'uwu-net' });
    expect(saved[0]!.fields.slice(0, 4)).toEqual([
      { name: 'uwulock:type', kind: 'text', value: 'wifi', from: null },
      { name: 'SSID', kind: 'text', value: 'uwu-net', from: null },
      { name: 'Password', kind: 'hidden', value: 'pw', from: null },
      { name: 'Security', kind: 'text', value: 'WPA2', from: null },
    ]);
    await act(async () => root.unmount());
  });
});
