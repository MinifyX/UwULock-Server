import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SuiteRecord } from '../../lib/suite/model';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const { pushed, state } = vi.hoisted(() => ({
  pushed: [] as string[][],
  state: { current: { status: 'open', records: [] as unknown[], unreadable: 0 } as unknown },
}));

// The space as the module would show it; pushes only recorded.
vi.mock('../../lib/suite/sync', () => {
  class Batch {
    ops: string[] = [];
    async add(kind: string) {
      this.ops.push(`add ${kind}`);
      return `new-${kind}`;
    }
    async edit(id: string) {
      this.ops.push(`edit ${id}`);
    }
    async remove(id: string) {
      this.ops.push(`remove ${id}`);
    }
    async push() {
      pushed.push(this.ops);
      return [];
    }
  }
  return {
    Batch,
    SpaceChanged: class extends Error {},
    createSpace: vi.fn(async () => undefined),
    loadSpace: vi.fn(async () => undefined),
    revealSecret: vi.fn(async () => 'hunter2'),
    useSuiteSpace: () => state.current,
  };
});

const { SuiteView } = await import('./SuiteView');
const { updateSettings } = await import('../../lib/settings');
updateSettings({ language: 'de' });

const rec = (id: string, kind: string, payload?: Record<string, unknown>): SuiteRecord => ({
  id,
  kind,
  seq: 1,
  updatedAt: { wallMs: 1, counter: 0, device: 1 },
  payload: payload as SuiteRecord['payload'],
});

const records = [
  rec('i1', 'identity', {
    label: 'Nyu',
    username: 'nyu',
    auth_type: 'password',
    password_secret_id: 's1',
  }),
  rec('s1', 'secret'),
  rec('g1', 'group', { name: 'Homelab', workspace: 'private', position: 0 }),
  rec('9b2d0c1e-0000-4000-8000-0000000000a1', 'host', {
    name: 'Router',
    address: 'router.example.com',
    port: 22,
    workspace: 'private',
    position: 0,
    group_id: 'g1',
    identity_id: 'i1',
  }),
  rec('f1', 'port_forward', {
    host_id: '9b2d0c1e-0000-4000-8000-0000000000a1',
    name: 'web',
    kind: 'local',
    bind_address: '127.0.0.1',
    bind_port: 8080,
    target_host: 'localhost',
    target_port: 80,
  }),
];

async function mount() {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  await act(async () => root.render(<SuiteView space="ssh" />));
  return { container, root };
}

const click = (element: Element | null | undefined) =>
  act(async () => (element as HTMLElement).click());

afterEach(() => {
  document.body.innerHTML = '';
  pushed.length = 0;
});

describe('a suite space in the web vault', () => {
  it('lists hosts under their group, with the command and the app link', async () => {
    state.current = { status: 'open', records, unreadable: 0 };
    const { container, root } = await mount();
    const list = container.querySelector('[role="listbox"]')!;
    expect(list.querySelector('.suite-heading:nth-child(2)')!.textContent).toBe('Homelab');
    expect(list.querySelector('[role="option"]')!.textContent).toContain('nyu@router.example.com');
    const detail = container.querySelector('.detail')!;
    expect(detail.textContent).toContain('ssh nyu@router.example.com');
    expect(detail.textContent).toContain('-L 127.0.0.1:8080 → localhost:80');
    expect(
      [...detail.querySelectorAll('button')].some((b) => b.textContent === 'In UwUSSH öffnen'),
    ).toBe(true);
    await act(async () => root.unmount());
  });

  it('deletes a host with its port forwards, and keeps an identity that is in use', async () => {
    state.current = { status: 'open', records, unreadable: 0 };
    const { container, root } = await mount();
    await click(container.querySelector('.detail-tools button[aria-label="Löschen"]'));
    const dialog = document.querySelector('[role="dialog"]')!;
    expect(dialog.textContent).toContain('Port-Weiterleitungen');
    await click(dialog.querySelector('button.danger'));
    expect(pushed).toEqual([['remove 9b2d0c1e-0000-4000-8000-0000000000a1', 'remove f1']]);

    const tabs = [...container.querySelectorAll('[role="tab"]')];
    await click(tabs.find((t) => t.textContent?.startsWith('Identitäten')));
    await click(container.querySelector('.detail-tools button[aria-label="Löschen"]'));
    const hint = document.querySelector('[role="dialog"]')!;
    expect(hint.textContent).toContain('Wird noch verwendet');
    expect(hint.textContent).toContain('Host: Router');
    expect(hint.querySelector('button.danger')).toBeNull();
    await act(async () => root.unmount());
  });

  it('offers to create the space when no app made it yet', async () => {
    state.current = { status: 'none' };
    const { container, root } = await mount();
    expect(container.textContent).toContain('Noch keine Daten von UwUSSH');
    expect(container.querySelector('button.primary')!.textContent).toBe('Bereich anlegen');
    await act(async () => root.unmount());
  });
});
