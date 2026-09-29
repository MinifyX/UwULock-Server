import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ImportSettings } from './ImportSettings';

// React's act() outside a test library.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const fixture = (name: string) =>
  readFileSync(join(process.cwd(), 'src/lib/import/fixtures', name), 'utf8');

async function mount() {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  await act(async () => root.render(<ImportSettings />));
  return { container, root };
}

async function choose(container: HTMLElement, name: string, content: string) {
  const input = container.querySelector<HTMLInputElement>('input[type="file"]')!;
  Object.defineProperty(input, 'files', { value: [new File([content], name)], configurable: true });
  await act(async () => input.dispatchEvent(new Event('change', { bubbles: true })));
}

afterEach(() => {
  document.body.innerHTML = '';
});

describe('the import in the settings', () => {
  it('shows a preview in a dialog, with focus in its list, and drops it on cancel', async () => {
    const { container, root } = await mount();
    const select = container.querySelector('select')!;
    expect(select.getAttribute('aria-label')).toBeTruthy();
    expect(select.value).toBe('auto');

    await choose(container, 'chrome.csv', fixture('chrome.csv'));
    const dialog = await vi.waitFor(() => {
      const found = document.querySelector<HTMLElement>('[role="dialog"]');
      if (!found) throw new Error('no dialog yet');
      return found;
    });
    const list = dialog.querySelector('.import-list')!;
    expect(document.activeElement).toBe(list);
    expect(list.querySelectorAll('li')).toHaveLength(2);
    expect(dialog.textContent).toContain('com.example.app');
    const buttons = [...dialog.querySelectorAll('button')];
    expect(buttons.at(-1)!.textContent).toMatch(/2/);

    await act(async () => buttons.find((b) => b.hasAttribute('data-secondary'))!.click());
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    await act(async () => root.unmount());
  });

  it('shows what is wrong with a file in a status line', async () => {
    const { container, root } = await mount();
    await choose(container, 'x.csv', 'Spalte A,Spalte B\n1,2\n');
    const status = await vi.waitFor(() => {
      const found = container.querySelector('[role="status"]');
      if (!found) throw new Error('no status yet');
      return found;
    });
    expect(status.getAttribute('data-tone')).toBe('error');
    await act(async () => root.unmount());
  });
});
