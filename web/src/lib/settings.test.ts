import { describe, expect, it, vi } from 'vitest';

describe('the appearance', () => {
  it('follows a change made in another tab, as the vault and the admin portal share it', async () => {
    window.matchMedia = vi.fn().mockReturnValue({
      matches: false,
      addEventListener: () => undefined,
    }) as unknown as typeof window.matchMedia;
    localStorage.clear();
    const { applyAppearance, getSettings } = await import('./settings');
    applyAppearance();
    expect(document.documentElement.dataset.theme).toBe('dark');

    // The other tab (say the vault) switched to "System"; this browser wants light.
    localStorage.setItem('uwulock.settings', JSON.stringify({ theme: 'system' }));
    window.dispatchEvent(new StorageEvent('storage', { key: 'uwulock.settings' }));
    expect(getSettings().theme).toBe('system');
    expect(document.documentElement.dataset.theme).toBe('light');

    // Something else in the storage changes nothing.
    localStorage.setItem('uwulock.settings', JSON.stringify({ theme: 'dark' }));
    window.dispatchEvent(new StorageEvent('storage', { key: 'uwulock.generator' }));
    expect(document.documentElement.dataset.theme).toBe('light');
  });
});
