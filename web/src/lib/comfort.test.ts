import { describe, expect, it, vi } from 'vitest';
import { automaticIcon, localLabel, suggestLibrary, type Library } from './comfort';

// The vault's WebAssembly is not needed here (nor built before every test run).
vi.mock('./web/core', () => ({ call: vi.fn(), callJson: vi.fn() }));
vi.mock('./requests', () => ({ openExtras: vi.fn() }));

describe('icons of the home network', () => {
  it('names the app a device is called after, never an address', () => {
    expect(localLabel('jellyfin.local')).toBe('jellyfin');
    expect(localLabel('Nextcloud.home.arpa.')).toBe('nextcloud');
    expect(localLabel('home-assistant')).toBe('home-assistant');
    expect(localLabel('192.168.1.10')).toBeNull();
    expect(localLabel('[2001:db8::1]')).toBeNull();
    expect(localLabel('10.0.0.1.local')).toBeNull();
    expect(localLabel('localhost')).toBeNull();
    expect(localLabel('shop.example.com')).toBeNull();
  });

  it('asks the server for names, not for addresses', () => {
    expect(automaticIcon('shop.example.com')).toBe('/icons/shop.example.com/icon.png');
    expect(automaticIcon('jellyfin.local')).toBe('/icons/jellyfin.local/icon.png');
    expect(automaticIcon('192.168.1.10')).toBeNull();
    expect(automaticIcon(null)).toBeNull();
  });

  it('suggests library icons by the device and the item', () => {
    const icon = (source: string, id: string, name: string) => ({
      source,
      id,
      name,
      variants: ['default'],
      aliases: [],
    });
    const index: Library = {
      updated: '2026-09-29T00:00:00Z',
      sources: [],
      icons: [
        icon('selfhst', 'home-assistant', 'Home Assistant'),
        icon('dashboard-icons', 'home-assistant', 'Home Assistant'),
        icon('dashboard-icons', 'jellyfin', 'Jellyfin'),
        icon('dashboard-icons', 'nextcloud', 'Nextcloud'),
      ],
    };
    const found = suggestLibrary(index, 'home-assistant.local', 'My Jellyfin');
    expect(found.map((icon) => `${icon.source}/${icon.id}`)).toEqual([
      'selfhst/home-assistant',
      'dashboard-icons/home-assistant',
      'dashboard-icons/jellyfin',
    ]);
    expect(suggestLibrary(index, '192.168.1.2', '')).toEqual([]);
  });
});
