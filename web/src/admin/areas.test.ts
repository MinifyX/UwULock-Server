import { describe, expect, it } from 'vitest';
import { AREAS, locate, MOVED, visibleAreas } from './areas';

const all = visibleAreas(() => true);

describe('the admin portal map', () => {
  it('has one path per tab, and each area starts at its own path', () => {
    const paths = AREAS.flatMap((area) => area.tabs.map((tab) => tab.path));
    expect(new Set(paths).size).toBe(paths.length);
    for (const area of AREAS.slice(1))
      for (const tab of area.tabs) expect(tab.path.startsWith(area.tabs[0]!.path)).toBe(true);
  });

  it('finds every tab by its path', () => {
    for (const area of all)
      for (const tab of area.tabs) expect(locate(tab.path, all)).toEqual({ area, tab });
  });

  it('sends the old pages where they went', () => {
    for (const [old, now] of Object.entries(MOVED)) expect(locate(old, all).tab.path).toBe(now);
    expect(locate('/settings', all).area.id).toBe('security');
    expect(locate('/notifications', all).tab.id).toBe('alerts');
  });

  it('leaves out what is switched off, and an area with nothing left', () => {
    const areas = visibleAreas((id) => id !== 'sso' && id !== 'offsite-backups');
    const security = areas.find((area) => area.id === 'security')!;
    expect(security.tabs.map((tab) => tab.id)).toEqual([
      'sign-in',
      'master-password',
      'admin-access',
    ]);
    // SCIM needs SSO too.
    expect(
      visibleAreas((id) => id !== 'sso')
        .flatMap((a) => a.tabs)
        .some((t) => t.id === 'scim'),
    ).toBe(false);
    expect(locate('/security/sso', areas).tab.id).toBe('sign-in');
    expect(locate('/backups/offsite', areas).tab.id).toBe('local-backups');
  });

  it('falls back to the overview for anything else, like the way back from SSO', () => {
    expect(locate('/sso', all).tab.id).toBe('overview');
    expect(locate('/nowhere', all).tab.id).toBe('overview');
    expect(locate('/users/nobody', all).tab.id).toBe('accounts');
  });
});
