import { describe, expect, it } from 'vitest';
import { SWITCH_GROUPS, SWITCH_TEXTS, switchedOff, switchOfLink, type SwitchId } from './switches';

describe('switched off', () => {
  it('follows the server’s switches', () => {
    const info = { features: ['reminders'], switches: { reminders: true, versions: false } };
    expect(switchedOff(info, 'reminders')).toBe(false);
    expect(switchedOff(info, 'versions')).toBe(true);
  });

  it('asks the features of a server without switches', () => {
    expect(switchedOff({ features: ['families'] }, 'families')).toBe(false);
    expect(switchedOff({ features: ['families'] }, 'travel-mode')).toBe(true);
  });

  it('counts nothing as off before the server answered', () => {
    expect(switchedOff(null, 'suite')).toBe(false);
    expect(switchedOff(undefined, 'suite')).toBe(false);
  });
});

describe('the switch a link needs', () => {
  const of = (hash: string) => {
    const [path = '', query = ''] = hash.split('?');
    return switchOfLink(path, new URLSearchParams(query));
  };

  it('knows the links into switchable parts', () => {
    expect(of('/file-requests/abc/def')).toBe('file-requests');
    expect(of('/request/abc')).toBe('file-requests');
    expect(of('/organizations/abc')).toBe('families');
    expect(of('/accept-organization')).toBe('families');
    expect(of('/vault?due=1')).toBe('reminders');
    expect(of('/settings/travel')).toBe('travel-mode');
    expect(of('/settings/masked')).toBe('masked-addresses');
  });

  it('leaves the vault and everything else alone', () => {
    for (const hash of ['', '/vault', '/send/abc/def', '/settings/account', '/sends'])
      expect(of(hash)).toBeNull();
  });
});

describe('the switch list', () => {
  it('has a text for every switch, each in a known group', () => {
    const ids = Object.keys(SWITCH_TEXTS) as SwitchId[];
    expect(ids).toHaveLength(16);
    for (const id of ids) expect(SWITCH_TEXTS[id].description.length).toBeGreaterThan(10);
    expect(SWITCH_GROUPS.map((group) => group.id)).toEqual([
      'sharing',
      'vault',
      'sign-in',
      'operations',
      'apps',
    ]);
  });
});
