import { describe, expect, it } from 'vitest';
import { changedSpaces } from './live';

describe('the realtime channel', () => {
  it('pulls a space only when the suite area of it changed', () => {
    expect(changedSpaces({ type: 'changed', areas: ['suite'], spaces: ['ssh'] })).toEqual(['ssh']);
    expect(changedSpaces({ type: 'changed', areas: ['vault', 'uwu'] })).toEqual([]);
    expect(changedSpaces({ type: 'changed', areas: ['suite'], spaces: ['rdp', 7] })).toEqual([
      'rdp',
    ]);
    expect(changedSpaces({ type: 'info' })).toEqual([]);
    expect(changedSpaces(null)).toEqual([]);
  });
});
