import { describe, expect, it } from 'vitest';
import { ENTRY_MARKER, mayBeEntrySend } from './entrySend';

describe('entry Sends', () => {
  it('asks the module only about a text with the marker', () => {
    expect(ENTRY_MARKER).toBe('uwulock-entry:v2:');
    expect(mayBeEntrySend(`Shop\n${ENTRY_MARKER}eyJ9.dGFn`)).toBe(true);
    expect(mayBeEntrySend('Hallo\nuwulock-entry:v1:eyJ9')).toBe(false);
    expect(mayBeEntrySend(null)).toBe(false);
    expect(mayBeEntrySend('')).toBe(false);
  });
});
