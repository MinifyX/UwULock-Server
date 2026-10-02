import { describe, expect, it } from 'vitest';
import { ENTRY_MARKER, isEntrySend, readableOf } from './entrySend';

describe('entry Sends', () => {
  it('shows the readable lines of an entry Send without its marker line', () => {
    const text = `Shop\nBenutzername: nyu\n${ENTRY_MARKER}eyJuYW1lIjoiU2hvcCJ9\n`;
    expect(isEntrySend(text)).toBe(true);
    expect(readableOf(text)).toBe('Shop\nBenutzername: nyu');
    expect(readableOf(`${ENTRY_MARKER}eyJ9`)).toBe('');
  });

  it('leaves a plain text as it is', () => {
    const plain = 'Hallo\nuwulock-entry:v1: steht hier mitten drin\nund geht weiter';
    expect(isEntrySend(plain)).toBe(false);
    expect(readableOf(plain)).toBe(plain);
    expect(isEntrySend(null)).toBe(false);
    expect(isEntrySend('')).toBe(false);
  });
});
