import { describe, expect, it } from 'vitest';
import { bytes, seconds, spacedCode } from './format';

describe('format', () => {
  it('writes sizes the way a person reads them', () => {
    expect(bytes(512)).toBe('512 B');
    expect(bytes(2048)).toMatch(/^2 KiB$/);
    expect(bytes(5 * 1024 * 1024)).toMatch(/^5 MiB$/);
  });

  it('reads the server’s dates', () => {
    expect(seconds('1970-01-01T00:00:01.000000Z')).toBe(1);
    expect(seconds(null)).toBeNull();
    expect(seconds('not a date')).toBeNull();
  });

  it('splits a code in two halves', () => {
    expect(spacedCode('123456')).toBe('123 456');
    expect(spacedCode('abc')).toBe('abc');
  });
});
