import { describe, expect, it } from 'vitest';
import {
  effectiveLength,
  GENERATOR_DEFAULTS,
  MAX_MINIMUM,
  requiredLength,
  sanitizeGenerator,
} from './generator';

describe('generator options', () => {
  it('keeps what it knows and drops the rest', () => {
    expect(sanitizeGenerator(null)).toEqual(GENERATOR_DEFAULTS);
    const options = sanitizeGenerator({
      length: 300,
      minSpecial: 4.4,
      minNumber: -3,
      minUppercase: 1000,
      minLowercase: 'two',
    });
    expect(options.length).toBe(128);
    expect(options.minSpecial).toBe(4);
    expect(options.minNumber).toBe(0);
    expect(options.minUppercase).toBe(MAX_MINIMUM);
    expect(options.minLowercase).toBe(0);
  });

  it('never switches every set off', () => {
    const options = sanitizeGenerator({
      lowercase: false,
      uppercase: false,
      digits: false,
      symbols: false,
    });
    expect(options.lowercase).toBe(true);
  });

  it('counts at least one per set that is on, and grows the length to fit', () => {
    expect(requiredLength(GENERATOR_DEFAULTS)).toBe(4);
    const many = { ...GENERATOR_DEFAULTS, length: 8, minNumber: 5, minSpecial: 4 };
    // 1 + 1 + 5 + 4
    expect(requiredLength(many)).toBe(11);
    expect(effectiveLength(many)).toBe(11);
    // A set that is off needs nothing, whatever its minimum says.
    expect(requiredLength({ ...many, symbols: false })).toBe(7);
    expect(effectiveLength({ ...many, symbols: false })).toBe(8);
  });
});
