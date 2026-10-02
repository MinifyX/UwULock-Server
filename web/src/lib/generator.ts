/**
 * The password generator's options, as this browser remembers them (never a password), and what
 * the minimums per set add up to — the same rule uwulock-core's generator follows: a set that is
 * on gets at least one character, more when its minimum says so, and the length grows to fit.
 */

import type { GeneratorOptions } from './api';

export const GENERATOR_KEY = 'uwulock.generator';

export const MIN_LENGTH = 5;
export const MAX_LENGTH = 128;
/** The most a single minimum may ask for; the sum is checked against `MAX_LENGTH`. */
export const MAX_MINIMUM = 32;

export const GENERATOR_DEFAULTS: GeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
  minLowercase: 0,
  minUppercase: 0,
  minNumber: 0,
  minSpecial: 0,
};

/** Each set with the option that switches it on and the one that holds its minimum. */
export const GENERATOR_SETS = [
  { key: 'uppercase', min: 'minUppercase', label: 'A–Z' },
  { key: 'lowercase', min: 'minLowercase', label: 'a–z' },
  { key: 'digits', min: 'minNumber', label: '0–9' },
  { key: 'symbols', min: 'minSpecial', label: '!@#$%^&*' },
] as const;

const minimum = (value: unknown) =>
  typeof value === 'number' && Number.isFinite(value)
    ? Math.min(MAX_MINIMUM, Math.max(0, Math.round(value)))
    : 0;

/** Stored options, checked one by one; anything unexpected falls back to its default. */
export function sanitizeGenerator(raw: unknown): GeneratorOptions {
  const input = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {};
  const bool = (v: unknown, d: boolean) => (typeof v === 'boolean' ? v : d);
  const d = GENERATOR_DEFAULTS;
  const options: GeneratorOptions = {
    length:
      typeof input.length === 'number' && Number.isFinite(input.length)
        ? Math.min(MAX_LENGTH, Math.max(MIN_LENGTH, Math.round(input.length)))
        : d.length,
    lowercase: bool(input.lowercase, d.lowercase),
    uppercase: bool(input.uppercase, d.uppercase),
    digits: bool(input.digits, d.digits),
    symbols: bool(input.symbols, d.symbols),
    avoidAmbiguous: bool(input.avoidAmbiguous, d.avoidAmbiguous),
    minLowercase: minimum(input.minLowercase),
    minUppercase: minimum(input.minUppercase),
    minNumber: minimum(input.minNumber),
    minSpecial: minimum(input.minSpecial),
  };
  if (!options.lowercase && !options.uppercase && !options.digits && !options.symbols) {
    options.lowercase = true;
  }
  return options;
}

export function loadGenerator(): GeneratorOptions {
  try {
    return sanitizeGenerator(JSON.parse(window.localStorage.getItem(GENERATOR_KEY) ?? '{}'));
  } catch {
    return GENERATOR_DEFAULTS;
  }
}

export function saveGenerator(options: GeneratorOptions) {
  try {
    window.localStorage.setItem(GENERATOR_KEY, JSON.stringify(options));
  } catch {
    // Remembering is a convenience.
  }
}

/** How many characters the minimums of the sets that are on need, at least one per set. */
export function requiredLength(options: GeneratorOptions): number {
  return GENERATOR_SETS.reduce(
    (sum, set) => sum + (options[set.key] ? Math.max(1, options[set.min]) : 0),
    0,
  );
}

/** The length the password will have: the one asked for, or more when the minimums need it. */
export function effectiveLength(options: GeneratorOptions): number {
  return Math.min(MAX_LENGTH, Math.max(MIN_LENGTH, options.length, requiredLength(options)));
}
