/**
 * The server's rules for master passwords, with nothing else in: the account settings and the
 * login both take them (the login for "enforce on login"), without importing each other.
 */
import { t } from './i18n';

/** The rules for a new master password: `minComplexity` is a zxcvbn score, 0 (none) to 4. */
export type PasswordRules = { minLength: number; minComplexity: number; enforceOnLogin?: boolean };

/** Without a word from the server: what Bitwarden's clients ask anyway. */
export const DEFAULT_RULES: PasswordRules = { minLength: 12, minComplexity: 0 };

/**
 * The bits as a score from 0 to 4 like zxcvbn's, which the admin's rule is written in. zxcvbn
 * draws its lines at 10³, 10⁶, 10⁸ and 10¹⁰ guesses: that is 10, 20, 26.6 and 33.2 bits.
 */
export function complexityScore(bits: number): number {
  if (bits < 10) return 0;
  if (bits < 20) return 1;
  if (bits < 26.6) return 2;
  if (bits < 33.2) return 3;
  return 4;
}

/** Why a new master password is refused under `rules`, or null when it is fine. */
export function passwordProblem(
  password: string,
  bits: number,
  rules: PasswordRules,
): string | null {
  // Bitwarden's clients ask for 12 characters whatever the server says; so does this one.
  const length = Math.max(rules.minLength, DEFAULT_RULES.minLength);
  if ([...password].length < length) return t('Mindestens {n} Zeichen.', { n: length });
  if (rules.minComplexity > 0 && complexityScore(bits) < rules.minComplexity)
    return t(
      'Dieser Server verlangt ein stärkeres Master-Passwort (Stufe {need} von 4, dieses hat {has}).',
      {
        need: rules.minComplexity,
        has: complexityScore(bits),
      },
    );
  return null;
}

/**
 * Whether a master password that is in use breaks the admin's rules, for "enforce on login":
 * the rules as set, without the clients' 12 characters on top, so a lower minimum asks no one.
 */
export function breaksRules(password: string, bits: number, rules: PasswordRules): boolean {
  if ([...password].length < rules.minLength) return true;
  return rules.minComplexity > 0 && complexityScore(bits) < rules.minComplexity;
}
