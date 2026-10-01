import { describe, expect, it } from 'vitest';
import { translate } from './i18n';
import { securityLabel } from './items';

describe('a security another app wrote', () => {
  it('stays text, also when it is a name of Object.prototype', () => {
    expect(securityLabel('WEP')).toBe('WEP (unsicher)');
    for (const text of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
      expect(securityLabel(text)).toBe(text);
      expect(translate('en', securityLabel(text))).toBe(text);
    }
    expect(translate('en', 'WEP (unsicher)')).toBe('WEP (insecure)');
  });
});
