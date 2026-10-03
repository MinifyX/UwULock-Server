import { describe, expect, it } from 'vitest';
import {
  ssoAdminRulesChanged,
  ssoNeedsPassword,
  ssoSignupRulesChanged,
  type SsoSettings,
} from './sso';

const current: SsoSettings = {
  enabled: true,
  issuer: 'https://auth.example.com',
  clientId: 'vault',
  scopes: ['openid', 'email'],
  pkce: true,
  identifier: 'firma',
  label: 'Firma',
  only: false,
  signups: 'group',
  userGroup: null,
  adminGroup: 'vault-admins',
  adminsOnlyWithSso: false,
  trustUnverifiedEmail: false,
  groupsClaim: 'groups',
  rolesClaim: null,
  extensionIds: [],
  paired: null,
};

describe('the SSO settings that take the master password', () => {
  it('include who becomes an admin (R5-3)', () => {
    for (const change of [
      { adminGroup: 'someone@example.com' },
      { adminGroup: null },
      { groupsClaim: 'email' },
      { rolesClaim: 'given_name' },
    ] satisfies Partial<SsoSettings>[]) {
      expect(ssoAdminRulesChanged(current, { ...current, ...change })).toBe(true);
      expect(ssoNeedsPassword(current, { ...current, ...change }, '')).toBe(true);
    }
  });

  it('include who may make an account (R8 I-D)', () => {
    for (const change of [
      { signups: 'invitation' },
      { signups: 'off' },
      { userGroup: 'staff' },
    ] satisfies Partial<SsoSettings>[]) {
      expect(ssoSignupRulesChanged(current, { ...current, ...change })).toBe(true);
      expect(ssoAdminRulesChanged(current, { ...current, ...change })).toBe(false);
      expect(ssoNeedsPassword(current, { ...current, ...change }, '')).toBe(true);
    }
    expect(ssoNeedsPassword(current, { ...current, userGroup: ' ' }, '')).toBe(false);
  });

  it('leave out the label and spaces the server trims', () => {
    expect(ssoNeedsPassword(current, { ...current, label: 'Company' }, '')).toBe(false);
    expect(ssoNeedsPassword(current, { ...current, adminGroup: ' vault-admins ' }, '')).toBe(false);
    expect(ssoNeedsPassword(current, { ...current, rolesClaim: '' }, '')).toBe(false);
  });
});
