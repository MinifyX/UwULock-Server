import { describe, expect, it } from 'vitest';
import type { ItemSummary } from './api';
import { entryFor, indexOf, missingTwoFactor, type TwofaEntry } from './twofa';

const entries: TwofaEntry[] = [
  {
    domain: 'example.com',
    additionalDomains: ['example.net'],
    name: 'Example',
    methods: ['sms', 'totp'],
    documentation: 'https://example.com/help/2fa',
  },
  {
    domain: 'mail.example.org',
    additionalDomains: [],
    name: 'Mail',
    methods: ['email'],
    documentation: null,
  },
];

function login(id: string, host: string | null, extra: Partial<ItemSummary> = {}): ItemSummary {
  return {
    id,
    kind: 'login',
    name: id,
    subtitle: null,
    host,
    favorite: false,
    folderId: null,
    organizationId: null,
    collectionIds: [],
    deleted: false,
    archived: false,
    reprompt: false,
    hasTotp: false,
    hasPassword: true,
    hasUsername: true,
    broken: false,
    revisionDate: null,
    ...extra,
  };
}

describe('the 2FA report', () => {
  it('finds a site by its host or a domain above it', () => {
    const index = indexOf(entries);
    expect(entryFor(index, 'www.example.com')?.name).toBe('Example');
    expect(entryFor(index, 'login.accounts.example.net')?.name).toBe('Example');
    expect(entryFor(index, 'Example.COM.')?.name).toBe('Example');
    expect(entryFor(index, 'other.example.org')).toBeNull();
    expect(entryFor(index, 'com')).toBeNull();
    expect(entryFor(index, '192.0.2.7')).toBeNull();
    expect(entryFor(index, 'nas')).toBeNull();
    expect(entryFor(index, null)).toBeNull();
  });

  it('names logins without a code for sites that offer one', () => {
    const items = [
      login('b-shop', 'shop.example.com'),
      login('a-has-code', 'example.com', { hasTotp: true }),
      login('mail', 'mail.example.org'),
      login('trash', 'example.com', { deleted: true }),
      { ...login('note', 'example.com'), kind: 'note' as const },
      login('a-alias', 'example.net'),
    ];
    expect(missingTwoFactor(items, entries).map(({ item }) => item.id)).toEqual([
      'a-alias',
      'b-shop',
    ]);
  });
});
