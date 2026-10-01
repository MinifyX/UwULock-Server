import { describe, expect, it } from 'vitest';
import {
  breachAfterChange,
  breachIndex,
  breachesFor,
  cardsOf,
  ignore,
  isAddress,
  isIgnored,
  switchesOf,
  tidy,
  unignore,
  type IgnoreList,
  type SiteBreach,
} from './breaches';
import type { Finding, Report } from './features';

const breach = (domain: string, date: string, passwords = true): SiteBreach => ({
  domain,
  title: domain,
  date,
  added: null,
  records: 1,
  passwords,
  dataClasses: passwords ? ['Passwords'] : ['Names'],
  sources: { hibp: domain },
});

const index = breachIndex([
  breach('example.com', '2024-05-01'),
  breach('example.com', '2019-01-01'),
  breach('example.net', '2025-01-01', false),
]);

const finding = (patch: Partial<Finding>): Finding => ({
  id: 'a',
  name: 'Example',
  subtitle: 'nyu@example.com',
  bits: 80,
  weak: false,
  reused: 0,
  unsecured: false,
  breached: 0,
  host: 'example.com',
  uri: 'https://example.com/login',
  passwordChanged: '2023-01-01T00:00:00Z',
  ...patch,
});

describe('breached sites', () => {
  it('finds the breaches of a host and the domains above it, never a bare ending', () => {
    expect(breachesFor(index, 'login.example.com').map((b) => b.date)).toEqual([
      '2024-05-01',
      '2019-01-01',
    ]);
    expect(breachesFor(index, 'www.example.com')).toHaveLength(2);
    expect(breachesFor(index, 'com')).toEqual([]);
    expect(breachesFor(index, '192.0.2.1')).toEqual([]);
    expect(breachesFor(index, null)).toEqual([]);
  });

  it('counts only a breach with passwords after the last change', () => {
    expect(breachAfterChange(index, finding({}))?.date).toBe('2024-05-01');
    expect(breachAfterChange(index, finding({ passwordChanged: '2024-06-01T00:00:00Z' }))).toBe(
      null,
    );
    expect(breachAfterChange(index, finding({ host: 'example.net' }))).toBe(null);
    expect(breachAfterChange(index, finding({ passwordChanged: null }))).toBe(null);
  });
});

describe('the ignore list', () => {
  it('is kept per item and kind, undone, and tidied', () => {
    let list: IgnoreList = { version: 1, ignored: [] };
    list = ignore(list, 'a', 'weak');
    list = ignore(list, 'a', 'weak');
    expect(list.ignored).toHaveLength(1);
    expect(isIgnored(list, 'a', 'weak')).toBe(true);
    expect(isIgnored(list, 'a', 'reused')).toBe(false);
    list = ignore(list, 'gone', 'reused');
    expect(tidy(list, new Set(['a'])).ignored).toHaveLength(1);
    expect(isIgnored(unignore(list, 'a', 'weak'), 'a', 'weak')).toBe(false);
  });
});

describe('the cards', () => {
  const report: Report = {
    findings: [
      finding({ id: 'weak', name: 'B', weak: true, bits: 30, host: null }),
      finding({ id: 'leak', name: 'A', breached: 3, breachSources: ['xon'] }),
      finding({ id: 'fine', name: 'C', host: 'example.org' }),
    ],
    checked: 3,
    breachesChecked: true,
    breachesIncomplete: false,
  };

  it('are one per login with open problems, the worst first', () => {
    const cards = cardsOf(report, { sites: index, ignored: { version: 1, ignored: [] } });
    expect(cards.map((c) => c.finding.id)).toEqual(['leak', 'weak']);
    expect(cards[0]?.problems.map((p) => p.kind)).toEqual(['breached', 'siteBreach']);
  });

  it('leave out what is ignored', () => {
    const ignored = ignore({ version: 1, ignored: [] }, 'weak', 'weak');
    const cards = cardsOf(report, { sites: null, ignored });
    expect(cards.map((c) => c.finding.id)).toEqual(['leak']);
    expect(cards[0]?.problems.map((p) => p.kind)).toEqual(['breached']);
  });

  it('show where 2FA is possible', () => {
    const twofa = new Map([['fine', { documentation: null }]]);
    const cards = cardsOf(report, { twofa, ignored: { version: 1, ignored: [] } });
    expect(cards.map((c) => c.finding.id)).toContain('fine');
  });
});

describe('the rest', () => {
  it('knows an older server by its hibp flag alone', () => {
    expect(switchesOf({ hibp: true })).toEqual({
      hibp: true,
      xonPasswords: false,
      siteBreaches: false,
      emailCheck: false,
      changePassword: false,
    });
  });

  it('tells addresses from other usernames', () => {
    expect(isAddress('nyu@example.com')).toBe(true);
    expect(isAddress('nyu')).toBe(false);
    expect(isAddress('nyu@localhost')).toBe(false);
    expect(isAddress(null)).toBe(false);
  });
});
