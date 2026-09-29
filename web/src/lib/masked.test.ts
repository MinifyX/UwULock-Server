import { describe, expect, it } from 'vitest';
import { connectResultOf, defaultDomainOf, forDomainOf, forwarderUrls } from './masked';

describe('the website an address is for', () => {
  it('is the origin of the first address', () => {
    expect(forDomainOf('https://shop.example.com/login?next=1')).toBe('https://shop.example.com');
    expect(forDomainOf('http://shop.example.com:8080/')).toBe('http://shop.example.com:8080');
  });

  it('takes a bare host as https', () => {
    expect(forDomainOf('shop.example.com/login')).toBe('https://shop.example.com');
    expect(forDomainOf('  shop.example.com ')).toBe('https://shop.example.com');
  });

  it('is empty for apps, words and nothing', () => {
    expect(forDomainOf('androidapp://com.example.shop')).toBe('');
    expect(forDomainOf('just words')).toBe('');
    expect(forDomainOf('')).toBe('');
    expect(forDomainOf(null)).toBe('');
    expect(forDomainOf(undefined)).toBe('');
  });
});

describe('the way back from UwUMail', () => {
  it('says connected', () => {
    expect(connectResultOf(new URLSearchParams('result=connected'))).toEqual({ ok: true });
  });

  it('names the reason, or unknown', () => {
    for (const reason of ['denied', 'expired', 'invalid_state', 'upstream', 'busy'])
      expect(connectResultOf(new URLSearchParams(`result=error&reason=${reason}`))).toEqual({
        ok: false,
        reason,
      });
    expect(connectResultOf(new URLSearchParams('result=error&reason=<script>'))).toEqual({
      ok: false,
      reason: 'unknown',
    });
  });

  it('is nothing without a result', () => {
    expect(connectResultOf(new URLSearchParams(''))).toBeNull();
    expect(connectResultOf(new URLSearchParams('result=maybe'))).toBeNull();
  });
});

describe('the official apps’ server URLs', () => {
  it('are under /uwu/v1/masked', () => {
    expect(forwarderUrls('https://lock.example.com/')).toEqual({
      addy: 'https://lock.example.com/uwu/v1/masked/addy',
      simpleLogin: 'https://lock.example.com/uwu/v1/masked/simplelogin',
    });
  });
});

describe('the domain a new address gets', () => {
  it('is the default, else the first, else none', () => {
    const connection = {
      connected: true,
      server: 'https://mail.example.com',
      username: 'someone@example.com',
      domains: ['example.com', 'masked.example.com'],
      defaultDomain: 'masked.example.com',
      status: 'ok' as const,
      connectedDate: null,
      lastUsedDate: null,
      allowedServers: [],
    };
    expect(defaultDomainOf(connection)).toBe('masked.example.com');
    expect(defaultDomainOf({ ...connection, defaultDomain: null })).toBe('example.com');
    expect(defaultDomainOf(null)).toBe('');
  });
});
