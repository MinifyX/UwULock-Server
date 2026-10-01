import { describe, expect, it } from 'vitest';
import { domainOf, hostOf, hostOfUrl, publicLinkOf, requestUrl, sendUrl } from './links';

const ORIGIN = 'https://lock.example.com';
const SEND = { id: 'd1', url: 'https://send.example.com' };
const ACCESS = 'AAECAwQFBgcICQoLDA0ODw';

describe('a Send link', () => {
  it('stays Bitwarden’s on the main host', () => {
    expect(sendUrl(ACCESS, 'k3y', null, ORIGIN)).toBe(`${ORIGIN}/#/send/${ACCESS}/k3y`);
  });

  it('is short on a send domain, the key after the #', () => {
    expect(sendUrl(ACCESS, 'k3y', SEND, ORIGIN)).toBe(`https://send.example.com/${ACCESS}#k3y`);
    expect(sendUrl(ACCESS, 'k3y', { id: 'd2', url: 'https://send.example.com/' }, ORIGIN)).toBe(
      `https://send.example.com/${ACCESS}#k3y`,
    );
  });
});

describe('a file request link', () => {
  it('is #/request/… here and /r/…#secret on a send domain', () => {
    expect(requestUrl('abc', 's3cret', null, ORIGIN)).toBe(`${ORIGIN}/#/request/abc/s3cret`);
    expect(requestUrl('abc', 's3cret', SEND, ORIGIN)).toBe('https://send.example.com/r/abc#s3cret');
  });
});

describe('the chosen domain', () => {
  it('is found by id, and a deleted one is the main host', () => {
    expect(domainOf([SEND], 'd1')).toBe(SEND);
    expect(domainOf([SEND], 'gone')).toBeNull();
    expect(domainOf([SEND], null)).toBeNull();
    expect(domainOf([], undefined)).toBeNull();
  });
});

describe('a link by its path', () => {
  it('is a Send for 22 base64url characters and a key', () => {
    expect(publicLinkOf(`/${ACCESS}`, '#k3y-_')).toEqual({
      kind: 'send',
      accessId: ACCESS,
      key: 'k3y-_',
    });
  });

  it('needs the key, and exactly 22 characters', () => {
    expect(publicLinkOf(`/${ACCESS}`, '')).toBeNull();
    expect(publicLinkOf(`/${ACCESS}x`, '#k')).toBeNull();
    expect(publicLinkOf('/admin', '#k')).toBeNull();
    expect(publicLinkOf('/', '#/send/a/b')).toBeNull();
    expect(publicLinkOf(`/${ACCESS}/`, '#k')).toBeNull();
  });

  it('is a file request under /r/', () => {
    expect(publicLinkOf('/r/abc_-1', '#s3cret')).toEqual({
      kind: 'request',
      accessId: 'abc_-1',
      secret: 's3cret',
    });
  });
});

describe('a send domain as typed', () => {
  it('becomes the bare host name', () => {
    expect(hostOf(' Send.Example.COM ')).toBe('send.example.com');
    expect(hostOf('https://send.example.com/some/path?x=1')).toBe('send.example.com');
    expect(hostOf('send.example.com:443')).toBe('send.example.com');
    expect(hostOf('send.example.com.')).toBe('send.example.com');
    expect(hostOf('')).toBe('');
  });

  it('shows as its host', () => {
    expect(hostOfUrl('https://send.example.com')).toBe('send.example.com');
    expect(hostOfUrl('not a url')).toBe('not a url');
  });
});

describe('a link from a list or the server', () => {
  it('is kept only when it is http(s)', async () => {
    const { webUrl } = await import('./links');
    expect(webUrl('https://example.com/2fa')).toBe('https://example.com/2fa');
    expect(webUrl('http://example.com')).toBe('http://example.com/');
    expect(webUrl('javascript:alert(1)')).toBeNull();
    expect(webUrl('  javascript:alert(1)')).toBeNull();
    expect(webUrl('data:text/html,x')).toBeNull();
    expect(webUrl('/relative')).toBeNull();
    expect(webUrl(null)).toBeNull();
    expect(webUrl(42)).toBeNull();
  });
});
