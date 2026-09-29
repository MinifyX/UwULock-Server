/**
 * The links of Sends and file requests, on the main host or on a send domain (§14), and reading
 * them back from the address bar. No imports: the public pages and the tests use it as it is.
 */

/** A send domain as `/uwu/v1/info` lists it: `url` like `https://send.example.com`. */
export type SendDomain = { id: string; url: string };

/** The domain a Send or file request chose, if it is still there; none: the main host. */
export function domainOf(domains: readonly SendDomain[], id: string | null | undefined) {
  return (id && domains.find((domain) => domain.id === id)) || null;
}

const base = (url: string) => url.replace(/\/+$/, '');

/**
 * A Send's link: `<main host>/#/send/<access id>/<key>` as Bitwarden's, or on a send domain
 * `https://send.example.com/<access id>#<key>`. The key is always after `#`.
 */
export function sendUrl(
  accessId: string,
  key: string,
  domain: SendDomain | null,
  origin: string = location.origin,
): string {
  return domain
    ? `${base(domain.url)}/${accessId}#${key}`
    : `${base(origin)}/#/send/${accessId}/${key}`;
}

/** A file request's link: `#/request/<access id>/<secret>` here, `/r/<access id>#<secret>` there. */
export function requestUrl(
  accessId: string,
  secret: string,
  domain: SendDomain | null,
  origin: string = location.origin,
): string {
  return domain
    ? `${base(domain.url)}/r/${accessId}#${secret}`
    : `${base(origin)}/#/request/${accessId}/${secret}`;
}

export type PublicLink =
  | { kind: 'send'; accessId: string; key: string }
  | { kind: 'request'; accessId: string; secret: string };

/**
 * A link a send domain answers by its path (and the main host too): `/<access id>#<key>` for a
 * Send — the access id is 16 bytes in base64url, 22 characters — and `/r/<access id>#<secret>`
 * for a file request. Anything else is not one.
 */
export function publicLinkOf(pathname: string, hash: string): PublicLink | null {
  const secret = hash.replace(/^#/, '');
  const send = pathname.match(/^\/([A-Za-z0-9_-]{22})$/);
  if (send) return secret ? { kind: 'send', accessId: send[1]!, key: secret } : null;
  const request = pathname.match(/^\/r\/([A-Za-z0-9_-]+)$/);
  if (request) return { kind: 'request', accessId: request[1]!, secret };
  return null;
}

/**
 * What an admin typed as a send domain, as the server wants it: the host name alone, lower
 * case, without scheme, path or port.
 */
export function hostOf(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/[/?#].*$/, '')
    .replace(/:\d+$/, '')
    .replace(/\.$/, '');
}

/** The host of a URL, for showing a send domain: `https://send.example.com` → `send.example.com`. */
export function hostOfUrl(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
