# Send domains

Extra names for Sends and file requests, like `send.example.com` beside `lock.example.com`. Under
such a name the server answers only what the pages of a Send and a file request need: no web
vault, no login, no admin portal. Links get shorter and say what they are:

- a Send: `https://send.example.com/<access id>#<key>` (instead of
  `https://lock.example.com/#/send/<access id>/<key>`);
- a file request: `https://send.example.com/r/<access id>#<secret>`.

The part after `#` stays in the browser; the server never sees it.

## Adding one

*Admin portal → Send domains → Add.* Type the name alone (`send.example.com`, no `https://`, no
port) and choose how it gets its certificate:

- **Let's Encrypt** — the server gets a certificate for the name itself, the same way it does for
  its main address (TLS-ALPN-01: no port 80, no web root). The name has to point to this server in
  DNS, and port 443 has to reach it from outside. Each send domain gets a certificate of its own,
  and the server shows each client the one for the name it asked for. This works with
  `UWULOCK_TLS=acme` and also with certificate files (`UWULOCK_TLS=files`) for the main address.
  With `UWULOCK_TLS=off` the server does no TLS at all, so it cannot get one; choose *proxy*.
- **Proxy** — a proxy in front (Caddy, nginx, Traefik …) does TLS for the name and passes the
  requests on with their `Host` header, like it does for the main address. With Caddy:

  ```
  send.example.com {
      reverse_proxy 127.0.0.1:8080
  }
  ```

  Behind a proxy that rewrites `Host`, set `UWULOCK_TRUST_FORWARDED=true` so the server reads
  `X-Forwarded-Host` instead.

*Check* resolves the name, asks `https://<name>/alive` and tells whether the answer came from this
server: *DNS*, *HTTPS* and *routing*. The list shows the certificate's state (valid until …,
being fetched, failed with the reason, or "the proxy does it"). The diagnosis in the admin portal
has a check for every send domain's certificate, and `/metrics` has
`uwulock_certificate_expiry_timestamp_seconds{domain="<id>"}` for the ones the server got itself.

Deleting a domain loses nothing but its links: Sends and file requests that used it are on the
main address again, and the old links under the deleted name stop working.

## Its own look

*Look …* at a domain sets a name, a colour, logos and a favicon for it, like the server's own
branding ([branding.md](branding.md)). Without its own, a send domain looks like the server. The
look covers the Send and file-request pages under that name and the mail with the code of a Send
for given addresses when the page was opened there.

## Which link a Send gets

Every Send and every file request opens under the main address **and** every send domain. What
is chosen is only the link that is shown and copied, and so the look of the page:

- *Web vault → Settings → Account → Address for Sends* sets the account's default. New Sends and
  file requests start with it, and a Send made in an official Bitwarden app gets it too.
- The Send editor and the file-request editor have *Address of the link* for each one.
- The official Bitwarden apps build their links from their own server address, so their links
  use the main address. They work all the same.

## What a send domain answers

The Send page (`/<access id>`), the file-request page (`/r/<access id>`), the web vault's files
those pages load, `/alive`, the reduced `/uwu/v1/info` (name, version, branding, and the features
`sends`, `send-emails`, `file-requests`), `/uwu/v1/branding…`, the public file-request API, the
Send access API of Bitwarden (`/api/sends/access…`, file downloads), and
`/identity/connect/token` for the `send_access` grant only. Everything else is 404 — also `/`.

The API for all of this is in [uwu-api.md](uwu-api.md) §14.
