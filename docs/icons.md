# Icons

Every item can have an icon. In this order:

1. **Its own icon** — a picture you chose, stored encrypted.
2. **The website's icon** — fetched by this server, for logins with an address.
3. **The default symbol** — the first letter of a login, or what kind of item it is.

Browsers and apps only ever talk to *your* server. Neither the web vault nor the Bitwarden apps
ask a website, Google or a CDN for an icon.

## Website icons

The Bitwarden apps and extensions ask a self-hosted server for icons at
`/icons/<host>/icon.png`, and so do the web vault and UwULock. This server answers by fetching the
website's icon itself: the page's `<link rel="icon">` and `apple-touch-icon`, then `/favicon.ico`.
It takes the one nearest to 64 pixels (at least 32), makes a PNG of at most 64 × 64 of it — from
ICO, PNG, JPEG, GIF, WebP or SVG — and keeps it for 30 days. A site without an icon is asked again
after 3 days. The website sees the server's address, never yours.

The admin switches it off under *Settings → Icons* in the admin portal (then every icon is
"none", and the apps show their symbol), sees how much is kept, and empties the cache. The files
are under `icons/` in the data directory; they can be deleted at any time and are not in the
backups.

### What the server never does

A request for an icon names a host, and anybody can make one — so the server is careful not to be
turned against its own network:

- **Only public names.** IP addresses, names without a dot, and names ending in `.local`,
  `.lan`, `.home`, `.internal`, `.intranet`, `.localhost`, `.localdomain`, `.corp`, `.private`,
  `.test`, `.invalid`, `.example`, `.onion` or `.arpa` get no icon from the server.
- **Only public addresses.** Every address a name resolves to is checked — loopback, private
  networks, carrier-grade NAT, link-local, unique-local IPv6, multicast, documentation and
  benchmarking ranges, also inside IPv4-mapped, NAT64, 6to4 and Teredo addresses. One such address
  among the answers, and the host gets nothing. The connection then goes to exactly the checked
  addresses: a DNS server cannot answer differently a second time (DNS rebinding).
- **Redirects** (at most five) are checked the same way before they are followed, and only to
  `http` or `https` on the usual ports.
- **Limits**: 5 seconds to connect, 10 seconds for everything, 512 KiB of a page and of an icon,
  images decoded only up to 2048 × 2048 pixels and 64 MiB (a small file that unpacks into a huge
  image is refused), SVG drawn without text, fonts or anything it points to, and refused when it
  would grow into more than 5,000 elements once drawn (nested `<use>`, clip paths used by many
  elements). At most two images are decoded at once. At most 8 fetches at
  a time, one per host; each address may start 60 fetches, one more per second — icons from the
  cache cost nothing.
- **No names in the logs or metrics.** `uwulock_icon_fetches_total` counts by result only.

### Devices in your home network

The router, the NAS, the printer: the server never asks them. In the web vault, open the item and
choose *Icon → Fetch from the device*: your browser loads the icon from the device and keeps it as
the item's own icon. Browsers often refuse that — an https vault may not load from an http
device, and the device has to allow it (CORS). Then UwULock's desktop app does it, or upload a
screenshot of the logo.

## Own icons

*Web vault → an item → Icon → Upload …*: PNG, JPEG, WebP or SVG. The browser draws it at 128 ×
128 pixels at most, turns it into a PNG, encrypts it — with your account's extras key, or for an
organisation's item with the organisation's key, so every member sees it — and stores it with the
item. The server cannot see it. It counts toward the storage of the account.

The Bitwarden apps ask for icons by host name and without logging in, so they show the website's
icon, not your own. Moving an item into an organisation drops its own icon (UwULock's apps put it
back under the organisation's key); deleting an item for good deletes its icon.

## The icon library

*Icon → From the library …* searches [selfh.st Icons](https://selfh.st/icons/), a collection of
logos of self-hosted and other software, licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) ("Icons by selfh.st"). The server
mirrors the library's index once a day (and when the admin clicks *Reload the library*); the
search runs in your browser. The icon you pick is fetched by the server from the library's one
host, kept, and handed to your browser, which stores it in the item like an uploaded one —
encrypted, so the server does not learn which icon belongs to which item.

The admin switches the library off under *Settings → Icons*.
