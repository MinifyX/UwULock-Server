# Icons

Every item can have an icon. In this order:

1. **Its own icon** — a picture you chose, stored encrypted.
2. **The website's icon** — fetched by this server, for logins with an address: the address's
   own, else its domain's.
3. **An icon from the databases** that come with the server — for a website without an icon of
   its own: [2FA Directory](#icon-databases)'s by its domain, else Simple Icons'. For a device in
   your home network: Dashboard Icons' by its name.
4. **The default symbol** — the first letter of a login, or what kind of item it is.

Browsers and apps only ever talk to *your* server. Neither the web vault nor the Bitwarden apps
ask a website, Google or a CDN for an icon.

## Website icons

The Bitwarden apps and extensions ask a self-hosted server for icons at
`/icons/<host>/icon.png`, and so do the web vault and UwULock. This server answers by fetching the
website's icon itself: the page's `<link rel="icon">` and `apple-touch-icon`, then `/favicon.ico`.
It takes the one nearest to 64 pixels (at least 32), makes a PNG of at most 64 × 64 of it — from
ICO, PNG, JPEG, GIF, WebP or SVG — and keeps it for 30 days. A site without an icon is asked again
after 3 days.

**No icon of its own? Then its site's.** Many addresses below a domain have none: a login page
that answers `404` without a page, `/favicon.ico` missing too. Then the server takes the icon of
the domain above it — `account.example.com` gets the one of `example.com`, `foo.example.co.uk`
the one of `example.co.uk`. Which part is "the domain" comes from the
[Public Suffix List](https://publicsuffix.org/), which is built into the server (it is not
downloaded). The domain's icon is fetched once and kept for every address below it; IP addresses,
names without a dot and the home network's names are never changed. The second fetch goes through
exactly the same checks and limits as the first.

**Another site's icon is not this one's.** When the page of an address below a domain ends up on
another site after its redirects — the login page of a sign-in provider, a hoster's page, a
parked domain — its icon is that other site's. The server does not take it and uses the domain's
icon instead. A domain itself may send elsewhere (`example.net` to `example.com` is the same
brand), and then it gets the icon of where it ends up. The website sees the server's address, never yours. The cache holds at most 256 MiB
(100,000 sites); past that the oldest go, older entries are deleted once a day, and nothing is
kept while the disk is nearly full.

The admin switches it off under *Settings → Icons* in the admin portal (then every icon is
"none", and the apps show their symbol), sees how much is kept, and empties the cache. The files
are under `icons/` in the data directory; they can be deleted at any time and are not in the
backups. An update that changes how icons are chosen starts a new cache (`icons/auto-2` since
0.6.0-beta.2): every site is fetched again when it is next asked for, and the old cache is
deleted with the daily clean-up.

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

The router, the NAS, the printer: the server never asks them. A device named like an app —
`jellyfin.local`, `nextcloud.home.arpa`, `home-assistant` — gets that app's icon from
[Dashboard Icons](#icon-databases), by the first part of its name (also without dashes, and by
the aliases Dashboard Icons lists); the server only looks the name up in its own copy. IP
addresses name no app and get nothing.

In the web vault, open the item: under *Icon* it suggests icons from the library that fit the
device's name and the item's name, or choose *Icon → Fetch from the device*: your browser loads the
icon from the device and keeps it as the item's own icon. Browsers often refuse that — an https
vault may not load from an http device, and the device has to allow it (CORS). Then UwULock's
desktop app does it, or upload a screenshot of the logo.

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

[Dashboard Icons](#icon-databases) is part of the library too, from the server's own copy:
nothing is fetched for it, and it is there when selfh.st is not.

The admin switches the library off under *Settings → Icons*.

## Icon databases

Three open icon databases come with the server, inside its binary. A lookup is a few reads in
memory — no request leaves the server for them, and the browser and the apps still only talk to
your server.

| Database | What it has | Used for | Licence |
|---|---|---|---|
| [2FA Directory](https://2fa.directory/) ([source](https://github.com/2factorauth/twofactorauth)) | about 2,500 logos for 3,300 domains | a website without an icon, by its domain or a domain above it | [MIT](https://github.com/2factorauth/twofactorauth/blob/master/LICENSE.md), © 2014–2020 Josh Davis, © 2021 2factorauth and contributors |
| [Simple Icons](https://simpleicons.org/) ([source](https://github.com/simple-icons/simple-icons)) | about 2,500 brand glyphs and colours, 1,600 domains | the same, after 2FA Directory | [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) |
| [Dashboard Icons](https://dashboardicons.com/) ([source](https://github.com/homarr-labs/dashboard-icons)) | about 3,300 logos of self-hosted apps | devices in the home network, by name; the icon library | [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0), © 2024 Bjorn Lammers, Meier Lukas, Thomas Camlong and Homarr Labs |

The order for a website is: its own icon, its domain's (see above), then 2FA Directory by the
host and the domains above it down to the registrable one (`console.aws.example.com`, then
`aws.example.com`, then `example.com`), then Simple Icons the same way, then nothing. The icon is
drawn as a PNG of 64 × 64 pixels and kept in the cache of website icons like a fetched one — it
counts toward the same ceiling. Each database has its own switch under *Settings → Icons* in the
admin portal (all on by default), with its licence and the commit it was taken from; automatic
icons switched off switch them off too.

**Simple Icons**: icons whose entry has a licence of its own or brand guidelines are left out —
those brands ask for more than CC0 does. The glyph is put on a rounded tile in the brand's colour,
white or dark, whichever reads better, with a thin edge on very light and very dark tiles, so it
looks like an app icon in light and dark mode. Simple Icons has no domains; the server's copy
gets them where that is unambiguous:

1. a 2FA Directory entry whose name gives the icon's slug or one of its aliases (`Amazon Web
   Services` → `amazonwebservices`) gives the icon all of its domains — a strong claim;
2. a registrable domain whose name is the slug — the host of the icon's `source` address
   (`brand.example.com` → `example.com` for `example`) or one of 2FA Directory's domains — a
   weak claim.

A domain goes to the one icon that claims it strongly; without a strong claim to the one that
claims it weakly; claimed by two icons alike, to none.

**Dashboard Icons**: an SVG of at most 16 KiB is kept as it is, every other icon as a PNG of at
most 64 pixels, whichever is smaller; the light and dark variants are left out.

### Updating the databases

They are taken from fixed upstream commits (`crates/uwulock-server/icon-databases/sources.json`),
made into one pack each by `uwulock-server icon-databases`, and committed with their checksums
(`SHA256SUMS`); an update of the server brings new ones. To take the newest upstream commits:

```sh
node scripts/icons/update.mjs --bump   # fetches, builds, writes the packs, sources.json, SHA256SUMS
node scripts/icons/update.mjs          # the pinned commits again: fails unless the packs come out the same
```

It needs git, cargo and the network; only the paths that are used are fetched. The same commits
make the same packs, byte for byte, and the tests check the committed packs against `SHA256SUMS`.

### Licences

The full licence texts and notices are in [`THIRD-PARTY-NOTICES.txt`](../THIRD-PARTY-NOTICES.txt),
which is also in the container image at `/usr/share/doc/uwulock-server/THIRD-PARTY-NOTICES.txt`.
All logos are trademarks of their owners; showing one does not mean its owner endorses UwULock.
