# Changelog

Each release gets a section here before its tag is pushed; CI copies the section into the GitHub
release. Versions follow semver; `-beta.N` versions are pre-releases.

## Unreleased

- **Web vault: items, entry Sends, passkeys and a new look.** Needs UwULock-Client's core at
  `b9580a2` (pinned in `web/wasm` and `uwulock-e2e`).
  - Password generator: a minimum per kind of character (A–Z, a–z, 0–9, symbols); the length grows
    to fit them and says so. Remembered in the browser with the other options.
  - One-time codes: in the last 10 seconds of a code the next one shows below it, small, with a copy
    button of its own ("Nächster: 123 456").
  - An item's page shows its first website; the others are behind "+2 more websites".
  - Editor: the favourite is a star in the name field instead of a checkbox; the reminder to renew
    is a switch in the editor, and the item's page shows the reminder only while it is on.
  - Passkeys: an item's page lists its passkeys — site, user, created — and deletes one after
    asking (named by its credential id, or its fingerprint when UwULock can't read it — never by
    its place alone), instead of "Has a passkey – UwULock can't use it yet". *Duplicate* (own items) makes a
    copy with the passkeys; attachments stay behind.
  - Share as Send: the choice lists each website with its address; the one-time codes can be shared
    (never ticked at the start, and ticking them asks once more: their key travels in the Send, and
    whoever has the link can read it). It is now an entry Send: readable lines for the Bitwarden apps
    (never the authenticator key), and a last line `uwulock-entry:v2:….<tag>` from which UwULock's
    Send page shows the item with copy buttons, secrets behind the eye and live codes — never the
    key or a QR code — and the original text on request. The tag is keyed from the link's secret
    part, so a marker line in an item's notes can't make a plain Send look like an entry; only
    http(s) websites become links. An entry Send's text can't be edited (delete it and share
    again). Plain Sends look as before (docs/sharing.md).
  - Font choice like UwUMail (*Appearance → Font*, per device): UwU Sans (the new default), Manrope,
    Rubik, DM Sans or the system's; only the chosen one is loaded, all from the server. UwU Sans'
    `:3`/`<3` ligatures are off everywhere, so values always look as they are. Licences (SIL OFL 1.1)
    in THIRD-PARTY-NOTICES.txt.
  - Checkboxes and switches in UwUMail's style, still native controls, with high contrast and Windows
    contrast themes.
  - More Nyu: empty trash, Sends and file requests, loading, unlocking, the password check, toasts and
    empty lists in the admin portal. Every animation follows *Appearance → Animations* and the
    system's wish for less motion.

- **Security check 0.8** (docs/security-review-0.8.md). Fixes every Medium and Low finding of the
  server review:
  - **Client address behind a proxy:** the last `X-Forwarded-For` entry is read from the raw bytes,
    `X-Real-IP` only counts without any `X-Forwarded-For`, and forwarding headers only count from
    `UWULOCK_TRUSTED_PROXIES` (addresses or CIDR ranges, comma separated) when it is set.
    `install.sh --trusted-proxy ADDRESS` sets it and asks for it with `--proxy-network`; without it
    the server trusts every peer as before and the installer warns. Set it if other containers share
    the proxy network.
  - **Logins:** a second bucket per IPv6 /48 (100, then one every 6 s); at most 30 wrong passwords
    per account and 2 hours from unknown devices (`429 account_limited`; known devices still get
    in, nobody is locked out); `503 busy` with `Retry-After: 2` at once when the password hashing
    queue is long, instead of a 408 after a minute.
  - **Admin portal:** changing the SSO provider (issuer, client id or secret, unverified addresses,
    extension ids, on/off), pairing SSO, *make admin* and *reset second step* ask for the master
    password.
  - **API keys:** bound to the security stamp (migration 0024): a password change, *log out
    everywhere*, key rotation or emergency takeover ends the old key. Unencrypted backups no longer
    hold API keys.
  - **Prelogin:** an unknown address gets a stand-in KDF that stays the same for it, chosen like
    real accounts' defaults, so the answer tells nobody which accounts exist.
  - **Organisations:** the delta sync tells a member only of items and collections they could see
    (an item moved out of their collections still disappears; migration 0025); Bitwarden clients'
    realtime messages name an item only to members who see it; attachment links stop once the member
    no longer sees the item; attaching file-request files into a family item counts against its
    owners' storage.
  - **Limits:** file-request messages count against the owner's storage and the request's cap; bulk
    lists take at most 5 000 ids and an account at most 100 000 items; connections are capped (8 192
    overall, 256 per /64 when the server does TLS itself); a public file-request upload has a whole
    deadline; an account waits with at most 4 XposedOrNot questions at a time.
  - Dependencies: `rustls-pemfile` (unmaintained) replaced by `rustls-pki-types`' PEM parsing;
    `yoke-derive` updated (the old one was yanked).
  - **Upgrade note:** backups made before 0.8 may still hold the Bitwarden push relay's
    installation key (sealed with `secret.key`). If you had push set up, regenerate or delete the
    installation id at bitwarden.com/host.
  - The SCIM token acts with admin rights over every account (it can disable or delete any but the
    last admin): keep it like an admin password (docs/sso.md).

## 0.7.0-beta.3

**Restores that work on a new machine.** A disaster-recovery drill restored a filled server from
SFTP, S3, a folder and a local backup onto a clean one; this release fixes what it found.

- **Bitwarden's push relay is gone (plan change).** The server no longer wakes Bitwarden's phone
  apps through Bitwarden's relay: it needed an installation id and key from bitwarden.com/host and
  sent account and device ids to Bitwarden with every change. Bitwarden's apps for iOS and Android
  sync when they are opened; everything else keeps its live updates (Bitwarden's notification hub,
  UwULock's own `/uwu/v1/realtime`). Removed: the admin portal's tab *Push for the apps* and its
  connection test, the `push` settings, the diagnosis check `pushRelay`, the admin notification
  `pushRelayFailing` and the metric `uwulock_push_relay_errors_total`. The apps' push tokens are
  answered 200 and dropped. Schema step 0023 removes the stored relay settings, the devices' push
  tokens and relay ids, and `pushRelayFailing` from the channels' events.
- **Password check: no more "incomplete" because XposedOrNot said 429.** The web vault asked
  XposedOrNot (through the server) four prefixes at a time, the server sent each on at once, and
  XposedOrNot answered many of them with 429. Now all accounts' questions wait in one queue on the
  server, one a second; a 429 pauses the queue for as long as XposedOrNot's `Retry-After` says (at
  most two minutes) and the prefix is asked again, up to four times. A queue that would keep a
  request longer than a minute answers 429 `busy` and the web vault asks again later. The web
  vault asks Have I Been Pwned and XposedOrNot side by side, shows HIBP's results as soon as they
  are in, and shows the progress per source ("XposedOrNot: 120 von 363"); a check that takes a few
  minutes is fine. The note that a source did not answer only comes for real failures.
- CI: the ACME tests against Pebble no longer run out of time now and then. Pebble turns away 5%
  of good nonces by default, rustls-acme fails the whole order on a badNonce and backs off 1, 2,
  4 … 64 seconds, and a few of those in a row took the send-domain test past its two minutes.
  Pebble now runs with `PEBBLE_WFE_NONCEREJECT=0`; both tests take about 3 seconds.
- Feature switches that came only from `UWULOCK_FEATURES` now go along in backups. While the
  line counts (nobody switched in the portal or on the command line), the server keeps what it
  says in the database (`features.start`), at every start and after a restore in the portal; a
  server restored on a new machine without that line keeps the extras it had, instead of losing
  `offsite-backups`, `families` and the rest. A switch by an admin still wins, and a changed
  `UWULOCK_FEATURES` still counts until somebody switches (docs/features.md).
- `backup restore` without a terminal and without `UWULOCK_BACKUP_KEY` says that no recovery key
  was given and how to give one, instead of "the recovery key does not fit this backup".
- A wrong `--host-key` for `backup restore` names the key the SFTP server showed and says to pass
  it with `--host-key` once checked; "forget the old key" was the portal's advice.
- A restore from the command line leaves nothing behind in the data directory: `backup-tmp/` goes,
  and so do `uwulock.db-wal` and `-shm`. The database now closes its write connection last, so
  SQLite folds the log in and removes both, for every command that opens it.
- `install.sh --no-start` sets everything up and fetches the image, but does not start the server:
  a restore can go into the empty data directory first.
- Docs: off-site backups have to be switched on first (`offsite-backups`); the order of a restore
  on a new machine (`install.sh --no-start`, restore, `docker compose up -d`); an SFTP login for
  the restore (password or a fresh key, `chown 10001`), the host key, S3 in your own network with
  `--path-style`, every option including `--port`; keeping the snapshot restored from when the
  new machine backs up the same day; feature switches after a restore; and what besides
  `/data/backups` a move by hand needs (`secret.key`, the files, `acme`), into a volume owned by
  uid 10001.

## 0.7.0-beta.2

**UwUSSH's and UwURDP's entries in the web vault.** The web vault has two new sections in the
sidebar, *SSH (UwUSSH)* and *Remote Desktop (UwURDP)*, with everything the apps keep in the suite
vault — viewable and editable, while the switch *Suite vault* is on. The links into the apps need
UwUSSH and UwURDP builds that know them (UwUSSH 0.3.0-beta.2, UwURDP 0.1.0-beta.11).

- Hosts by workspace and group, groups, identities, SSH keys, snippets, port forwards and known
  hosts, each with a search, details and an editor. RDP hosts with every setting: display and
  resolution, colour depth, audio, clipboard, console session, NLA, wallpaper, graphics pipeline,
  gateway with its own login, drive redirection (also per group, with the group's login).
- Passwords are shown, copied and changed, with the generator; keys are imported (OpenSSH, PEM,
  PuTTY) or made new as Ed25519 in the browser, optionally with a passphrase, and the private key
  is shown or downloaded.
- A host's extras: copy the command (`ssh -p 2222 user@host`, or `host:port`), download an RDP
  host as an `.rdp` file (without password, drives off), and on a computer *In UwUSSH öffnen* /
  *In UwURDP öffnen* (`uwussh://connect/<id>`, `uwurdp://connect/<id>`: only the entry's id goes
  along).
- Deleting works as in the apps: a host takes its port forwards along; an identity or a key goes
  only when nothing uses it any more (else the web vault lists what does), and its password or key
  with it; a group leaves its hosts without a group.
- The records are written by the apps' rules (their clocks, `baseSeq`, fresh nonces, tombstones),
  and fields the web vault doesn't know stay as they are. When something changed on another
  device meanwhile, the web vault reloads it and asks to apply the change again. Changes in the
  apps show up at once (the realtime channel).
- When no app has synced yet, the web vault can create the space.
- The server takes UwUSSH 0.3's assistant records (`assist_config`, `assist_cache`) in the SSH
  space; before, their sync was refused.

**Security.** The new sections were reviewed ([docs/security-review-0.7.md](docs/security-review-0.7.md),
"0.7.0-beta.2: SSH/RDP entries"); two medium and six low findings are fixed:

- The copied SSH command can't turn a user or an address that starts with `-` (like
  `-oProxyCommand=…`, written by another device) into an option; control characters are dropped
  from it and from the `.rdp` file.
- Deleting a key or an identity takes along only `secret` records; the link into the app is only
  offered for an id that is a UUID; ids in other spellings from the server are not taken; a pull
  that doesn't move on stops; creating the space runs in line with loading it; odd values of a
  record (`constructor`) no longer break its details.
- A record is checked against the space key before an edit or a delete is sealed on top of it,
  so a server can't slip a made-up clock into what the web vault signs.

**Maintenance.**

- The web vault's crypto and the end-to-end tests use UwULock-Client's core with the suite module
  (UwULock 0.4.0-beta.2).
- A new end-to-end test: the web vault makes the space and writes entries, UwUSSH opens them, and
  an edit in the web vault keeps what the app added.

## 0.7.0-beta.1

**Checking passwords one by one, more breach sources, Wi-Fi and failed logins.** The password
check gets a second view that goes through the logins with a problem one card at a time — open
the site's change-password page, save a new password, put it off or ignore it — and asks
XposedOrNot as well as Have I Been Pwned; the server also keeps the public lists of breached
sites, so a login whose site lost passwords after its last change is marked, and, if the admin
and the account agree, checks addresses at XposedOrNot. The web vault has Wi-Fi networks with a
QR code, stored so that Bitwarden's apps show them as notes, and imports them from 1Password,
Proton Pass and LastPass. Failed logins have their own page in the admin portal with origin
(from a GeoIP database on the server), device and app, and addresses can be blocked. The web
vault opens only its own vault, and everything new was reviewed for security. It belongs with
UwULock 0.4.0-beta.1. Update with `sudo bash update.sh`; database steps 19 and 22 run on their
own, and the server then downloads the GeoIP databases (about 130 MB) by itself.

**Maintenance.**

- The image is built on a newer distroless base whose OpenSSL has the fixes for the two findings
  the image scan skipped since 0.6.0-beta.2; the scan skips nothing any more.
- The end-to-end tests and the web vault's crypto use UwULock 0.4.0-beta.1's core.

**Wi-Fi networks.**

- The web vault has a Wi-Fi item type: its own icon, its own filter under *Types* and its own
  choice under *New*. The editor has the network's name (the item's name follows it), the
  security (WPA3, WPA2/WPA3, WPA2, WPA, WEP, none, WPA2-/WPA3-Enterprise), the password with the
  generator and *Hidden network*; EAP method, phase 2, identity, anonymous identity and CA
  certificate appear only for Enterprise. The details copy every value and share the network as
  a QR code (`WIFI:…`, drawn in the browser), with the password hidden until asked.
- Stored the Bitwarden way, as a secure note with custom fields and the marker
  `uwulock:type` = `wifi`: Bitwarden's apps show a note with fields, every UwULock app a network.
  Other fields of the item stay as they are, and the JSON export keeps every field
  ([docs/wifi.md](docs/wifi.md) has the contract all UwULock apps share).
- The import makes Wi-Fi networks of 1Password's wireless routers (1PUX and CSV), Proton Pass's
  Wi-Fi items (JSON and CSV), LastPass's *Wi-Fi Password* form and of every entry that already
  has the marker (KeePass, Bitwarden); the preview counts them apart from the notes.

**One vault in the web vault.**

- The account menu in the web vault no longer offers *Add account* (or other accounts, or
  renaming), which it had from the desktop app and which did nothing: the web vault opens this
  server's vault, one account at a time. The menu now has *Lock* and *Log out*.

**Failed logins.**

- The overview's tile "Failed logins" leads to a page of its own (*Security & sign-in → Failed
  logins*): every refused login of the 90 days with its reason (wrong password, no such account,
  account disabled, wrong API key, wrong second step), the account it was for (with a link to it,
  or "does not exist"), the IP address with country, city and network, the device, the app and
  its version, and the user agent. Filters for the time range, the account, the address (also
  `203.0.113.*`) and the reason; grouped by address with how many accounts were tried; the whole
  history of an address, logins that worked included ([docs/failed-logins.md](docs/failed-logins.md)).
- Logins now keep what the client said about itself: `User-Agent`, `Bitwarden-Client-Name` and
  `-Version` (or the `client_id`), and the device's name — refused ones and those that worked.
- **Blocking addresses.** "Block IP" blocks an address or a network for an hour up to 30 days, or
  until lifted; *Security & sign-in → Blocked addresses* lists and lifts the blocks. A blocked
  address gets 403 `ip_blocked` from every login endpoint — the token endpoint with all its
  grants, the prelogin, registering, the password hint, the second step's mail, passkey and SSO
  starts, "log in with a device" — so also in the web vault and the admin portal. The portal
  will not block the admin's own address. `uwulock-server blocks` lists the blocks on the command
  line, `uwulock-server blocks remove <address>` lifts one.
- **GeoIP on the server.** Where an address is comes from DB-IP's free City Lite and ASN Lite
  databases (CC BY 4.0), which the server downloads once a month into `<data>/geoip` (about
  130 MB) and looks addresses up in — no address is sent anywhere. The setting `geoip` (on by
  default) switches it off; then the files are deleted.
- Database step 19: the event log gets the client's details and the reason, two indexes, and the
  table of blocked addresses.

**The password check, one login at a time, and more breach sources.**

- *Durchgehen / Review one by one*: beside the report (which stays as it is), a stack of cards,
  one per login with a problem — breached, a breach of the site after the last password change,
  reused, weak, no https, 2FA possible. "3 von 12"; swipe or the arrow keys to move. Each card
  opens the site's change-password page (or the login), generates and saves a new password (the
  old one goes into the item's history, as in Bitwarden), puts the login off until later, or
  ignores a problem for good. What is ignored is kept encrypted under the extras key, so every
  UwULock app shares it, and can be undone in the report's new "Ignoriert" list. Works with touch
  at phone width.
- XposedOrNot's passwords as a second source next to Have I Been Pwned: the browser sends ten
  characters of a Keccak-512 of each password through the server, which keeps the answers a day
  per account and writes nothing down.
- Breached sites: the server fetches the public lists of Have I Been Pwned and XposedOrNot once a
  day, merges them by domain and hands them to the vault, which marks logins whose site lost
  passwords after the login's password was last changed. No user data leaves the server.
- Addresses at XposedOrNot (off by default): when the admin turns it on and an account agrees,
  the server checks the account's address and the logins' addresses, within XposedOrNot's free
  limits for the whole server, keeps the answers a week under a salted hash and logs no address.
- Change-password pages: the server looks for `/.well-known/change-password` on the login's site
  (never in the local network, like the icons) so "open the page" lands where the password is
  changed.
- Each source has its own switch in the admin portal (*Vault & features → Icons & password check*);
  `/uwu/v1/info` and `/uwu/v1/account` say which are on. API: [docs/uwu-api.md](docs/uwu-api.md)
  §15.1–§15.7. Migration 0022 adds `health_ignores`, `breach_email_opt_ins`, `breach_email_cache`.

**Small fixes in the web vault and the admin portal.**

- The account menu at the foot of the sidebar opens above the account card instead of over it,
  inside the window on a phone too, with its entries in line on the left.
- The admin portal and the web vault share one theme setting (dark by default, as in every UwU
  app; *System* follows the browser). A change in one tab now reaches the other open tabs at
  once: switching the vault to *System* or *Light* no longer leaves an open admin portal dark.
  Every admin page passes the contrast checks in the light theme; a browser test checks it.

**Security review of the new parts.** Everything new since 0.6.0-beta.2 was reviewed
([docs/security-review-0.7.md](docs/security-review-0.7.md)): nothing critical or high, two
medium and seven low findings, all fixed.

- Merging the lists of breached sites keeps at most 100 breaches per domain, so a hostile list
  can no longer keep the server busy for minutes (SV7-M1).
- Failed requests to HIBP and XposedOrNot are logged without their address, which carried a
  password's hash prefix (SV7-L1). While the breach lists cannot be fetched, requests try again
  only every five minutes instead of each one fetching anew (SV7-L2).
- GeoIP downloads follow redirects only to https on the internet (SV7-L3).
- An IPv4 network written as IPv6 (`::ffff:198.51.100.0/120`) is blocked as the IPv4 network it
  is; before, such a block was listed but not enforced, and `::ffff:0.0.0.0/96` got past the
  size check (SV7-L4). The same holds for `adminNetworks`.
- The web vault no longer opens the change-password address the server names: the server only
  says whether there is a page, and the web vault opens `/.well-known/change-password` on the
  login's own host, so a hostile server cannot send anybody to another site (WV-1, like CL-M3 in
  the apps). 2FA guides are linked only when they are http(s), a Wi-Fi item with an odd
  *Security* value no longer breaks its view, and *Block address* suggests the /64 of an IPv6
  address (WV-2 to WV-4).

## 0.6.0-beta.2

**Tidying up after 0.6.** The admin portal is sorted into areas with tabs, and every setting says
in plain words what it does and what is recommended; it now looks like the web vault, whose
spacing is even again. The admin switches off the extras this server does not need: a new server
starts with only the vault and icons, and an update switches off every extra that nobody uses
(nothing is deleted). Website icons fall back to the domain's (`account.example.com` →
`example.com`) and, where a site has none, come from 2FA Directory, Simple Icons or Dashboard
Icons, which ship with the server. Every low finding and note of the 0.6 review is fixed. It
belongs with UwULock 0.3.0-beta.2, UwUSSH 0.2.1 and UwURDP 0.1.0-beta.8. Update with
`sudo bash update.sh`; every client syncs in full once afterwards, and a server with sealed
settings no longer starts without its `secret.key`.

**Website icons.**

- An address without an icon of its own now gets its domain's: `account.example.com`, which
  answers 404 and names no icon, shows the icon of `example.com`. Which part is the domain comes
  from the Public Suffix List built into the server (`foo.example.co.uk` → `example.co.uk`); IP
  addresses, names without a dot and the home network's names stay as they are. The domain is
  fetched once for every address below it, through the same checks and limits as every other
  fetch ([docs/icons.md](docs/icons.md)).
- An address whose page ends up on another site after its redirects (a sign-in provider, a
  hoster's or a parked domain's page) no longer gets that site's icon, but its domain's.
- The cache of website icons starts anew (`icons/auto-2`): every site is fetched again when it
  is next shown, and the old cache — with its "none"s that would now keep the domain's icon away,
  and icons of other sites — is deleted with the daily clean-up.
- Three open icon databases now come with the server, inside its binary: 2FA Directory (MIT,
  about 2,500 logos for 3,300 domains), Simple Icons (CC0, about 2,500 brand glyphs on a tile in
  the brand's colour; icons with a licence or brand guidelines of their own are left out) and
  Dashboard Icons (Apache-2.0, about 3,300 logos of self-hosted apps). A website without an icon
  of its own, nor its domain, gets 2FA Directory's by its domain, else Simple Icons'. A device in
  the home network is still never asked, but one named like an app (`jellyfin.local`,
  `nextcloud.home.arpa`) gets that app's icon from Dashboard Icons. Nothing is fetched for them;
  the browser and the apps still only talk to your server.
- Dashboard Icons is part of the icon library, also without selfh.st. An item for a device in the
  home network suggests library icons that fit its name.
- Admin portal, *Vault & features → Icons & password check*: each database has its own switch (all on) and a list of
  where the icons come from, with their licences. The licence texts are in
  `THIRD-PARTY-NOTICES.txt`, also in the image under `/usr/share/doc/uwulock-server/`. The
  databases are taken from fixed upstream commits and updated with
  `node scripts/icons/update.mjs --bump` ([docs/icons.md](docs/icons.md#icon-databases)).

**Web vault: even spacing and one set of building blocks.**

- Spacing, type sizes, radii and control heights come from tokens (`web/src/styles/tokens.css`):
  fields, selects and buttons are one height again, so a field and its button line up, and the
  focus ring no longer squares the corners of a field.
- The item editor lines up: labels no longer grow when a field has buttons (they sit inside the
  field now), card expiry and identity fields share one row height, websites and fields of one's
  own are groups with the same heading and add buttons, and website rows stack on a phone. A
  field that never had a value no longer says it will be cleared.
- Dialogs have even padding, a close button in the title bar where they had one, hairlines when
  their content scrolls, and one footer order (cancel, then the main action, at the end).
- Settings: each section starts at the top with the same heading, rows put their control below
  the text on a phone, and the section list scrolls sideways there instead of wrapping.
- Item details: the icon, the rows and the notes keep one inset from the card's edge; a long
  title wraps instead of breaking inside words on a phone. The password check fills the screen
  on a phone instead of starting halfway across.
- One set of components for the web vault and, next, the admin portal: buttons, icon buttons,
  fields, selects, check boxes, toggles, form rows, field groups, cards, sections, tabs, badges,
  callouts, tables and the dialog ([docs/ui.md](docs/ui.md)). No behaviour changed.

**Admin portal: areas with tabs, plain words, and the web vault's look.**

- The portal is sorted into eight areas in the sidebar, each with its tabs: *Overview*, *Users &
  invitations* (accounts, invitations, families), *Security & login* (login, master password,
  admin portal, SSO provider, SSO rules, SCIM), *Vault & features* (features, storage & limits,
  icons & password check, masked addresses, send domains), *Mail & notifications* (mail server,
  mails to users, push for the apps, admin alerts), *Backups* (on this server, off-site),
  *Branding* and *System & diagnosis* (diagnosis, events, log, monitoring). The long settings
  page is gone; each setting is found in one or two clicks. Tabs of switched-off features are not
  there.
- Every setting says in one plain line what it does, with the technical term where it helps
  (Argon2id, PBKDF2, OIDC, SCIM), its unit spelled out (days, megabytes, hours) and the
  recommended value on a green badge. German and English.
- Settings are saved together as before: changed on any tab, a bar at the foot of the page offers
  *Save* and *Discard*. What cannot be undone (deleting an account, resetting two-step login,
  restoring an off-site backup, the strict SSO rules) sits framed apart, and still asks first;
  unpairing from UwUAuth now asks too.
- The portal uses the web vault's shell (bar, sidebar with the account at its foot) and its
  building blocks throughout; the portal's own copies of buttons, cards, tables and badges are
  gone. On a phone the areas and the tabs are rows that scroll sideways.
- Old addresses (`#/settings`, `#/features`, `#/logs`, `#/notifications`, …) lead to their new
  place. `1` … `8` open the areas, `J`/`K` go to the next and previous one, the arrow keys move
  between tabs.
- A table that scrolls sideways and the diagnosis' snippets take the keyboard focus, and the
  green badges have 4.5:1 contrast in the light theme.

**Feature switches: the admin decides which extras this server offers.**

- *Admin portal → Vault & features → Features* has a switch for each UwULock extra, grouped and with one line each:
  families, file requests, send domains, masked addresses, versions, reminders, travel mode, the
  emergency sheet, own icons, the icon library, 2FA hints, SSO, SCIM, off-site backups,
  notifications through ntfy/Gotify/Matrix and the suite vault ([docs/features.md](docs/features.md)).
  The vault and everything the Bitwarden apps use are always there.
- Off means: its endpoints answer 404 `feature_off`, its jobs stop, and the web vault and the admin
  portal hide it; a link that leads there says "Not on this server". Nothing is deleted, and
  switched on again, everything is back. SSO off makes a server without SSO (master passwords
  work again); travel mode cannot be switched off while someone travels.
- **A new server starts with only the vault and icons.** An updated server keeps on what it uses
  (data or a setup), everything else is off. `UWULOCK_FEATURES` sets what a new server starts
  with, `uwulock-server features [list|on|off]` changes them on the command line, and moving in
  from Vaultwarden switches families on when organisations come along.
- `/uwu/v1/info` lists every switch under `switches`; the admin API is
  `GET|PUT /uwu/v1/admin/features`, and every change is in the event log
  ([docs/uwu-api.md](docs/uwu-api.md) §2, §21.12).
- The on/off settings of file requests and the suite vault moved into the switches
  (`fileRequests.enabled` and `suite.enabled` are gone from the settings).

**The low findings of the 0.6 review, fixed.** Every low finding and note of
[the review](docs/security-review-0.6.md) that stayed open for 0.6.0-beta.1 (SV-L1 to SV-L41,
SV-I1 to SV-I4) is fixed; the review says how, finding by finding. What admins and client
authors notice:

- **Migration 0018**: SCIM remembers which accounts it disabled
  (`scim_disabled`), organisation tombstones keep their collections, the sync epoch starts anew
  (every client syncs in full once), and leaving or being revoked from an organisation removes
  one's reminders and masked links there.
- **Suite push:** `POST /uwu/v1/suite/spaces/{space}/records` takes `spaceId`; a push sealed for
  a space that was rekeyed since is refused with 409 `space_changed`. Pushes without it are still
  taken (UwUSSH and UwURDP send it from their next releases on).
- **Secrets at rest:** the SMTP and Loki passwords, the push relay key, the channels' tokens and
  the off-site secrets and recovery key are sealed under `secret.key` now, existing ones at the
  first start. Without `secret.key` but with sealed values the server refuses to start;
  `UWULOCK_NEW_SECRET_KEY=1` for one start empties them instead.
- **Two-step login duty:** an account that must set up a second step gets a setup-only token
  (scope `uwu.twofactor-setup`, everything else 403 `two_factor_required`, an empty sync) until
  it has one, from any client.
- **SSO:** the redirect of browser extensions is pinned to the released ones; self-built ones
  are listed in the SSO settings (`extensionIds`). The issuer takes no `?query`, endpoints on
  loopback http only with an issuer there, and a failing provider is asked once in 30 seconds.
- **Off-site backups:** an SFTP server's host key is confirmed before any login (the portal asks;
  the command line needs `--host-key`). The command line reads the recovery key without echo and
  asks before putting back the newest snapshot; the portal warns when the last snapshot this
  server wrote is missing at the target. A restore whose files fail still finishes its steps.
- **Alerts:** channels get fixed texts with the status code, not another server's words; admin
  test buttons show only the status of what they reached.
- **Sends and file requests:** send domains are recognised with a dot at the end, Send codes
  have eight digits with daily caps and caps per Send and owner, a file request holds at most
  2 GB by default (`fileRequests.maxRequestMb`), and uploads stop when a request closes.
- **More:** a WebSocket ticket instead of the admin's token in the diagnosis
  (`POST /uwu/v1/admin/diagnosis/websocket-ticket`), at most 25 sockets per address waiting for
  their login (429), masked connects need this server on https (`https_required`), invitations
  count admins as admins only where the portal is open, automatic icons refuse more NAT64
  ranges and answer a cached icon like a missing one when out of tries, Loki lines are capped,
  "Share as Send" asks for the master password first, and the importers have size limits and
  stricter checks.

## 0.6.0-beta.1

**Families, the UwU extras, and a server that looks after itself.** Stages 4b, 4c, 4d and 6 of
[the plan](docs/plan.md) at once: backups off-site, alerts, metrics, logging in through UwUAuth
or another OpenID Connect provider; entry versions, reminders, travel mode and more importers in
the vault; families; and UwULock's own extras: delta sync and a realtime channel, the suite vault
for UwUSSH and UwURDP, file requests, Sends on domains of their own and masked addresses from
UwUMail. It belongs with UwULock 0.3.0-beta.1 and its browser extension. A security review came
before the release; what it found high or medium is fixed (the last part below), the low findings
are listed in [docs/security-review-0.6.md](docs/security-review-0.6.md). Update with
`sudo bash update.sh`. Unencrypted off-site backups to SFTP or S3 stop until they are saved again
with encryption. Stufe 5 (companies) is not part of it and stays planned.

**The UwU extras (Stufe 6).**

- **Delta sync** (`GET /uwu/v1/sync`) for UwULock's own clients: a first full sync with
  UwULock's own data (extras key, own icons, reminders, travel mode, each Send's domain, the
  masked addresses' links, unseen counts, the suite vault), then only what changed, deletions included, paged by change numbers. Every change is
  counted by database triggers, per account and per family; tombstones are kept 90 days. Key
  rotations, membership changes, travel mode, large imports and a restored backup make the next
  sync a full one (`reset`). A delta of a 5,000-item vault takes about a millisecond
  ([docs/performance.md](docs/performance.md), [docs/sync.md](docs/sync.md)).
- **Realtime channel** (`/uwu/v1/realtime`, subprotocol `uwu.realtime.v1`): the token in the first
  message and renewed on the same connection, heartbeat with a session check, `changed`,
  `logout`, `notice` (security notices, file-request submissions, due reminders) and `info`
  (also when a send domain or a UwUMail server is added or removed); fed from the same place as
  the SignalR hub. 20 connections per account.
- **Suite vault** for UwUSSH and UwURDP (`docs/uwu-api.md` §6, [docs/suite.md](docs/suite.md)):
  the apps log in with `client_id=uwussh|uwurdp` and `scope=uwu.suite offline_access`, two-step
  login and remembered devices included, and get a token that opens their own space only. Spaces
  keep UwUSync's record model (numeric cursor, conflicts, 500 records / 8 MiB per push), their
  keys under the extras key; rekeying gives a space a new id. Quotas per account
  (`suite.maxRecords`, `suite.maxMb`, counted in the storage limit), a switch in the admin portal,
  and the spaces with their size under *Settings → Devices* in the web vault, deletable with the
  master password. The apps' own scenarios, the move from UwUSync included, run in `uwulock-e2e`.
- **Security notices** for the extras key (created, wrapped again, lost in a rotation), for
  every login of a UwU app and for masked addresses; travel mode's notices are named in the mail
  too.
- **Password health**: the web vault keeps its report, encrypted under the extras key, and shows
  it again with its date.
- New metrics: `uwulock_sync_duration_seconds{kind="full"|"delta"}` and
  `uwulock_live_connections{channel="realtime"}`.
- Proxies: `/uwu/v1/realtime` is a WebSocket; the nginx example passes it.
- **Send domains**: extra names like `send.example.com` that serve only Sends and file requests —
  no web vault, no login, no admin portal — with short links
  (`https://send.example.com/<id>#<key>`; the old `/#/send/…` links keep working). The admin adds
  several; each gets its certificate from Let's Encrypt through the server itself (TLS-ALPN-01,
  one certificate per name, chosen by SNI) or from a proxy in front, and can have a look of its
  own (name, colour, logos, favicon), which the page and the mail with a Send's code follow.
  Every Send opens under every address; the account's default and a choice per Send or file
  request only decide which link is shown. The admin portal checks DNS, HTTPS and routing per
  domain; the diagnosis and `/metrics` watch each certificate ([docs/send-domains.md](docs/send-domains.md)).
- **Masked addresses from UwUMail**: connect your UwUMail mailbox once (OAuth with PKCE, a scope
  that can only make masked addresses) and make a mail address of its own for each website — in
  the web vault's settings, its generator and next to an item's username. Switch them off, on or
  delete them; deleting an item offers to switch its address off. The official Bitwarden apps
  make them too, through addy.io- and SimpleLogin-compatible endpoints with keys from the web
  vault. The admin lists which UwUMail servers the server may talk to; tokens are kept encrypted
  with the server secret, and connecting, disconnecting and new keys are security notices
  ([docs/masked-addresses.md](docs/masked-addresses.md)).

**Families (Stufe 4d).**

- **Share with your family**: make a family in the web vault, invite people by address, and
  confirm each one after comparing the fingerprint phrase of their key — only then does the
  family's key reach them. Collections with read or read-and-write access per member; items move
  in from the web vault, the UwULock app and the official Bitwarden apps and CLI, and every
  client sees the family like any Bitwarden organisation. Owners hand over, remove, rename and
  delete; members leave. Somebody without an account registers with the family's invitation when
  the inviter may invite people to the server ([docs/families.md](docs/families.md)).
- The admin decides who may make a family (everyone, admins, nobody), how many members one has
  and how many one account owns, and lists and deletes families in the portal. Organisations moved
  over from Vaultwarden with only owners and members are managed the same way.
- Mails for invitations, members waiting to be confirmed and being confirmed, in German and
  English; security notices for joining, leaving and a changed role; live updates to every device.
- Newer Bitwarden apps did not list organisations at all (the profile's `organizationsNew` was
  empty); they do now.

**Comfort in the vault (Stufe 4c).**

- **Import from other password managers**, read in the browser — the server only ever sees what
  it encrypted: KeePass and KeePassXC (KDBX 4 and 3.1 with the file's password and key file,
  Argon2 or AES-KDF, AES or ChaCha20; and their CSV), 1Password (1PUX and CSV), Chrome and Edge,
  Firefox, Apple Passwords, Proton Pass (JSON or its zip) and LastPass. A preview shows what comes
  and into which folders, TOTP keys come along, and whatever has no place of its own becomes a
  custom field instead of getting lost ([docs/import.md](docs/import.md)).
- **Share an item as a Send**: tick the values — never the authenticator key — and the item's
  name with them becomes a text Send that goes after a day and opens once, unless you say
  otherwise. An ordinary Send, visible in every app.
- **Sends only for given addresses**, Bitwarden's "Send with email verification": whoever opens
  the link gives their address and gets a code by mail. The answer is the same for addresses on
  and off the list, codes last five minutes, five wrong ones end a code, and mails are limited per
  Send and address. Needs mail on the server; the newest Bitwarden apps open such Sends too
  ([docs/sharing.md](docs/sharing.md)).
- **"2FA possible, not set up"** in the password check: logins for sites that offer authenticator
  codes, without one stored, with a link to the site's instructions. The list is
  [2FA Directory](https://2fa.directory/)'s (MIT), mirrored by the server once somebody asks and
  then daily; the comparison happens in the browser, so the server never learns which sites are
  in a vault. The last report can be kept, encrypted, under `/uwu/v1/reports/health`.
- **Branding** in the admin portal: a name, an accent colour (checked for contrast, with its
  shades for both themes worked out as in UwUMail), logos for light and dark and a favicon — for
  the web vault, the login, Send and file-request pages and the mails. Pictures, SVG included,
  are drawn again as PNG by the server, so nothing but pixels survives
  ([docs/branding.md](docs/branding.md)).
- **Accessibility** in the web vault and the admin portal: everything by keyboard, with
  shortcuts and an overview of them (`?`), lists that move with the arrow keys, a skip link,
  messages that screen readers announce, errors tied to their fields, and a high-contrast mode
  (or the system's). Aiming at WCAG 2.2 AA; axe-core checks each main page in the browser tests
  ([docs/accessibility.md](docs/accessibility.md)).
- `#/settings/masked`, where the UwULock app links for masked addresses, answers with a friendly
  "coming soon" until they arrive.
- **Icons for items**: `/icons/<host>/icon.png`, where the Bitwarden apps and extensions ask, now
  answers with the website's icon, fetched by the server — every resolved address checked (also
  after redirects, against DNS rebinding), nothing in the local network ever asked, with time,
  size and image limits — converted to PNG and kept for 30 days. **Own icons**: uploaded, picked
  from the [selfh.st Icons](https://selfh.st/icons/) library (CC BY 4.0, mirrored by the server)
  or fetched from a device in the home network by the browser, and stored encrypted with the item.
  The admin portal switches both off and empties the cache ([docs/icons.md](docs/icons.md)).
- **Travel mode**: folders marked "hide while travelling" disappear from every device — the
  Bitwarden apps too — while it is on. On from any device; off only with the master password and
  the second step of the login, every failed try noticed
  ([docs/travel-mode.md](docs/travel-mode.md)).
- **Earlier versions of items**: every change keeps the state before, encrypted; list, show and
  bring back in the web vault. How many and how long is the admin's choice; they count toward the
  storage.
- **Reminders to renew a password**, per item after some months or on a day, with a mail that
  names no item and a *Due* section in the web vault.
- **New keys** from the web vault go through `POST /uwu/v1/accounts/rotate-keys` and take the
  extras key and the versions along; a rotation by a Bitwarden app drops the versions.
- The Send page opens Sends the way Bitwarden's newest clients do: a token from the identity
  endpoint first. Database schema 10.

**Running it and keeping it safe (Stufe 4b, first part).**

- **Security notices** for everybody, under *Settings → Security* in the web vault and by mail in
  the account's language: failed passwords and two-step codes (a burst is one notice that counts
  up), a new device, changes to the master password, address, KDF, keys, two-step login and API
  key, emergency access asked for or taken over, "log in with a device" requests, exports of the
  vault (the web vault says so, and so do Bitwarden's apps). Mails come bundled — five minutes
  after the first notice, at most one every fifteen minutes — so an attack does not flood an
  inbox; the admin chooses which kinds are mailed.
- **Server policies** in the admin portal: two-step login required from a date on (then only the
  web vault lets such an account in, to set it up; the apps say what to do), a minimum key
  derivation (weaker ones are refused; accounts below it get a notice and a *Switch now* button),
  and rules for the master password, which the web vault checks and Bitwarden's apps get with
  every login.
- **The admin portal only from some networks**: outside them `/admin` and its API answer 404.
  `uwulock-server settings set adminNetworks '[]'` is the way back in; `uwulock-server settings`
  reads and changes every setting of the portal.
- **Monitoring**: `/metrics` for Prometheus (off by default; with a token or on an address of its
  own; no user data in labels) with example alert rules in [docs/metrics.md](docs/metrics.md),
  the log to Grafana Loki from the admin portal, and `UWULOCK_LOG_FORMAT=json` with the same lines.
- **Admin notifications** by mail, ntfy, Gotify and Matrix when a backup fails or is too old, the
  certificate runs out, an update is out, many logins fail, the disk fills up, or the push relay
  or mail stop working — per channel which, with a test; tokens stay on the server
  ([docs/notifications.md](docs/notifications.md)).
- **Diagnosis** in the admin portal, on demand and after every update: certificate, clock, mail,
  push relay, backups, disk, and the reverse proxy (WebSockets, upload limit, the client's
  address, the public address), each with what to do for Caddy and nginx.
- Errors under `/uwu/v1` carry a machine-readable `code`.

**Stufe 4b, second part.**

- **Backups on another system**: an SFTP server (a NAS), an S3 bucket (Amazon, MinIO, B2,
  Hetzner, Garage, …) or a mounted folder, every night and at the press of a button,
  deduplicated (only what is new goes up), encrypted with a recovery key shown once (and again
  after the master password), kept 7 days / 4 weeks / 6 months. They hold the database, the
  attachments, Send files, file requests and the server's keys. A snapshot goes back in the admin
  portal like a local backup, or with `uwulock-server backup restore --sftp|--s3|--folder` onto a
  new machine. A failed or too old off-site backup is an alert, a warning in the diagnosis and a
  metric. The local backups stay beside them ([docs/backups.md](docs/backups.md)).
- **File requests**: a link through which somebody without an account uploads files and a message
  to you, encrypted in their browser for your account — with an expiry, a number of submissions,
  files and bytes, a password and a note. A mail when something arrives; read it, download it, or
  take it over as an item with the files attached, in the web vault. Rate-limited against abuse,
  deleted 30 days after it expired ([docs/file-requests.md](docs/file-requests.md)).
- **The emergency sheet**: a PDF for your family, made in the browser (the server never sees it),
  in German or English — the server's address and your email as text and QR codes, a box for
  the master password to write in by hand, the recovery code of two-step login, and what to do,
  with your emergency contacts and their waiting times. Under *Settings → Emergency access*.
- **Storage per account** (`storagePerUserMb`): attachments, Send files and file requests
  together; uploads past it are refused. The web vault's account data says how much is used.
- The extras key of the 0.6 API (`/uwu/v1/keys`), which UwULock's own things are encrypted
  under so that a key rotation by any client loses nothing.

**Stufe 4b, third part: UwUAuth (or any OpenID Connect provider) as the login.**

- **Log in with SSO** in the web vault, the admin portal and Bitwarden's own apps — browser
  extension, desktop, phones, CLI — the way they do it with Vaultwarden: any SSO identifier will
  do. SSO says who somebody is; the vault still opens only with the master password, which the
  server never sees. The server's own two-step login still applies. Works with UwUAuth, Keycloak,
  Authentik, Entra ID and any other provider (ID tokens signed RS256/PS256/ES256/ES384/EdDSA).
- **Accounts without an invitation** for whoever the settings let in: everybody the provider lets
  through, the members of a group, or (after pairing) UwUAuth's `user` role. They set their master
  password at the first login. An existing account is linked by its verified address, with a
  security notice (`ssoLinked`).
- **Admins through SSO**: being an admin can follow a group (or UwUAuth's `admin` role) — given
  only within the admin networks, never taken from the last admin — and the admin portal can be
  kept to SSO logins. "SSO only" leaves password logins to admins and the CLI's API key.
- **SCIM 2.0** at `/scim/v2`: the provider disables accounts (every session ends at once), deletes
  them (or only disables them, as the admin chooses), adds addresses that may sign up, and keeps
  the admin group, whose former members lose the admin right. The address never changes this way:
  it is the salt of the account's keys.
- **Pairing with UwUAuth** (0.4 and newer): a code (or the QR code's text) in the admin portal
  under *Anmeldung*, and client id, secret, addresses, roles and SCIM set themselves up. Any other
  provider is set up by hand on the same page, with a test.
- The client secret is kept encrypted, under a key in `secret.key` in the data directory (the
  off-site backups take it along). See [docs/sso.md](docs/sso.md).

- Development: `scripts/test.sh` runs the tests quietly, with only a summary and what failed.
  The tests take about half the time (the crypto and SQLite are built optimised in the dev
  profile too), and CI starts the end-to-end tests about two minutes sooner (a job per binary).

**The security review of 0.6.** What it found high or medium is fixed:

- The server can't hand out an extras key of its own: the second wrap of the extras key was an
  RSA wrap for the account's public key, which anyone who knows that key (the server too) can
  make. It is now `privateKeyWrapped`, under a key derived from the account's private key;
  clients never take an RSA wrap and check that both wraps hold the same key, and the web vault
  shows no file-request link whose details encrypt for another key. Keys made before get the new
  wrap from the next client that opens them; one left with only the old wrap counts as lost
  ([docs/uwu-api.md](docs/uwu-api.md) §3).
- While travel mode is on, two-step login stays as it is: no provider can be set up, replaced
  or switched off, the authenticator key and the recovery code are not shown, and the recovery
  code does not work at login. Before, the master password on a seized device was enough to take
  the second step away and switch travel mode off. A second step that is set up but cannot be
  used is no longer given up either; an admin resets it.
- Off-site backups: every change to their settings, and forgetting the SFTP host key, asks for
  the admin's master password, and switching encryption off drops the recovery key only when
  confirmed. A stolen admin session could send the whole database, unencrypted, to a target of
  its choosing.
- Unencrypted off-site backups only into a folder of this machine, without the server's own keys
  (token key, `secret.key`, Let's Encrypt keys), and never back into the running server from the
  portal. Existing unencrypted SFTP/S3 setups stop and raise the "backup failed" alert until
  they are saved again with encryption.
- Off-site backups over SFTP read directory listings page by page with the same ceiling as S3
  (2 million names, 128 MiB), and every run has a deadline (12 hours; listing the snapshots 10
  minutes): a hostile backup server can no longer fill the memory or hold the backup lock for
  ever.
- SVG icons are parsed as XML before they are drawn, and refused when they would grow once drawn:
  a `use` with a namespace prefix (`<s:use>`) slipped past the old text check, so a 1 KB icon
  from any website cost a second of CPU and 150 MB. At most two icons are decoded at a time.
- The cache of website icons has a ceiling (256 MiB, 100,000 files; the oldest go past it),
  forgets old entries once a day, keeps nothing while the disk is nearly full, and the admin
  portal shows the ceiling. Anybody could have filled the disk by asking for icons of made-up
  hosts.
- Masked addresses: one account can no longer spend UwUMail's limit of refused token requests
  for everybody. Codes that are no codes are not sent on, refused ones are limited per account
  and per UwUMail server, and when UwUMail asks to wait (429) its token endpoint is left alone
  for 15 minutes.
- Every answer the server reads from elsewhere has a ceiling (error texts 4 KiB, OAuth and JSON
  answers 512 KiB, UwUMail 8 MiB): notification channels, Loki, the identity provider, UwUAuth
  pairing, UwUMail and the push relay could each fill the memory with an endless answer.
- The request metrics label only the standard HTTP methods; anything else is `other`. Requests
  with invented methods made new counters that were never removed, metrics on or off.
- Uploads to a file request: one at a time per file, four per request, never over a file that
  arrived, counted per address, and the free-space check reserves the room of every upload on
  its way. Parallel uploads to the same file could fill the disk past the guard.
- The storage limit covers families: their attachments, versions and own icons count against
  each confirmed owner, and attachments of family items (the old one-step upload too) and
  moving items with files into a family are checked against it. Deleting an account also
  deletes the families nobody else is in, with their items and files. Before, family files
  counted against nobody.

## 0.4.0-beta.2

**The rest of the security review.** 0.4.0-beta.1 fixed what the review before it found high
or medium; this fixes every low finding too — [docs/security-review-2026-09.md](docs/security-review-2026-09.md)
lists them. Update with `sudo bash update.sh`. Three things behave differently:

- **Putting a backup back logs everybody out**, on every device, the admin who did it included: a
  backup carries the sessions of its day, among them ones that were taken back since.
- **Emergency contacts are never accepted by themselves.** Without mail, an invitation used to
  count as accepted at once; now it waits in the contact's settings (Emergency access → Accept),
  and inviting answers the same whether the address has an account or not.
- **Users who may invite** get the signup link only when the server cannot mail it.

Also:

- Logging in: a login by another device's approval always mails; a request to unlock does not
  log in; a login takes the same time whether the account came from Vaultwarden or not; refresh
  tokens from Vaultwarden are replaced at their first use, signed or not — and afterwards, the
  old Vaultwarden data is best destroyed ([docs/deployment.md](docs/deployment.md)).
- Files and Sends: uploads give up after a minute without a byte and run four at a time per
  account; two uploads of the same file cannot write into each other; a Send limited to one
  opening opens once in the newest apps too; a Send's download link stops with the Send.
- Live updates end with their session (a new password, a logout), checked every 15 seconds.
- The password check keeps what Have I Been Pwned answered per account, and says what the
  server sees.
- New keys in the web vault refuse a public key on the server that does not belong to the
  account; an emergency takeover gives the new password today's key derivation when the old one
  was weaker; key rotation takes organisation account recovery along.
- The import checks every id before it becomes a path, and mails whoever lost their only second
  step (Duo, YubiKey OTP, U2F).
- The WebAuthn pages may be framed only by Bitwarden's browser extensions.
- [docs/deployment.md](docs/deployment.md) shows how to keep the clients' access tokens out of
  Caddy's and nginx's access logs.

The UwULock app stays at [0.2.0-beta.3](https://github.com/MinifyX/UwULock-Client/releases/tag/v0.2.0-beta.3).

## 0.4.0-beta.1

**Everything Vaultwarden does for one person, and the way over from it.** Attachments, Sends,
emergency access, security keys and passkeys, logging in with another device, the API key and a
password check; `uwulock-server import-vaultwarden` brings a whole Vaultwarden over as it is;
live updates for the apps and the web vault; the web vault on a phone; and a grown-up admin
portal. Update with `sudo bash update.sh`. The version jumps from 0.1 to 0.4 because stages 2,
3 and 4 of [the plan](docs/plan.md) come at once; 1.0 comes after testing on real devices.

Behind a reverse proxy, check two things: the proxy has to pass on WebSockets for
`/notifications/hub` (the nginx example in [docs/deployment.md](docs/deployment.md) does), and
it has to let files through up to the size set in the admin portal (500 MB by default:
`client_max_body_size 525M;` in nginx). Attachments and the files of Sends are kept next to the
database, in `/data/attachments` and `/data/sends` — copy them along with the backups.

- **Attachments** on items, up to 500 MB each (changeable in the admin portal), in the web
  vault, the official apps and the `bw` CLI; they come along when the keys are renewed.
- **Sends**: a text or a file behind a link, with a password, an expiry, a deletion date and a
  maximum number of openings; a page of their own in the web vault for whoever gets the link.
- **Emergency access**: trusted contacts who may see or take over the vault after a waiting
  time, with mails at every step and the fingerprint phrase to confirm them.
- **Security keys and passkeys**: WebAuthn as a second step (with the connector pages the
  browser extension and the apps use), logging in with a passkey in the web vault, and with PRF
  unlocking it too — verified by the server itself, without OpenSSL.
- **Log in with another device**, with the fingerprint phrase on both; **the API key** for
  `bw login --apikey`; a **password check** in the web vault: weak, reused, without https, and in
  breaches — asked through this server from Have I Been Pwned, only the first five characters of
  a hash leave it (switchable in the admin portal).
- **Moving in from Vaultwarden**: `uwulock-server import-vaultwarden <its data directory>`
  (`--dry-run` first) brings accounts, devices — which stay logged in —, two-step login,
  folders, items, attachments, Sends, emergency access and organisations over, in one go and
  after a backup. The old passwords work and are hashed anew at the next login. Organisations
  can be used as they are; managing them comes later. Tested in CI against a real
  Vaultwarden 1.37.3, filled by Bitwarden's CLI. See [docs/deployment.md](docs/deployment.md).
- **Live updates**: Bitwarden's notification hub (SignalR over a WebSocket), so a change on one
  device shows on the others at once; the web vault listens too. **Push for the phone apps**
  through Bitwarden's relay, with an installation id and key from bitwarden.com/host, set up and
  tested in the admin portal.
- **The web vault on a phone**: one layer at a time — list, item, menu — with a bar at the
  bottom. The admin portal fits a phone too.
- **The admin portal** gets the push relay, the largest file, the password check, invitation
  rules (users may invite, up to a number each, never as admins; in the vault under Settings →
  Invite), numbers over time as charts, files per account, and **restoring a backup while the
  server runs** — with the master password, and a backup of how things were first, so it can be
  undone the same way.
- `UWULOCK_LOGIN_ATTEMPTS` for many people behind one address.

- **The UwULock app** fits from [0.2.0-beta.3](https://github.com/MinifyX/UwULock-Client/releases/tag/v0.2.0-beta.3)
  on: items with attachments, Sends and organisations come through its sync and stay intact.

**A security review** of everything new came before the release; what it found high or medium
is fixed, the rest is listed in [docs/security-review-2026-09.md](docs/security-review-2026-09.md):

- Uploads cannot fill the memory with an oversized part, and are refused when they would leave
  the disk too full for the database.
- Rate limits for a Send's password, the master password and the second step of a login count
  tries sent all at once too.
- "Log in with a device" says nothing about which addresses have an account; the anonymous
  live-update connections need a waiting request, take only small messages, count IPv6 by /64
  and have a ceiling.
- An emergency takeover takes the grantor out of organisations they do not own, so the contact
  does not get what others shared with them.
- `import-vaultwarden` run a second time stops before touching anything, and never writes over
  or removes the files of the first run.
- New keys in the web vault show each emergency contact's fingerprint phrase first.

## 0.1.0-beta.2

**A security release.** A review of the whole server, the web vault and the scripts, and what
it found, fixed. Update with `sudo bash update.sh`. One setting changes: `UWULOCK_TLS` has to be
in `.env` now (`install.sh` has always written it); without it, Compose refuses to start rather
than serve plain HTTP on port 443.

- **Imported passkeys are encrypted.** A Bitwarden JSON export carries passkeys in plain text,
  and an import passed them on as they were, so their private keys reached the server
  unencrypted. They are encrypted in the browser now, like everything else in an item; an export
  decrypts them again, and a new user key encrypts them anew. Whoever imported passkeys before:
  delete those items and import the file again.
- **Rate limits that hold.** Behind a proxy the address it added counts, not the one a client
  claims in `X-Forwarded-For`. An IPv6 address counts by its /64. The second step of a login and
  a wrong master password in a logged-in session are limited per account too, and every mail
  somebody can make the server send (a hint, an invitation again, a code) per address.
- **Connections that send nothing are closed**: ten seconds for the TLS handshake, and a
  connection on which nothing moves for 90 seconds is closed, so idle sockets cannot use up the
  server's file descriptors.
- **Less for an attacker to learn or leave behind**: the password hint answers the same for every
  address; a login's username is at most 254 characters, and no log line can be longer than
  4 KiB or make a second, made-up one; SMTP errors go to the log, not to whoever asked; the
  Argon2 hashes run a few at a time, so many logins at once cannot take all memory.
- **The mail password stays with its server.** Pointing the settings at another mail server asks
  for the password again, and a password is never sent without TLS to a server that is not on
  this machine or its network.
- **The web vault** closes itself, keys and all, when the server ends its session (logged out
  everywhere, a new password, an admin); the admin portal locks the vault right after login; the
  clipboard is cleared once the page may do it, and on lock; an item behind the master password
  prompt cannot be saved over before the prompt; a CSV export does not start a cell with a
  spreadsheet formula; the master password is wiped from the WebAssembly memory; the notes field
  sends nothing to a spell checker; invitation tokens stay out of request URLs.
- **A backup takes the master password.** It is the whole database, the server's own keys among
  them, so downloading one in the admin portal asks for the admin's master password too.
- **Headers**: `Strict-Transport-Security` whenever the server is reached over https, and
  `Cross-Origin-Opener-Policy` for the web vault.
- **install.sh and update.sh**: the install directory and everything above it have to be
  root's, so nobody else can swap what runs as root; a version is checked before it goes into
  a download address; `.env` is made readable by root only.
- **Releases** are built without caches from earlier CI runs, no CI job keeps its git
  credentials, and secrets stay out of the Docker build context.
- A session in memory no longer outlives a new security stamp by a few seconds, and a key
  rotation keeps every item in one of the account's own folders.

## 0.1.0-beta.1

**A vault for one person, with a web vault and an admin portal.** The official Bitwarden apps,
browser extension and CLI log in, sync and save; UwULock has a web vault of its own and an admin
portal. A beta: the browser extension and the phone apps want trying by hand before 0.1.0 (the
checklist is in [docs/plan.md](docs/plan.md)). Organisations, attachments, sends and real-time
sync come later; the apps sync when they are opened.

- **Accounts by invitation.** `install.sh --admin you@example.com` invites the first admin; the
  admin portal invites everybody else, by mail or as a link to pass on. The link opens the web
  vault, where the keys are made — the server gets the master password's hash and the keys
  wrapped under it, as with Bitwarden.
- **Bitwarden's API for one person**: login with refresh tokens and devices, sync, items and
  folders, the trash, the archive, several items at once, import, changing the master password,
  the key derivation or the address, new keys, logging out everywhere, deleting the account.
  The server hashes what the clients send once more, with Argon2id; access tokens are signed
  with Ed25519.
- **Two-step login**: an authenticator app, codes by mail, the recovery code, and "remember
  this device" for 30 days.
- **The web vault** at `/`, in the UwULock app's look, German and English: the vault in three
  panes, the generator, import and export in Bitwarden's JSON and CSV, every account setting,
  two-step login with a QR code, devices. Its crypto is UwULock's own, as WebAssembly.
- **The admin portal** at `/admin`: users (disable, log out, reset two-step login, make admin,
  delete), invitations, mail with a test mail, the invitations' lifetime and other settings,
  the event log, the server's log, backups to write and download, and the update notice.
- **Mail**: SMTP over TLS or STARTTLS, set up in the portal or in `.env` for the first start;
  every mail in German or English, as its reader chose.
- **Hardening**: rate limits on logins and everything anybody can ask without one, a timeout
  for a request's head, CORS only for the Bitwarden desktop app, a strict content security
  policy for the web vault.
- **Tested with the real clients**: CI runs UwULock's own client, Bitwarden's `bw` CLI and the
  web vault in a browser against the release binary.
- On the command line: `uwulock-server invite`, `admin` and `reset-two-factor`.

## 0.0.2

**A reverse proxy in a container.** Behind a proxy that runs as a Docker container on the same
machine, the server listened on `127.0.0.1` — which inside the proxy's container is the proxy
itself, so it answered 502.

- **`install.sh --proxy-network NET`** puts the server into the proxy's Docker network instead of
  onto a port of the machine; the proxy reaches it at `http://uwulock:8443`. Asked for, too, when
  you choose the proxy without flags. A port on the machine that something else has already, like
  8443, no longer matters then.
- **`--proxy-ip ADDRESS`** gives it a fixed address in that network, which ipvlan and macvlan
  networks need: the proxy passes on to `http://ADDRESS:8443`.
- The address the proxy has to pass on to, and the lines for Caddy, are printed at the end.
- How it looks by hand, as a `compose.override.yaml`: [docs/deployment.md](docs/deployment.md#a-proxy-in-a-container).

## 0.0.1

**The foundation.** UwULock Server runs, updates itself safely and backs itself up — but it does
not keep a vault yet. Accounts, sync and everything the Bitwarden apps need come in 0.1; the
whole way is in [docs/plan.md](docs/plan.md).

- **One container, set up by `install.sh`.** It asks one thing: whether the server gets its own
  certificate from Let's Encrypt, or runs behind a reverse proxy you already have. The official
  Bitwarden apps need a certificate the system trusts, so there is no self-made one.
- **Let's Encrypt built in**, over port 443 alone (TLS-ALPN-01), renewed by the server itself.
  Or your own certificate files, read again when they change.
- **`update.sh`** with the channels latest, beta and edge: a backup first, then the new version,
  and the old one back if the new one does not come up.
- **Backups** every night and before every update, seven kept, never at the cost of a full disk;
  `uwulock-server restore` puts one back.
- **`/alive`, `/api/alive` and `/api/now`** like Bitwarden's server, and `/healthz` for the
  container's health check.
- **Measured against Vaultwarden** from the start: `uwulock-bench` and a weekly run in CI. The
  first numbers are in [docs/performance.md](docs/performance.md).
