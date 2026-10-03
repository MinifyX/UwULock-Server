<p align="center">
  <img src="brand/uwulock-app-icon.svg" width="112" alt="UwULock logo" />
</p>

<h1 align="center">UwULock Server</h1>

<p align="center">
  The password server I build for myself, because the others annoyed me. (◕‿◕✿)<br/>
  Bitwarden-compatible · made for UwULock · Rust, one container, one SQLite file
</p>

---

## Why this exists

My passwords live in a Vaultwarden, and [UwULock](https://github.com/MinifyX/UwULock-Client) is
the window I open them in. UwULock Server is the other half: a server of its own, speaking the
same Bitwarden API as Vaultwarden — so the official Bitwarden browser extension, apps and CLI keep
working — but faster, made for UwULock, and with room for what only UwULock will use: a vault
UwUSSH, UwURDP and UwUMail can share, live updates without polling, and later a company with its
teams and SSO.

- **Just for fun.** No company, no team, no schedule, no promises. I work on it when I have time
  and feel like it.
- **Written with AI.** Almost all of the code is written with Claude, because I'm honestly not a
  great programmer. Not your thing? No hard feelings.
- **Use it, fork it, do what you want with it.** The license (AGPL-3.0) only asks one thing: if
  you pass on a changed version, or run one for others, its source stays open too.
- **No support.** Issues and pull requests are okay, but I might answer late or not at all.

> **Status: 0.8, everything Vaultwarden does for one person and a family, and more — beta.**
> Accounts by invitation or through SSO, the vault with attachments, Sends, emergency access,
> security keys and passkeys, live updates, families, and the official Bitwarden apps, browser
> extension and CLI on top; a web vault of its own that works on a phone, and an admin portal.
> `uwulock-server import-vaultwarden` moves a Vaultwarden over, devices and all. Organisations
> come along from Vaultwarden and work as they are; companies' organisations (Stufe 5) are
> planned, not built. The [UwULock app](https://github.com/MinifyX/UwULock-Client) fits from
> 0.2.0-beta.3 on, and gets the most out of it from 0.5.0-beta.1 on. The [plan](docs/plan.md) has
> every step (in German).

## What is in 0.8

- **The official Bitwarden clients work**: browser extension, mobile apps, desktop app and
  `bw` CLI log in (with two-step login, a security key, another device, the API key or SSO),
  sync, and save, with live updates over Bitwarden's notification hub — tested in CI with
  Bitwarden's own CLI. (Push to Bitwarden's phone apps through Bitwarden's relay was removed in
  0.7.0-beta.3, a plan change: it sent account and device ids to Bitwarden with every change.
  Bitwarden's phone apps sync when they are opened.)
- **Everything for one person**: attachments (500 MB each by default), Sends with a page of
  their own for whoever gets the link, emergency access with a waiting time, security keys and
  passkeys (with PRF, a passkey unlocks the web vault too), logging in with another device, and
  a password check that asks Have I Been Pwned and XposedOrNot through this server.
- **Moving in from Vaultwarden**: `uwulock-server import-vaultwarden <its data directory>`
  brings accounts, devices (which stay logged in), two-step login, items, attachments, Sends,
  emergency access and organisations over in one go. Tested in CI against a real Vaultwarden.
  **Import from KeePass, 1Password, Chrome, Firefox, Apple Passwords, Proton Pass and LastPass**,
  read in the browser with a preview ([docs/import.md](docs/import.md)).
- **UwULock's own web vault** at `/`, in the look of the UwULock app: the vault in three panes
  (one at a time on a phone), several items at once, the generator, import and export (Bitwarden
  JSON and CSV), Sends, file requests, the password check, the emergency sheet, Wi-Fi networks
  with a QR code ([docs/wifi.md](docs/wifi.md)), UwUSSH's and UwURDP's hosts and connections, and
  every account setting. The crypto runs in the browser, as WebAssembly: the same code the
  UwULock app uses.
- **The password check** finds weak, reused and breached passwords (Have I Been Pwned and
  XposedOrNot, by the first characters of a hash only), sites breached after a password's last
  change and sites that offer two-step login you don't use, and goes through them one card at a
  time: open the site's change-password page, save a new password, put it off or ignore it.
- **An admin portal** at `/admin`: users with their files, invitations and who may send them,
  mail and other settings, numbers over time, the event log, failed logins with their origin and
  blocked addresses ([docs/failed-logins.md](docs/failed-logins.md)), the server's log, backups —
  here and on another system, put back while the server runs — and the update notice. Admins are
  ordinary accounts with the admin right. Every extra below is a **feature switch** there: a new
  server starts with only the vault and icons, and what is off is gone from sight but not deleted
  ([docs/features.md](docs/features.md)).
- **Registration by invitation**: by mail, or as a link to pass on by hand; users may
  invite a few people too, if the admin allows it.
- **Log in with UwUAuth or any OpenID Connect provider**, in the web vault, the admin portal and
  the official Bitwarden apps ("Log in with SSO", any identifier); the master password still
  opens the vault. People in a group sign up without an invitation, admins can follow a group,
  SCIM disables and removes accounts, and pairing with UwUAuth takes one code
  ([docs/sso.md](docs/sso.md)).
- **Security notices** for everybody, in the web vault and bundled by mail; **server policies**
  (two-step login required, a minimum KDF, master password rules); the admin portal only from
  some networks.
- **Running it**: `/metrics` for Prometheus, the log as JSON lines (`UWULOCK_LOG_FORMAT=json`)
  or straight to Loki, admin alerts by mail, ntfy, Gotify and Matrix, a diagnosis of the setup,
  and backups on another system (SFTP, S3 or a folder) that put a server back on a new machine
  ([docs/metrics.md](docs/metrics.md), [docs/backups.md](docs/backups.md)).
- **File requests** (people without an account send you files, encrypted in their browser) and
  **the emergency sheet** as a PDF for your family.
- **Icons** for items — the website's, fetched by the server and never by your browser, or your
  own, encrypted, also from the selfh.st library ([docs/icons.md](docs/icons.md)); **travel
  mode**, **earlier versions** of items and **reminders** to renew a password
  ([docs/travel-mode.md](docs/travel-mode.md)).
- **Share an item as a Send**, **Sends only for given addresses** with a code by mail, and the
  report **"2FA possible, not set up"** ([docs/sharing.md](docs/sharing.md)); the server's own
  **branding** ([docs/branding.md](docs/branding.md)).
- **Families**: share items with a few people in collections, read or write per member, like
  Bitwarden's Families and seen by the official apps too; members are confirmed with a
  fingerprint phrase ([docs/families.md](docs/families.md)).
- **For UwULock's own apps**: a delta sync that sends only what changed (a millisecond for a
  5,000-item vault) and a lean realtime channel instead of polling ([docs/sync.md](docs/sync.md));
  the **suite vault**, where UwUSSH and UwURDP keep their hosts and connections end-to-end
  encrypted instead of in UwUSync ([docs/suite.md](docs/suite.md)).
- **Send domains**: short Send and file-request links on names of their own, like
  `send.example.com`, with their own certificate and look ([docs/send-domains.md](docs/send-domains.md)).
- **Masked addresses** from UwUMail, a mail address of its own for every website — in the web
  vault and in the Bitwarden apps' generator ([docs/masked-addresses.md](docs/masked-addresses.md)).

New in 0.8:

- **The password check finishes.** All accounts' XposedOrNot questions wait in one queue on the
  server, one a second; a 429 pauses it as long as XposedOrNot's `Retry-After` says and the prefix
  is asked again. Have I Been Pwned's results show at once, with the progress per source
  ("XposedOrNot: 120 von 363"), and "a source did not answer" only comes for a real outage.
- **Generator minimums**: at least so many capitals, small letters, digits and symbols; the
  length grows to fit them and says so.
- **One-time codes**: in a code's last 10 seconds the next one shows below it, with its own copy
  button.
- **Items**: only the first website on an item's page, the others behind "+2 more websites"; the
  favourite is a star in the editor; the reminder to renew is a switch in the editor and shows on
  the item only while it is on.
- **Passkeys** in the web vault: an item's page lists its passkeys — site, user, created — and
  deletes one; *Duplicate* keeps them in the copy.
- **Entry Sends**: an item shared as a Send shows on the Send page as an entry, with copy
  buttons, secrets behind the eye, each website with its address and, if you tick them, live
  one-time codes — never the key on the page, but the key travels in the Send, so whoever has the
  link can read it out, and the web vault asks before it goes along. The Bitwarden apps still see
  readable text ([docs/sharing.md](docs/sharing.md)).
- **A new look**: a font of your choice per device (UwU Sans, the UwU apps' font, by default;
  Manrope, Rubik, DM Sans or the system's), checkboxes and switches like UwUMail's, and more Nyu —
  empty lists, loading, unlocking, the password check, toasts — following *Appearance →
  Animations* and the system's wish for less motion.
- **Security review** of the server, the web vault and the admin portal, with every finding
  fixed or explained, and a re-check of the fixes ([docs/security-review-0.8.md](docs/security-review-0.8.md)):
  stricter login limits per address, network and account, the master password for the admin
  portal's SSO and user actions, API keys that end with a password change, forwarding headers
  only from `UWULOCK_TRUSTED_PROXIES`, and caps on connections, items and bulk requests.

## What it will and won't do

- **It never sees your passwords.** Like Bitwarden's server, it stores what your clients
  encrypted, and your master password never reaches it — only a hash of it, at login.
- **The official Bitwarden clients keep working.** That is the contract. UwULock's own features
  live under `/uwu/v1`, where Bitwarden's clients never look.
- **No favicons from third parties, no telemetry.** The only connections it opens on its own are
  Let's Encrypt (if you use it), a daily look at GitHub for a newer release, which
  `UWULOCK_UPDATE_CHECK=off` stops, and — unless the admin switches them off — websites' icons
  and the icon library's index, fetched for your apps so they never ask anybody but this server;
  for the password check Have I Been Pwned's and XposedOrNot's password ranges (a short prefix
  of a hash, never with an account), their lists of breached sites, 2FA Directory's
  list and sites' change-password pages; and DB-IP's GeoIP databases once a month for the failed
  logins page.
- **Faster than Vaultwarden, measured.** [docs/performance.md](docs/performance.md) has the
  numbers, and CI runs both side by side every week.

## Install

On a Linux machine — a VPS, a NAS, a box at home — with a name pointing to it and port 443
reaching it, or behind a reverse proxy you already run:

```bash
curl -fsSLO https://github.com/MinifyX/UwULock-Server/releases/latest/download/install.sh
sudo bash install.sh
```

It installs Docker when it is missing, asks whether the server gets its own certificate from
Let's Encrypt or sits behind your proxy, sets up `/opt/uwulock`, starts it — and invites you as
the first admin: the link to register with is shown at the end. Without questions:

```bash
sudo bash install.sh --domain vault.example.com --admin you@example.com --yes
sudo bash install.sh --behind-proxy https://vault.example.com --admin you@example.com --yes
# the proxy runs as a container here: the server joins its Docker network,
# and believes forwarding headers only from the proxy's address
sudo bash install.sh --behind-proxy https://vault.example.com --proxy-network proxy \
  --trusted-proxy 192.0.2.2 --yes
```

Everybody else you invite in the admin portal. Mail (for invitations and codes) is set up there
too, or in `.env` before the first start.

[docs/deployment.md](docs/deployment.md) has the rest: Caddy and nginx in front, your own
certificate, backups, logs, every setting. Settings new in 0.8, all in `.env`:

| Variable | Default | What it does |
| --- | --- | --- |
| `UWULOCK_TRUSTED_PROXIES` | — (every peer) | With `UWULOCK_TRUST_FORWARDED=on`: believe `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Host` only from these addresses or CIDR networks, comma separated. Set it when other containers share the proxy's network. |
| `UWULOCK_CLIENT_IP_HEADER` | `x-forwarded-for` | `x-real-ip` for a proxy that sets only `X-Real-IP`. Leave it alone behind Caddy. |
| `UWULOCK_CONNECTIONS_PER_NETWORK` | `256` | With TLS of its own: the most connections from one IPv4 address or IPv6 /64; `0` for no cap but the total of 8 192. Private peers (Docker's gateway) share 7/8 of the total. |

`UWULOCK_LOG_FORMAT=json` (one JSON object a line, for Grafana Alloy, Promtail or Vector) has been
there before; *Admin portal → System & diagnosis → Monitoring* sends the same lines straight to
Loki, and switches `/metrics` on.

## Update

```bash
cd /opt/uwulock && sudo bash update.sh
```

A backup first, then the new image, and the old one back if the new one does not come up.
`UWULOCK_VERSION` in `.env` says what the machine follows: `latest`, `beta`, `edge` or one exact
version.

## Project layout

| Path                    | What lives there                                                           |
| ----------------------- | -------------------------------------------------------------------------- |
| `crates/uwulock-store`  | The database: SQLite now, behind methods PostgreSQL can implement later     |
| `crates/uwulock-backup` | Backups on another system: SFTP, S3 or a folder, deduplicated and encrypted |
| `crates/uwulock-api`    | HTTP: Bitwarden's API, UwULock's own and the admin API under `/uwu/v1`      |
| `crates/uwulock-mail`   | SMTP, and what the mails say, in German and English                        |
| `crates/uwulock-notify` | Live updates: Bitwarden's notification hub and UwULock's realtime channel  |
| `crates/uwulock-web`    | The web vault's files, embedded into the binary                             |
| `crates/uwulock-server` | The program: settings, TLS and Let's Encrypt, commands, backups, updates   |
| `crates/uwulock-bench`  | The same load against any Bitwarden-compatible server, for comparisons     |
| `crates/uwulock-e2e`    | UwULock's own client against the real server                               |
| `web/`                  | The web vault and the admin portal (React), and `web/wasm`, their crypto    |
| `scripts/e2e/`          | A browser and Bitwarden's CLI against a running server                     |
| `docker/`, `compose.yaml`, `install.sh`, `update.sh` | The container and how it gets onto a machine  |
| `docs/`                 | Plan, deployment, performance, security reviews                            |

## Development

Requirements: Rust stable. For the web vault Node 24 with pnpm, the `wasm32-unknown-unknown`
target and `wasm-bindgen` in the version `web/wasm/Cargo.toml` pins. Docker for the container
and the scripts.

```bash
cargo run -p uwulock-server          # plain HTTP on 0.0.0.0:8443, data in ./data
cargo run -p uwulock-server -- invite --admin you@example.com
scripts/test.sh                      # every Rust test, quietly: one line, and only what failed
scripts/test.sh --all                # and rustfmt, clippy and all of the web vault's checks
scripts/test.sh -p uwulock-api sends # anything else goes to `cargo test` as it is
cargo test --workspace               # the same tests with cargo's own output

cd web && pnpm install && pnpm build # the web vault, into web/dist; then build the server again
pnpm dev                             # the web vault on :5173, talking to the server on :8443
```

The web vault needs a secure context for its crypto: `localhost`, or https.

`scripts/test.sh` is the way to run the tests while working, for people and for coding agents
alike: it prints one line per step and the output of a failure, and keeps the full output in
`target/test-logs/`. The tests stay fast, and should: unit tests next to the code, calling the
API in process without a socket (`crates/uwulock-api/src/test_support.rs`); one integration test
binary per crate (`tests/integration/main.rs`, a new file there is a module of it); a temporary
directory per test and ports on `127.0.0.1:0`; local fakes for anything outside, and
`#[ignore = "…"]` for what needs the internet; cheap hashing; waiting for the event, never a fixed
sleep. The dev profile builds the crypto and SQLite optimised, so tests that log in do not wait
for unoptimised code.

The Let's Encrypt test needs Pebble, Let's Encrypt's test CA; CI runs it, and the comment on
`a_certificate_from_an_acme_ca` in `crates/uwulock-server/tests/integration/serve.rs` says how
to run it locally.

Releasing: set the version in `Cargo.toml` (and `web/package.json`), add its section to
`CHANGELOG.md`, commit, tag `v<version>` and push both. CI checks that they match, tests
everything — the server, the web vault, a browser and Bitwarden's CLI against the release
binary, install and update — builds and scans the image, pushes it to GHCR and creates the
GitHub release with the scripts.

## Documentation

- [Plan](docs/plan.md) — where this is going, stage by stage (German)
- [Deployment](docs/deployment.md) — Let's Encrypt, reverse proxies, backups, settings
- [Feature switches](docs/features.md) — which extras this server offers, and what "off" means
- [Backups](docs/backups.md) — on another system: SFTP, S3 or a folder, and back onto a new machine
- [File requests](docs/file-requests.md) — links through which people without an account send you files
- [Icons](docs/icons.md) — website icons fetched by the server, own icons and the icon library
- [Travel mode, versions and reminders](docs/travel-mode.md) — hiding folders at the border, earlier versions of items, renewing passwords
- [Import](docs/import.md) — moving in from KeePass, 1Password, browsers, Proton Pass and LastPass
- [Wi-Fi networks](docs/wifi.md) — networks as items, with a QR code, readable by Bitwarden's apps as notes
- [Failed logins](docs/failed-logins.md) — refused logins with their origin, and blocking addresses
- [Sharing](docs/sharing.md) — an item as a Send (an entry Send), Sends only for given addresses, the 2FA report
- [Branding](docs/branding.md) — the server's own name, colour, logos and favicon
- [Delta sync and realtime](docs/sync.md) — what UwULock's own apps sync, and how they hear of changes
- [Suite vault](docs/suite.md) — UwUSSH and UwURDP syncing through this server, and moving over from UwUSync
- [Send domains](docs/send-domains.md) — names of their own for Sends and file requests, their certificates and look
- [Masked addresses](docs/masked-addresses.md) — addresses from UwUMail per website, also for the Bitwarden apps
- [Accessibility](docs/accessibility.md) — keyboard shortcuts, high contrast, screen readers, what axe checks
- [Families](docs/families.md) — sharing with a few people: invitations, the fingerprint phrase, collections, the admin's settings
- [SSO](docs/sso.md) — logging in through UwUAuth or another OpenID Connect provider, SCIM, pairing
- [Metrics](docs/metrics.md) and [notifications](docs/notifications.md) — Prometheus, Loki, and alerts to the admins
- [Performance](docs/performance.md) — how it is measured, and the numbers
- [Security review, September 2026](docs/security-review-2026-09.md) — what was found for 0.4,
  and how it was fixed
- [Security review of 0.6](docs/security-review-0.6.md) — what was found for 0.6, what is fixed,
  and the low findings that stay open
- [Security review of 0.7](docs/security-review-0.7.md) — the password check's sources, failed
  logins, Wi-Fi, and the SSH/RDP sections
- [Security review of 0.8](docs/security-review-0.8.md) — logins, proxies, the admin portal,
  entry Sends and passkeys, and the re-check of the fixes; the apps' side is in UwULock's
  [review of 0.5](https://github.com/MinifyX/UwULock-Client/blob/main/docs/security-review-0.5.md)
- [Changelog](CHANGELOG.md)
- [Security](SECURITY.md) — how to report a vulnerability
