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

> **Status: 0.4, everything Vaultwarden does for one person — beta.** Accounts by invitation,
> the vault with attachments, Sends, emergency access, security keys and passkeys, live updates
> and push, and the official Bitwarden apps, browser extension and CLI on top; a web vault of its
> own that works on a phone, and an admin portal. `uwulock-server import-vaultwarden` moves a
> Vaultwarden over, devices and all. Organisations come along from Vaultwarden and work as they
> are; families are made and managed here from the next release on, companies' organisations
> after that. The [UwULock app](https://github.com/MinifyX/UwULock-Client)
> fits from 0.2.0-beta.3 on. The [plan](docs/plan.md) has every step (in German).

## What is in 0.4

- **The official Bitwarden clients work**: browser extension, mobile apps, desktop app and
  `bw` CLI log in (with two-step login, a security key, another device or the API key), sync,
  and save, with live updates over Bitwarden's notification hub and push to the phone apps
  through Bitwarden's relay — tested in CI with Bitwarden's own CLI.
- **Everything for one person**: attachments (500 MB each by default), Sends with a page of
  their own for whoever gets the link, emergency access with a waiting time, security keys and
  passkeys (with PRF, a passkey unlocks the web vault too), logging in with another device, and
  a password check that asks Have I Been Pwned through this server.
- **Moving in from Vaultwarden**: `uwulock-server import-vaultwarden <its data directory>`
  brings accounts, devices (which stay logged in), two-step login, items, attachments, Sends,
  emergency access and organisations over in one go. Tested in CI against a real Vaultwarden.
- **UwULock's own web vault** at `/`, in the look of the UwULock app: the vault in three panes
  (one at a time on a phone), several items at once, the generator, import and export (Bitwarden
  JSON and CSV), Sends, file requests, the password check, the emergency sheet, and every account
  setting. The crypto runs in the
  browser, as WebAssembly: the same code the UwULock app uses.
- **An admin portal** at `/admin`: users with their files, invitations and who may send them,
  mail, push and other settings, numbers over time, the event log, the server's log, backups —
  here and on another system, put back while the server runs — and the update notice. Admins are ordinary accounts with the
  admin right.
- **Registration by invitation**: by mail, or as a link to pass on by hand; users may
  invite a few people too, if the admin allows it.

Coming with the next release (on `main` already):

- **Log in with UwUAuth or any OpenID Connect provider**, in the web vault, the admin portal and
  the official Bitwarden apps ("Log in with SSO", any identifier); the master password still
  opens the vault. People in a group sign up without an invitation, admins can follow a group,
  SCIM disables and removes accounts, and pairing with UwUAuth takes one code
  ([docs/sso.md](docs/sso.md)).
- **Security notices** for everybody, in the web vault and bundled by mail; **server policies**
  (two-step login required, a minimum KDF, master password rules); the admin portal only from
  some networks.
- **Running it**: `/metrics` for Prometheus, the log to Loki, admin alerts by mail, ntfy, Gotify
  and Matrix, a diagnosis of the setup, and backups on another system (SFTP, S3 or a folder).
- **File requests** (people without an account send you files, encrypted in their browser) and
  **the emergency sheet** as a PDF for your family.
- **Icons** for items — the website's, fetched by the server and never by your browser, or your
  own, encrypted, also from the selfh.st library ([docs/icons.md](docs/icons.md)); **travel
  mode**, **earlier versions** of items and **reminders** to renew a password
  ([docs/travel-mode.md](docs/travel-mode.md)).
- **Import from KeePass, 1Password, Chrome, Firefox, Apple Passwords, Proton Pass and LastPass**,
  read in the browser with a preview ([docs/import.md](docs/import.md)); **share an item as a
  Send**, **Sends only for given addresses** with a code by mail, and the report **"2FA possible,
  not set up"** ([docs/sharing.md](docs/sharing.md)); the server's own **branding**
  ([docs/branding.md](docs/branding.md)).
- **Families**: share items with a few people in collections, read or write per member, like
  Bitwarden's Families and seen by the official apps too; members are confirmed with a
  fingerprint phrase ([docs/families.md](docs/families.md)).

## What it will and won't do

- **It never sees your passwords.** Like Bitwarden's server, it stores what your clients
  encrypted, and your master password never reaches it — only a hash of it, at login.
- **The official Bitwarden clients keep working.** That is the contract. UwULock's own features
  live under `/uwu/v1`, where Bitwarden's clients never look.
- **No favicons from third parties, no telemetry.** The only connections it opens on its own are
  Let's Encrypt (if you use it), a daily look at GitHub for a newer release, which
  `UWULOCK_UPDATE_CHECK=off` stops, and — unless the admin switches them off — websites' icons
  and the icon library's index, fetched for your apps so they never ask anybody but this server,
  and 2FA Directory's list once somebody opens the password check.
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
# the proxy runs as a container here: the server joins its Docker network
sudo bash install.sh --behind-proxy https://vault.example.com --proxy-network proxy --yes
```

Everybody else you invite in the admin portal. Mail (for invitations and codes) is set up there
too, or in `.env` before the first start.

[docs/deployment.md](docs/deployment.md) has the rest: Caddy and nginx in front, your own
certificate, backups, every setting.

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
| `crates/uwulock-notify` | Live updates: Bitwarden's notification hub, and push through its relay     |
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
- [Backups](docs/backups.md) — on another system: SFTP, S3 or a folder, and back onto a new machine
- [File requests](docs/file-requests.md) — links through which people without an account send you files
- [Icons](docs/icons.md) — website icons fetched by the server, own icons and the icon library
- [Travel mode, versions and reminders](docs/travel-mode.md) — hiding folders at the border, earlier versions of items, renewing passwords
- [Import](docs/import.md) — moving in from KeePass, 1Password, browsers, Proton Pass and LastPass
- [Sharing](docs/sharing.md) — an item as a Send, Sends only for given addresses, the 2FA report
- [Branding](docs/branding.md) — the server's own name, colour, logos and favicon
- [Accessibility](docs/accessibility.md) — keyboard shortcuts, high contrast, screen readers, what axe checks
- [Families](docs/families.md) — sharing with a few people: invitations, the fingerprint phrase, collections, the admin's settings
- [SSO](docs/sso.md) — logging in through UwUAuth or another OpenID Connect provider, SCIM, pairing
- [Metrics](docs/metrics.md) and [notifications](docs/notifications.md) — Prometheus, Loki, and alerts to the admins
- [Performance](docs/performance.md) — how it is measured, and the numbers
- [Security review, September 2026](docs/security-review-2026-09.md) — what was found for 0.4,
  and how it was fixed
- [Changelog](CHANGELOG.md)
- [Security](SECURITY.md) — how to report a vulnerability
