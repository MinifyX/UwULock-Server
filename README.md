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

> **Status: 0.0.1, the foundation.** It installs, serves over Let's Encrypt or behind a proxy,
> updates itself safely and backs itself up — but it does not keep a vault yet. Accounts and
> sync, the part the Bitwarden apps need, come in 0.1. Keep your Vaultwarden until 0.2, which
> brings it over, devices and all. The [plan](docs/plan.md) has every step (in German).

## What it will and won't do

- **It never sees your passwords.** Like Bitwarden's server, it stores what your clients
  encrypted, and your master password never reaches it — only a hash of it, at login.
- **The official Bitwarden clients keep working.** That is the contract. UwULock's own features
  live under `/uwu/v1`, where Bitwarden's clients never look.
- **No favicons from third parties, no telemetry.** The only connections it opens on its own are
  Let's Encrypt (if you use it) and a daily look at GitHub for a newer release, which
  `UWULOCK_UPDATE_CHECK=off` stops.
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
Let's Encrypt or sits behind your proxy, sets up `/opt/uwulock` and starts it. Without questions:

```bash
sudo bash install.sh --domain vault.example.com --yes
sudo bash install.sh --behind-proxy https://vault.example.com --yes
```

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
| `crates/uwulock-api`    | HTTP: Bitwarden's API, and UwULock's own under `/uwu/v1`                    |
| `crates/uwulock-server` | The program: settings, TLS and Let's Encrypt, commands, backups, updates   |
| `crates/uwulock-bench`  | The same load against any Bitwarden-compatible server, for comparisons     |
| `docker/`, `compose.yaml`, `install.sh`, `update.sh` | The container and how it gets onto a machine  |
| `docs/`                 | Plan, deployment, performance                                              |

## Development

Requirements: Rust stable. Docker for the container and the scripts.

```bash
cargo run -p uwulock-server          # plain HTTP on 0.0.0.0:8443, data in ./data
cargo test --workspace
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings
```

The Let's Encrypt test needs Pebble, Let's Encrypt's test CA; CI runs it, and the comment on
`a_certificate_from_an_acme_ca` in `crates/uwulock-server/tests/serve.rs` says how to run it
locally.

Releasing: set the version in `Cargo.toml`, add its section to `CHANGELOG.md`, commit, tag
`v<version>` and push both. CI checks that they match, tests everything, builds and scans the
image, pushes it to GHCR and creates the GitHub release with the scripts.

## Documentation

- [Plan](docs/plan.md) — where this is going, stage by stage (German)
- [Deployment](docs/deployment.md) — Let's Encrypt, reverse proxies, backups, settings
- [Performance](docs/performance.md) — how it is measured, and the numbers
- [Changelog](CHANGELOG.md)
- [Security](SECURITY.md) — how to report a vulnerability
