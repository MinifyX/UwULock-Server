# Changelog

Each release gets a section here before its tag is pushed; CI copies the section into the GitHub
release. Versions follow semver; `-beta.N` versions are pre-releases.

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
