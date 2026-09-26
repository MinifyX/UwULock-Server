# Changelog

Each release gets a section here before its tag is pushed; CI copies the section into the GitHub
release. Versions follow semver; `-beta.N` versions are pre-releases.

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
