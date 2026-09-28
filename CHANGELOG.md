# Changelog

Each release gets a section here before its tag is pushed; CI copies the section into the GitHub
release. Versions follow semver; `-beta.N` versions are pre-releases.

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
