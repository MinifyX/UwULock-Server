# Running UwULock Server

- [With install.sh](#with-installsh)
- [The first admin, and everybody else](#the-first-admin-and-everybody-else)
- [Mail](#mail)
- [With Let's Encrypt](#with-lets-encrypt)
- [Behind a reverse proxy](#behind-a-reverse-proxy)
- [With your own certificate](#with-your-own-certificate)
- [Updates](#updates)
- [Backups](#backups)
- [Settings](#settings)
- [Without Docker](#without-docker)

UwULock Server runs in one container with one volume, `/data`: the database `uwulock.db`, the
nightly backups under `backups/`, and with Let's Encrypt its account and certificate under
`acme/`. Everything that differs from one machine to the next is in `.env`.

The official Bitwarden apps and the browser extension only talk to a server whose certificate the
system trusts. So there are two ways to run it: the server gets its own certificate from Let's
Encrypt, or a reverse proxy you already have does TLS in front of it.

## With install.sh

On a Linux machine with a public name — a VPS, a box at home with port 443 forwarded:

```bash
curl -fsSLO https://github.com/MinifyX/UwULock-Server/releases/latest/download/install.sh
sudo bash install.sh
```

It installs Docker if it is missing, asks which of the two ways, sets up `/opt/uwulock`, starts
the server and waits until it is healthy. Without questions:

```bash
sudo bash install.sh --domain vault.example.com --acme-email admin@example.com --admin you@example.com --yes
sudo bash install.sh --behind-proxy https://vault.example.com --admin you@example.com --yes
```

`sudo bash install.sh --help` lists every flag.

## The first admin, and everybody else

Nobody registers without an invitation. An invitation is a link to the web vault
(`https://vault.example.com/#/finish-signup?token=…`) that works for a week; whoever opens it
chooses a name and a master password there, and the account is made — the keys in their
browser, the server gets only the password's hash and the keys wrapped under it.

The first invitation comes from the command line, and makes an admin:

```bash
cd /opt/uwulock
sudo docker compose exec uwulock uwulock-server invite --admin you@example.com
```

(`install.sh --admin you@example.com` does exactly that at the end.) The link is printed; when
the server can send mail, it goes out by mail as well. Everybody else an admin invites in the
admin portal at `/admin`, where the link is shown too, for passing on by hand. With *Users may
invite* in the portal's settings, every account can invite people too — in the web vault under
Settings → Invite, up to the number of people the settings allow (open invitations count), and
never as an admin. They do not see the link while the server can send mail: whoever holds it can
register the address. Without mail they get it to pass on, and could register the address
themselves — so let users invite only when mail is set up, or when you trust them.

Admins are ordinary accounts with the admin right. The portal shows accounts, devices, the event
log (logins, refused logins, what admins did), the server's log, backups and whether there is an
update — never anything inside a vault: that is encrypted with keys only its owner has.

For the day the only admin cannot log in any more:

```bash
sudo docker compose exec uwulock uwulock-server admin you@example.com          # make an admin
sudo docker compose exec uwulock uwulock-server reset-two-factor you@example.com
```

## Mail

For invitations, codes for two-step login by mail, password hints, and a note when an account
logs in on a new device. Without it everything else works; invitations are passed on as links.
Set it up in the admin portal (Settings → Mail, with a test mail), or in `.env` before the
first start — that is only where a new server starts; once saved in the portal, the database
holds it:

```bash
UWULOCK_SMTP_HOST=mail.example.com
UWULOCK_SMTP_PORT=587
UWULOCK_SMTP_SECURITY=starttls        # starttls (587), tls (465), or none for a local relay
UWULOCK_SMTP_USERNAME=vault@example.com
UWULOCK_SMTP_PASSWORD=...
UWULOCK_SMTP_FROM=vault@example.com
UWULOCK_SMTP_FROM_NAME=UwULock
```

Mails go out in German or English: in the language each account chose in the web vault, and
for invitations in the server's (`UWULOCK_LANGUAGE`, or the portal).

## With Let's Encrypt

`UWULOCK_TLS=acme`. The server asks Let's Encrypt for a certificate for the name in
`UWULOCK_PUBLIC` and renews it by itself, well before it runs out. It uses the TLS-ALPN-01
challenge: Let's Encrypt connects to port 443 of that name, so

- the name has to point to this machine (an A and/or AAAA record), and
- port 443 has to reach the container (`UWULOCK_BIND=443`, and forwarded in your router if the
  box is at home).

Port 80 is not needed. The certificate and the ACME account are kept in the volume under
`acme/`, so a restart does not ask for a new one — Let's Encrypt only issues a few per week for
the same name. While trying things out, `UWULOCK_ACME_DIRECTORY=staging` uses Let's Encrypt's
test CA, whose certificates no browser trusts but which has much higher limits.

The container counts as healthy once it has its certificate, which takes a few seconds to half a
minute on the first start. If it does not come: `docker compose logs uwulock | grep certificate`
says what Let's Encrypt said.

## Behind a reverse proxy

`UWULOCK_TLS=off`: the server speaks plain HTTP and listens on this machine only
(`UWULOCK_BIND=127.0.0.1:8443`). Your proxy terminates TLS and passes requests on. Set
`UWULOCK_TRUST_FORWARDED=on`, so the server sees who is asking and not only the proxy — and only
then, because anybody can send that header to a server that believes it.

Caddy:

```caddyfile
vault.example.com {
    reverse_proxy 127.0.0.1:8443
}
```

When the site writes an access log, filter the clients' access token out of it (see below):

```caddyfile
    log {
        format filter {
            fields {
                request>uri query {
                    delete access_token
                }
            }
        }
    }
```

nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name vault.example.com;
    # ssl_certificate ... ssl_certificate_key ...

    client_max_body_size 525M;  # attachments and Sends: 500 MB by default, see the admin portal

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Live updates for the clients: /notifications/hub is a WebSocket.
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

(`$connection_upgrade` is the usual `map $http_upgrade $connection_upgrade { default upgrade; '' close; }`
in the `http` block.)

The clients' live connection (`/notifications/hub?access_token=…`) carries their access token in
its address, as with Bitwarden. It works for an hour; still, keep it out of access logs — in
nginx with `access_log off;` in a `location /notifications/` block of its own (with the same
lines as above), or a `log_format` that writes `$uri` instead of `$request`.

### A proxy in a container

When the proxy itself runs as a Docker container on the same machine, `127.0.0.1` inside it is
the proxy's own, not the machine's: `reverse_proxy 127.0.0.1:8443` answers 502. The server joins
the proxy's Docker network instead and takes no port on the machine at all:

```bash
sudo bash install.sh --behind-proxy https://vault.example.com --proxy-network proxy --yes
```

The proxy then reaches it at `http://uwulock:8443`. In an ipvlan or macvlan network, where every
container has an address of your network and the proxy reaches services by it, the server needs a
fixed one that no other machine uses:

```bash
sudo bash install.sh --behind-proxy https://vault.example.com \
  --proxy-network dmz --proxy-ip 192.0.2.64 --yes
```

and the proxy passes on to `http://192.0.2.64:8443`. Without the flags, install.sh asks for the
network once you choose the proxy. What it writes is `compose.override.yaml` next to
`compose.yaml`, which update.sh leaves alone; by hand it is:

```yaml
services:
  uwulock:
    ports: !reset []        # Compose 2.24 or newer
    networks:
      proxy: {}             # or, in ipvlan/macvlan:  dmz: { ipv4_address: 192.0.2.64 }
networks:
  proxy:
    external: true
```

then `docker compose up -d`.

### Whether the proxy does its job

The admin portal's *Diagnosis* checks it from your browser and from the server: whether
WebSockets get through (the clients' live updates and "log in with a device" need them), whether
the proxy takes an upload as large as the largest allowed file, whether the server sees the
client's address and not the proxy's, and whether the address the portal is open at is
`UWULOCK_PUBLIC`. Each problem comes with the lines for Caddy and nginx that fix it. See
[Diagnosis](#diagnosis).

## With your own certificate

`UWULOCK_TLS=files`, with `UWULOCK_TLS_CERT` and `UWULOCK_TLS_KEY` pointing at PEM files inside
the container — from certbot, a company CA, anything the clients trust. The server reads them
again within a minute when they change, so a renewal needs no restart. Mount them with a
`compose.override.yaml` next to `compose.yaml` (update.sh leaves that file alone):

```yaml
services:
  uwulock:
    environment:
      UWULOCK_TLS: files
      UWULOCK_TLS_CERT: /certs/fullchain.pem
      UWULOCK_TLS_KEY: /certs/privkey.pem
    volumes:
      - /etc/letsencrypt/live/vault.example.com:/certs:ro
```

The files must be readable by uid 10001, which the server runs as.

## Updates

```bash
cd /opt/uwulock && sudo bash update.sh
```

It fetches a newer copy of itself first, then brings `compose.yaml` up to date (a file you changed
by hand stays unless you say `--force`), writes a backup, pulls the new image and waits for the
health check. If the new version does not come up, the one from before goes back in, with the
backup from just before if the new one had already changed the database.

`UWULOCK_VERSION` in `.env` is what the machine follows: `latest` for stable releases, `beta` for
every release, `edge` for every commit on `main` that passed CI, or one exact version.
`sudo bash update.sh --version beta` switches.

Once a day the server asks GitHub whether there is something newer on that channel and says so
in its log. `UWULOCK_UPDATE_CHECK=off` stops it. Nothing installs itself: a password server that
could replace itself from the network would be one more way in.

## Moving in from Vaultwarden

`uwulock-server import-vaultwarden` takes over a Vaultwarden (on SQLite; tested with 1.37) as it
is: accounts with their passwords, the devices that are logged in — they stay logged in —,
two-step login (authenticator apps, codes by mail, security keys), folders, items, favourites,
attachments, Sends, emergency access, and organisations with their collections, groups and
policies. Nothing is decrypted on the way. Organisations can be used as they are, but not yet
managed here: inviting people and making collections comes with Stufe 5.

Keep the address: clients, security keys and the links of Sends are bound to it. Then:

```bash
# 1. Vaultwarden stops, so nothing changes during the move.
sudo docker stop vaultwarden

# 2. What would come over — nothing is written yet. /srv/vaultwarden is Vaultwarden's data
#    directory, the one with db.sqlite3 and rsa_key.pem.
cd /opt/uwulock
sudo docker compose run --rm -v /srv/vaultwarden:/vaultwarden:ro uwulock \
  import-vaultwarden /vaultwarden --dry-run

# 3. The move. --admin makes that account an admin here; repeat it for more.
sudo docker compose run --rm -v /srv/vaultwarden:/vaultwarden:ro uwulock \
  import-vaultwarden /vaultwarden --admin you@example.com
```

A backup of UwULock's database is written first. The import is one transaction: if an address
of the Vaultwarden has an account here already, nothing is imported. Afterwards, point the
proxy (or the DNS name) at UwULock instead of Vaultwarden. The old password still works; it is
hashed anew at each account's next login.

What does not come over, and is named in the summary: accounts that were invited but never
registered, Duo, YubiKey OTP and U2F (whoever is left without a second step gets a mail saying
so, when mail is set up — otherwise the summary names them, to tell them yourself), the event
log, and "log in with a device" requests that were still waiting. Organisation policies come
along and the apps follow them, but the server does not enforce them before Stufe 5.

Once everything works, destroy the old Vaultwarden data and its backups — or keep them only
where nobody else gets at them: the refresh tokens of the devices that moved are in there, as
they are. A device's old token is replaced here at its first use, so after that the old copy is
worthless; a device that has not been used since the move stays reachable with it until then. A Vaultwarden on MySQL or PostgreSQL has to
move to SQLite first. If the container cannot read the directory (`Permission denied`), copy it
and `chmod -R a+rX` the copy.

## Backups

Every night, and before every update, the server writes a consistent copy of its database to
`/data/backups/uwulock-<date>-<time>.db` and keeps the newest seven. It skips a backup rather than
fill the disk: a backup is only written if a twentieth of the disk (at least 256 MiB) stays free
afterwards.

Those backups protect against a bad update or a mistake, not against a dead disk. Copy them
somewhere else:

```bash
cd /opt/uwulock
sudo docker compose exec uwulock uwulock-server backup
sudo docker compose cp uwulock:/data/backups ./backups-copy
```

Putting one back — only with the server stopped:

```bash
cd /opt/uwulock
sudo docker compose run --rm uwulock restore            # lists them
sudo docker compose stop
sudo docker compose run --rm uwulock restore uwulock-2026-09-25-031000.db
sudo docker compose up -d
```

The database that was there is kept next to it as `uwulock.db.before-restore-<time>`. A restore
ends every session — on every device, apps included, everybody logs in again: a backup carries
the tokens of its day, and among them ones that were taken back since.

The admin portal puts a backup back without stopping anything (Backups → Restore, with the
master password): how things are right then is written as a backup first
(`uwulock-<time>-before-restore.db`), so the step can be undone the same way. It only takes
backups of this server; one of another server goes back on the command line as above. Here too,
everybody logs in again afterwards, the admin who put it back included.

Attachments and the files of Sends are not in the database: they are files next to it, in
`/data/attachments` and `/data/sends`, encrypted by the clients. Copy those along with the
backups. A file whose attachment or Send is deleted stays another week before the nightly sweep
takes it, so a backup from that week that is put back still finds its files.

## Push notifications for the phone apps

Bitwarden's apps for iOS and Android learn about changes through Bitwarden's push relay; without
it they sync when they are opened. The browser extension, the desktop apps and the web vault do
not need it: they keep a WebSocket to the server (`/notifications/hub`, which a proxy has to pass
on, see above).

1. Get an installation id and key at <https://bitwarden.com/host/> — free, and for the region
   you pick there (US or EU).
2. Admin portal → Settings → *Push for the phone apps*: switch it on, choose the region, enter
   id and key, save, and *Test the connection*.
3. The apps register when they next log in or start.

The server then sends the relay the ids of the changed item, folder or Send and of the account —
never anything of a vault's content.

## Diagnosis

*Admin portal → Diagnosis* looks at everything that tends to go wrong once, and the server runs it
by itself after every update (the overview says when it found something):

- the **certificate** clients see — the server's own, or the proxy's in front of it — and when it
  runs out;
- the **clock**, against the `Date` of GitHub's answers (which the update check asks anyway) and
  of Bitwarden's push relay — codes of two-step login fail when it is off by more than half a
  minute. `UWULOCK_TIME_SOURCE` names other http(s) addresses to compare with, or `off`;
- the **mail server** (connect, TLS, login — nothing is sent), the **push relay**, the age of the
  newest **backup**, the free **disk**;
- the **reverse proxy**: WebSockets, the upload limit (16 MB first; *Try the full size* sends as
  much as the largest allowed file), the client's address, the public address. These run from
  your browser against your own server; the browser talks to nobody else.

Every check that is not fine says what to do, with an example for Caddy and one for nginx where
the proxy is the answer.

## The admin portal from some networks only

*Admin portal → Policies → Admin networks*: addresses or networks, one a line (`192.0.2.0/24`,
`2001:db8::/32`, a VPN's range). From anywhere else, `/admin` and the admin API answer 404, as if
there were no admin portal. The address counted is the client's — behind a proxy the one it
passes on, with `UWULOCK_TRUST_FORWARDED=on`. The vault, Sends and the command line are not
affected. An empty list means everywhere.

The portal refuses a list that would shut out the address you save it from. Locked out anyway
(a new VPN, a changed network)? From a shell on the box:

```bash
cd /opt/uwulock
sudo docker compose exec uwulock uwulock-server settings set adminNetworks '[]'
```

The running server takes it over with the next request that it would have refused.

## Settings from the command line

What the admin portal changes, the command line reads and changes too — for a script, or when the
portal is out of reach:

```bash
sudo docker compose exec uwulock uwulock-server settings list          # passwords only as "set"
sudo docker compose exec uwulock uwulock-server settings get policies
sudo docker compose exec uwulock uwulock-server settings set policies.requireTwoFactor.enabled true
printf '%s' "$TOKEN" | sudo docker compose exec -T uwulock uwulock-server settings set metrics.token -
```

Names are the portal's, with dots for the parts; the value is JSON, `-` reads it from standard
input so a secret stays out of the shell's history. The same checks as in the portal apply. A
running server takes `adminNetworks` over at once and the rest when it starts again
(`sudo docker compose restart uwulock`).

## Logs, metrics and notifications

- **Logs** go to the container's output (`docker compose logs uwulock`), and the newest few
  thousand lines to the admin portal. `UWULOCK_LOG_FORMAT=json` writes one JSON object a line, as
  Grafana Alloy, Promtail or Vector like them.
- **Grafana Loki** can get them straight from the server, without anything running next to it:
  *Admin portal → Monitoring → Logs to Loki* with Loki's address (`http://192.0.2.20:3100`;
  `/loki/api/v1/push` is added when the address has no path), optionally a tenant
  (`X-Scope-OrgID`), a user and password for basic authentication, and labels (`job=uwulock` to
  start with; the server adds `level`). The lines are the same JSON as with
  `UWULOCK_LOG_FORMAT=json`, so the same queries work either way:
  `{job="uwulock", level="warn"} | json | fields_message=~"login refused.*"`. They go out every
  second or every megabyte; while Loki is away, up to 10,000 lines wait, and after that the
  oldest are dropped and counted (the overview shows it). A request never waits for Loki. Log
  lines hold addresses and IP addresses — what a Loki gets, it keeps.
- **Prometheus**: [metrics.md](metrics.md).
- **Mail, ntfy, Gotify, Matrix** to the admins when backups fail, the certificate runs out or the
  disk fills up, and **security notices** to everybody: [notifications.md](notifications.md).

## Settings

All in `.env`, read when the container starts (`docker compose up -d` after a change). Mail,
the invitations' lifetime, the default language and a few switches live in the admin portal
instead; `.env` only gives where a new server starts.

| Variable | Default | What it does |
| --- | --- | --- |
| `UWULOCK_PUBLIC` | — | The address clients use, like `https://vault.example.com`. With `acme`, the name the certificate is for. |
| `UWULOCK_TLS` | `off` | `acme`, `files` or `off` (see above). |
| `UWULOCK_BIND` | `443` | Where the container's port is published on this machine: a port or `address:port`. |
| `UWULOCK_VERSION` | `latest` | Image tag: `latest`, `beta`, `edge` or a version. |
| `UWULOCK_ACME_EMAIL` | — | Where Let's Encrypt writes about certificates that did not renew. |
| `UWULOCK_ACME_DIRECTORY` | `letsencrypt` | `letsencrypt`, `staging`, or the https address of another ACME directory. |
| `UWULOCK_TLS_CERT`, `UWULOCK_TLS_KEY` | `/data/tls/cert.pem`, `/data/tls/key.pem` | The PEM files for `files`. |
| `UWULOCK_TRUST_FORWARDED` | `off` | Believe the address the proxy added last to `X-Forwarded-For`. Only behind a proxy that sets it. |
| `UWULOCK_UPDATE_CHECK` | `on` | Ask GitHub once a day whether there is a newer release. |
| `UWULOCK_LOGIN_ATTEMPTS` | `10` | Logins one address may try at once; after that one more a minute. More for many people behind one address. |
| `UWULOCK_LANGUAGE` | `de` | Invitations, and new accounts until their owner picks: `de` or `en`. Start value; the admin portal changes it. |
| `UWULOCK_SMTP_*` | — | The mail server, see [Mail](#mail). Start values; the admin portal changes them. |
| `UWULOCK_LOG_FORMAT` | `text` | `json` for one JSON object a line, the same the server sends to Loki. |
| `UWULOCK_TIME_SOURCE` | GitHub's API, with the update check on | http(s) addresses whose `Date` the diagnosis compares the clock with, or `off`. |
| `RUST_LOG` | `info` for the server | How much it logs, e.g. `uwulock_server=debug`. |

## Without Docker

```bash
cargo build --release -p uwulock-server
UWULOCK_DATA=/var/lib/uwulock UWULOCK_LISTEN=127.0.0.1:8443 ./target/release/uwulock-server
```

It needs a directory to write to and nothing else. Behind a proxy as above; for TLS of its own,
`UWULOCK_LISTEN=0.0.0.0:443` needs the right to bind a port below 1024
(`setcap cap_net_bind_service=+ep uwulock-server`).
