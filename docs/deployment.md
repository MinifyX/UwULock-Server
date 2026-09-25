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
admin portal at `/admin`, where the link is shown too, for passing on by hand.

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

nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name vault.example.com;
    # ssl_certificate ... ssl_certificate_key ...

    client_max_body_size 525M;  # attachments and sends, once they are there

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Live updates for the clients (WebSocket), once they are there.
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

(`$connection_upgrade` is the usual `map $http_upgrade $connection_upgrade { default upgrade; '' close; }`
in the `http` block.)

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

The database that was there is kept next to it as `uwulock.db.before-restore-<time>`.

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
| `UWULOCK_TRUST_FORWARDED` | `off` | Believe `X-Forwarded-For`. Only behind a proxy that sets it. |
| `UWULOCK_UPDATE_CHECK` | `on` | Ask GitHub once a day whether there is a newer release. |
| `UWULOCK_LANGUAGE` | `de` | Invitations, and new accounts until their owner picks: `de` or `en`. Start value; the admin portal changes it. |
| `UWULOCK_SMTP_*` | — | The mail server, see [Mail](#mail). Start values; the admin portal changes them. |
| `RUST_LOG` | `info` for the server | How much it logs, e.g. `uwulock_server=debug`. |

## Without Docker

```bash
cargo build --release -p uwulock-server
UWULOCK_DATA=/var/lib/uwulock UWULOCK_LISTEN=127.0.0.1:8443 ./target/release/uwulock-server
```

It needs a directory to write to and nothing else. Behind a proxy as above; for TLS of its own,
`UWULOCK_LISTEN=0.0.0.0:443` needs the right to bind a port below 1024
(`setcap cap_net_bind_service=+ep uwulock-server`).
