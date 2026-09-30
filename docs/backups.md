# Backups

UwULock Server keeps two kinds of backups side by side:

- **Local backups**, every night and before every update: a copy of the database under
  `/data/backups`, the newest seven kept. They protect against a bad update or a mistake, not
  against a dead disk. [deployment.md](deployment.md#backups) says how they work and how to put
  one back.
- **Backups on another system**, every night and at the press of a button, to an SFTP server
  (a NAS, say), an S3 bucket or a folder mounted into the container. They protect against losing
  the machine. The rest of this page is about them.

The design is UwUMail Server's: the same repository format, the same targets, the same checks.

## Setting them up

*Admin portal → Backups → Off-site.* Choose where they go, save, **write down the
recovery key** the portal shows once, test the connection, and back up once by hand to see it
work. From then on the server backs up every night at the time you set (UTC).

## What is in a backup

Everything a new server needs to take over:

- the **database**, as a consistent copy made while the server keeps running: accounts, vaults
  (encrypted by the clients, as always), settings, and the key that signs access tokens;
- the **files** in the data directory: attachments, the files of Sends, uploads to file
  requests, and the certificate and account key of Let's Encrypt.

Not in it: the local backups under `backups/`.

The first backup uploads everything. Later ones upload only what is new: the database copy and
every file are cut into content-defined pieces, each stored once by its content, so a changed
database changes only a few of them, and a file that did not change is not even read again. A
day of use usually means a few megabytes.

Every snapshot is complete on its own. The retention rules keep the newest snapshot of each of
the last **7 days, 4 weeks and 6 months** (changeable), and remove what no remaining snapshot
needs.

A backup server that is not ours cannot have this one read without end: files, manifests and
listings have ceilings (a directory listing at most 2 million names), and a run stops after 12
hours (listing the snapshots in the portal after 10 minutes), letting go of the lock restores
need.

## Encryption

Backups are encrypted by default (ChaCha20-Poly1305, with keyed names, so the backup server sees
neither content nor which files exist). The portal shows the **recovery key** once, after the
first save. Without it nobody can read the backups — not you either, once the server is gone —
so keep it apart from the server: in a password manager that does not live on this server, and
on paper. The portal shows it again after the master password.

The vaults in the database are encrypted by the clients anyway. The recovery key protects the
rest: who has an account, the server's signing key, the settings with their passwords.

Unencrypted backups are possible only into a **folder** of this machine (a mounted disk that
encrypts by itself, say); SFTP and S3 always get encrypted ones. An unencrypted backup leaves out
the server's own keys: the key that signs access tokens, `secret.key` (it opens the OpenID Connect
client secret, the UwUMail tokens of masked addresses and the passwords and tokens in the
settings, the notification channels and the off-site settings; the copy has them emptied) and the
Let's Encrypt keys under `acme/`. After a restore from one, everybody logs in again, a new
certificate is fetched, SSO and masked addresses have to be set up anew, and those passwords and
tokens are entered again. It goes back only with the command line, into a new
server — never into the running one from the portal, since nothing ties its content to this
server. The choice is fixed once there are backups at the target; for a change, use another
folder or bucket.

Settings from before 0.6 that send unencrypted backups over SFTP or S3 are kept, but do not run:
each attempt fails with a message, which raises the "backup failed" alert, until they are saved
again with encryption, at a new place. Older unencrypted snapshots still hold the signing key:
delete them from the target.

Every change to the settings asks for the admin's master password, and so does forgetting the
SFTP server's host key: they decide where the whole database goes, and a session token that got
away must not be enough to send it elsewhere. Switching encryption off (for a folder) drops the
recovery key only when that is confirmed.

Whether a backup is encrypted is this server's decision, by whether it has a recovery key, never
the backup server's. A target that claims to hold an unencrypted backup while the server has a
key is refused, and so is anything in an encrypted backup that is not encrypted, that sits under
another object's name, or a snapshot stored under another snapshot's name. An unencrypted backup
has no such protection: its content is checked against its names, which catches damage, but
whoever controls the folder can read it and change both.

## Where backups go

### An SFTP server

- **The server's own key** (recommended): the portal shows its public half after the first save.
  Put that line into `~/.ssh/authorized_keys` of the backup user on the NAS.
- **A password**, for systems that offer only that.

*Test connection* shows the backup server's host key first and asks you to compare it with the
server's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` there); only once you trust it
does UwULock log in there, and it remembers the key. If it changes later, backups stop with an
error until you press *Forget* beside it and test again — as `ssh` would warn. The backup server needs an Ed25519 or ECDSA host key.

### An S3 bucket

Amazon S3 or anything that speaks its API: MinIO, Backblaze B2, Hetzner Object Storage, Wasabi,
Garage. The server needs the S3 address without the bucket (such as
`https://s3.eu-central-1.amazonaws.com`), the region the provider signs for, the bucket, a folder
in it (to keep several servers apart), an access key and a secret key. *Bucket in the path* is
for MinIO and most servers in the own network.

Requests are signed with AWS Signature Version 4; the secret key itself never travels. Plain
`http://` works only for addresses in the own network. A key that may list, read, write and
delete objects in that bucket (or folder) is all it needs.

### A folder

A full path such as `/backup`, which has to exist already — a disk or share that is not mounted
must not quietly turn into a folder on the disk the server runs from — and has to be outside the
data directory. In Docker, mount it into the container, for example with
`- /mnt/nas/uwulock:/backup` under `volumes:` in `compose.yaml`, and make it writable for the
container's user.

Inside the folder the server never follows a symbolic link, so whoever else can write to a share
cannot lead a backup to the server's own files.

## When something goes wrong

A failed backup is tried again an hour later. The admins hear of it — on the overview, by mail
and on the other notification channels ([notifications.md](notifications.md)) — when a backup
fails (*Backup failed*) and when the last good one is older than the warning time, 48 hours by
default (*Backup too old*). The diagnosis shows the off-site backup's age and last error, and
`/metrics` has `uwulock_backup_last_success_timestamp_seconds{target="offsite"}`
([metrics.md](metrics.md)).

## Putting a snapshot back

### In the admin portal, on this server

*Off-site backups → Show the snapshots at the target → Restore*, with the master password. As with
a local backup: only snapshots of this server (the same signing key), how things are right then is
written as a local backup first (`uwulock-<time>-before-restore.db`), the database and the files
come back while the server runs, and everybody logs in again afterwards, you too. The off-site
settings stay as they are now.

### On a new machine, from the command line

When the old machine is gone, restore into an empty data directory **before** the new server
starts the first time. Nothing from the old server is needed but the recovery key and the way to
the backups.

```bash
cd /opt/uwulock
# A folder (mounted into the container):
sudo docker compose run --rm -v /mnt/nas/uwulock:/backup uwulock \
  backup restore --folder /backup
# An SFTP server, with the old server's key (or UWULOCK_BACKUP_SFTP_PASSWORD) and its host key:
sudo docker compose run --rm -v "$PWD/backup_key:/key:ro" uwulock \
  backup restore --sftp backup@nas.example.com:/volume1/backups/uwulock --ssh-key /key \
  --host-key SHA256:…
# An S3 bucket; the keys come from the environment, never from the command line:
sudo docker compose run --rm -e UWULOCK_BACKUP_S3_ACCESS_KEY=… -e UWULOCK_BACKUP_S3_SECRET_KEY=… uwulock \
  backup restore --s3 s3://my-bucket/uwulock --endpoint https://s3.eu-central-1.amazonaws.com \
  --region eu-central-1
sudo docker compose up -d
```

The command asks for the recovery key without showing it, or reads `UWULOCK_BACKUP_KEY`; leave it
empty for unencrypted backups. Without `--snapshot` it shows the newest snapshot with its date and
asks before putting it back — if a newer one should be there, answer no: whoever keeps the storage
could have hidden it. `--list` shows the snapshots there instead, `--snapshot <name>` takes
another one, `--host-key SHA256:…` is needed for SFTP (without it the command shows the server's
key and stops before logging in), `--path-style` is for
MinIO, `--into <dir>` restores somewhere else than the server's data directory.

Afterwards everybody logs in again, and **the off-site backups are switched off** on the new
machine: the snapshot carries the old server's target, and the new one should not write over its
history until you say so. Check the target in the admin portal and switch them on again.

Restore with the version the snapshot came from, or a newer one: the database migrations only run
forwards.

## From the command line, on a running server

```bash
sudo docker compose exec uwulock uwulock-server backup offsite   # back up now
sudo docker compose exec uwulock uwulock-server backup list      # the snapshots
```
