# Notifications

Two kinds: **security notices** tell a person what happened on their account; **admin
notifications** tell the admins what is wrong with the server.

## Security notices, for everybody

What happened on an account, listed in the web vault under *Settings → Security* — with the
device, the address it came from and the time — and mailed in the account's language:

| Kind | When |
| --- | --- |
| Failed logins | 3 or more wrong master passwords for the account within 15 minutes |
| Failed two-step codes | 3 or more wrong second-step codes within 15 minutes |
| New device | A device logs in to the account for the first time |
| Account changes | Master password, email address or key derivation (KDF) changed, keys rotated, two-step login turned on or off, the API key made or renewed |
| Access | Emergency access asked for or taken over, a "log in with a device" request, the vault exported (the web vault says so, and so do Bitwarden's apps) |
| Key derivation | The account's KDF is weaker than the server asks for (see [Policies](#policies)) |
| UwU extras key | The key for UwULock's extras (suite vault, own icons, the health report) was made, wrapped again after a rotation, started over, or lost because the account's keys were renewed without it |
| UwU app login | UwUSSH or UwURDP logged in and can read its data in the suite vault — every time, not only on a new device ([suite.md](suite.md)) |

A burst of failed attempts is one notice that counts up while it lasts, not one per try.

**Mails come in bundles**, so an attack does not become a flood of them: the first notice starts
a five-minute wait, then one mail lists everything that came in the meantime (failed attempts
summed up), and an account gets at most one such mail every fifteen minutes; whatever comes later
waits for the next. The mail about a new device goes out at once, as before; so do the mails of
emergency access and of the recovery code, which the list only repeats. When the address changes,
the old address hears of it as well.

The admin decides which kinds are mailed: *Settings → Security notices*. Kinds that are not mailed
are listed all the same. Without a mail server, notices are only listed. They are kept 180 days.

## Admin notifications

The server looks at itself every minute and tells its admins when

| Event | means |
| --- | --- |
| `backupFailed` | the nightly backup could not be written (often: the disk is too full) |
| `backupStale` | the newest backup is older than two days |
| `certificateExpiring` | the certificate clients see runs out within 14 days |
| `updateAvailable` | there is a newer release (only with the update check on) |
| `manyFailedLogins` | 50 or more failed logins across all accounts within an hour |
| `diskLow` | less than 5 % or 1 GB free on the data volume |
| `pushRelayFailing` | Bitwarden's push relay did not take the last request within the hour |
| `mailFailing` | the mail server did not take the last mail within the hour |

An event goes to a channel when it starts, at most once an hour however often it comes and goes,
and once more when it is over. The admin portal's overview lists what is going on right now.
Messages name no account, only counts, dates and sizes. What another server said (the mail
server's refusal, the push relay's or the backup storage's error) stays in the portal and the log;
channels get a fixed text with the status code, like "Mails do not go out (SMTP 550)" or "The
off-site backup did not work (the backup server answered 503)".

### Channels

*Admin portal → Notifications.* Every channel has its own events, a switch, and *Send a test*.
A server starts with **Mail** to every admin (for everything but `updateAvailable` and
`mailFailing`), which needs a mail server. Others:

- **ntfy** — the server's address (`https://ntfy.example.com` or one in your network), the
  topic, a priority from 1 to 5, and an access token if the topic is protected. The server
  publishes as JSON to the address.
- **Gotify** — the server's address and an application's token, a priority from 0 to 10.
- **Matrix** — the homeserver (`https://matrix.example.org`), the room's id (`!abc:example.org`,
  in Element under *Room settings → Advanced*) and the access token of the account that writes.
  Invite that account to the room first. Messages are plain text; the room is not encrypted by
  the server.

Tokens stay on the server, sealed (AES-256-GCM) under `secret.key` in the data directory like
the other secrets in the settings: the portal shows only whether one is saved, and a token left empty on
saving is kept — as long as the address stays the same. Sent to another address, it has to be
typed again.

The addresses may be in your own network — only an admin can set them. The server speaks only
http and https to them, follows no redirect and gives up after ten seconds. A failing test says
the status the address answered, not what it wrote. A channel that does
not take a message keeps it and is tried again a minute later, then two, four, up to an hour; the
overview shows it as failing. A message nobody took for a day is dropped.

## Policies

*Admin portal → Policies* sets rules for every account (organisations get their own with
Stufe 5):

- **Two-step login required**, from a date on. Until then the web vault shows a banner. After it,
  an account without two-step login only gets into the web vault, which shows nothing but the
  setup; Bitwarden's apps, the browser extension, the CLI and UwULock get the message *This server
  requires two-step login. Set it up in the web vault at …* and show it.
- **Minimum key derivation** (KDF): Bitwarden's defaults to start with — PBKDF2 with 600,000
  iterations, Argon2id with 64 MB, 3 iterations and a parallelism of 4. Registering, changing the
  KDF and setting a password by emergency access are refused below it. Accounts already below it
  (like old PBKDF2 accounts from Vaultwarden) keep working; they get a security notice and a
  *Switch now* button in the web vault.
- **Master password rules**: a minimum length and strength (0–4). The server never sees the
  master password, so the clients check it: the web vault at registration and when the password
  changes, and Bitwarden's apps too — the server hands the rules to them as Bitwarden's master
  password policy with every login. With *Require on login*, the apps make a person whose password
  is weaker change it right after logging in.
