# Feature switches

UwULock is a Bitwarden-compatible vault with extras on top. An admin decides which extras this
server offers: *Admin portal → Vault & features → Features* has one switch per extra, grouped, each with one line
that says what it does. What is off is not shown and not reachable; **nothing is deleted**, and
switched on again, everything is back as it was.

## Always there

These are never switched off, so Bitwarden's apps keep working unchanged:

- the vault itself: items, folders, trash, archive, import, collections of imported organisations
  and everything `/api/sync` carries;
- Sends (also Sends only for given addresses, and an item shared as a Send), attachments;
- two-step login, passkeys, login with a device, API keys, emergency access;
- the local backups (every night and before every update), the password health report and the
  security notices.

Website icons (`icons.automatic`) and the check against Have I Been Pwned (`hibp`) keep their own
settings under *Settings*; metrics and log shipping are configured in `.env`. The failed logins
page and blocking addresses are always there; their GeoIP (`geoip`, on by default) is a setting
on that page ([failed-logins.md](failed-logins.md)).
The other breach sources of the password check (0.7, *Vault & features → Icons & password
check*, `breaches`) are settings too: XposedOrNot's passwords, the lists of breached sites and the
change-password pages are on for every server, the check of addresses at XposedOrNot is off until
the admin turns it on (and then each account still has to agree). Off, their endpoints answer 404
`feature_off` and the vault hides them ([uwu-api.md](uwu-api.md) §15.1).

## The switches

| Group | Switch (`id`) | What it is |
|---|---|---|
| Sharing | `families` | Sharing in a family, with collections and permissions ([families.md](families.md)) |
| Sharing | `file-requests` | Links through which people without an account upload files ([file-requests.md](file-requests.md)) |
| Sharing | `send-domains` | Names of their own for Sends and file requests ([send-domains.md](send-domains.md)) |
| Sharing | `masked-addresses` | Addresses from UwUMail per website ([masked-addresses.md](masked-addresses.md)) |
| In the vault | `versions` | Earlier states of an item, to bring back |
| In the vault | `reminders` | A mail when it is time to renew a password |
| In the vault | `travel-mode` | Folders hidden from every device while travelling ([travel-mode.md](travel-mode.md)) |
| In the vault | `emergency-sheet` | A PDF for the family, made in the browser |
| In the vault | `own-icons` | Own pictures as icons, encrypted ([icons.md](icons.md)) |
| In the vault | `icon-library` | Ready-made icons for self-hosted services; needs `own-icons` |
| In the vault | `twofa-directory` | Where a website offers 2FA that is not used (2fa.directory) |
| Sign-in | `sso` | Sign-in through UwUAuth or another OpenID Connect provider ([sso.md](sso.md)) |
| Sign-in | `scim` | Accounts created, disabled and removed by the provider; needs `sso` |
| Operations | `offsite-backups` | Nightly backups to SFTP, S3 or a folder ([backups.md](backups.md)) |
| Operations | `admin-notifications` | The server's problems through ntfy, Gotify or Matrix ([notifications.md](notifications.md)); the mail to the admins always goes |
| UwU apps | `suite` | The suite vault for UwUSSH and UwURDP ([suite.md](suite.md)) |

## What "off" means

- Every endpoint of the feature answers **404** with `"code": "feature_off"` — for everybody,
  logged in or not ([uwu-api.md](uwu-api.md) §1.3).
- Its jobs stop: no reminder mails, no versions recorded or pruned, no off-site backup, no
  refresh of the icon library or of 2fa.directory, no sweep of expired file requests, no
  notifications other than mail.
- The web vault hides its menus, settings, buttons and pages; a link that leads there shows
  "Not on this server". The admin portal hides its settings and pages.
- `sso` off makes the server one without SSO: master passwords work again, also where "only
  SSO" was set, and admins are not asked for SSO. Its settings stay for when it is on again.
- `families` off: nobody makes a new family or invites anyone; organisations that are there
  (also those moved in from Vaultwarden) keep working in the Bitwarden apps.
- `send-domains` off: the send domains answer nothing, and no certificates are renewed.
- `travel-mode` cannot be switched off while an account is travelling (400 `travelling`): its
  hidden folders would show up again on every device.
- Nothing is deleted, and the delta sync ([sync.md](sync.md)) still carries what an account
  already has; the apps hide it by `switches`.

## New and updated servers

- A **new server** starts with only the vault and the website icons. `UWULOCK_FEATURES` in `.env`
  sets what it starts with instead: `all`, `none` or names like `families,file-requests`. It
  counts only as long as nobody switched anything in the admin portal.
- While it counts, the server **keeps what it says in the database** (`features.start` in the
  `server` table), at every start and after a restore in the portal. `.env` is not in a backup, the
  database is: a server restored on a new machine without `UWULOCK_FEATURES` keeps the switches
  the old one had through it ([backups.md](backups.md)). The order is: the switches an admin
  switched (portal or command line) win over everything; until then `UWULOCK_FEATURES`, when it is
  set, also a changed one; without it, what it said last; without that, none. So the documented
  rule holds — the line counts until somebody switches, and a server that is switched once keeps
  the admin's switches whatever `.env` says. The other way round was not chosen: writing the
  line's values as switched would have frozen it at the first start, and a changed
  `UWULOCK_FEATURES` would no longer count although nobody switched.
- A server **updated from 0.6.0-beta.1** keeps on what it uses: an extra with data (an
  organisation, a file request, a reminder, an own icon, a version …) or set up (a UwUMail
  server, an SSO provider, a SCIM token, an off-site target, a non-mail notification channel)
  stays on; everything else is off. What an admin had switched off in the settings before (the
  suite vault, file requests, the icon library) stays off.
- `uwulock-server import-vaultwarden` switches `families` on when it brings organisations.

## Changing them

- **Admin portal → Vault & features → Features.** Switching off something in use asks first.
- **Command line**, also with the server stopped: `uwulock-server features` lists them,
  `uwulock-server features on families sso` and `… off reminders` change them. A running server
  takes that over when it starts again.
- **Admin API** (admin session, like every admin endpoint):
  - `GET /uwu/v1/admin/features` →
    `{"object":"features","features":[{"id":"icon-library","group":"vault","on":true,"works":false,"requires":"own-icons","inUse":false}, …]}`.
    `on` is the switch, `works` is on with what it needs, `inUse` says there is data or a setup.
  - `PUT /uwu/v1/admin/features` with `{"reminders": false, "families": true}` changes only the
    names given and answers like `GET`. An unknown name is 400. Every change is written to the
    event log ("switched features: reminders off, families on") and the clients hear of it
    through the realtime channel (`info`).

## For clients

`GET /uwu/v1/info` carries every switch under `switches`, `true` when it works:

```json
"switches": { "families": true, "file-requests": false, "icon-library": false, "own-icons": false, … }
```

`features` lists only what is on (and, where it takes more, set up), so a client that knows no
switches keeps working. A server without `switches` is older: its `features` tell everything.
