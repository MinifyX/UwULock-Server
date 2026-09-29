# Security review, 0.6 (September 2026)

Before 0.6.0-beta.1, everything new since 0.4.0-beta.2 (Stufe 4b, 4c, 4d and 6, at `ab2f47e`) was
reviewed in six parts, each by reading the code paths end to end:

- logging in and accounts: SSO, SCIM, pairing with UwUAuth, travel mode's proof, the two-step
  login duty, invitations;
- who may see what: families and organisations, delta sync, live updates, the suite vault, entry
  versions, key rotation, own icons, reminders, travel mode, storage limits;
- what the server fetches or shows to anyone: automatic icons, the icon library, the 2FA
  Directory mirror, the Have I Been Pwned proxy, off-site backups, masked addresses, alerts, Loki,
  OIDC, send domains, public Sends, file requests, branding, metrics;
- the web vault and the admin portal, with the importers;
- the desktop app and the new crypto in `uwulock-core`;
- the browser extension, and the UwULock sync in UwUSSH and UwURDP.

The last two parts are about the clients; their findings are in UwULock-Client's
`docs/security-review-0.3.md` (see the end). The previous review's fixes were checked again
where a part touched them; they hold.

Every finding was checked again before it was counted, and a finding several reviewers reported is
counted once. There was nothing critical. The high and medium findings are fixed in 0.6.0-beta.1.
The low ones and the notes stayed open for 0.6.0-beta.1 and are fixed in 0.6.0-beta.2 (below).

Severity, as before: **High** is a secret or the whole database leaving the server, or a promise of
the design broken for a normal user. **Medium** needs a hostile server, an admin session that got
away, or is resource exhaustion by anybody. **Low** is defence in depth, a small leak of ids or
metadata, or exhaustion that needs a login or an admin. **Info** is worth knowing and nothing to do.
The ids (SV-…) stay the same from here on; "reported as" names the reviewers' own numbers.

## Fixed

| Id | Severity | Where | Finding | Fix | Status |
|---|---|---|---|---|---|
| SV-H1 | High | Travel mode, two-step login | Travel mode promises to be switched off only with the master password and the second step, so a device taken at a border cannot bring the hidden items back. But every two-step login endpoint needed only the session and the master password: a seized, logged-in device could read the authenticator key or the recovery code, remove every provider or set up its own, and then switch travel mode off. With no provider left, the password alone was enough. (Reported as R1-1, R2-1.) | While travelling, every change and every reveal of two-step login (the authenticator key, the recovery code, disabling, setting up any provider, the recovery code at login) answers 400 `travel_active`. The "password alone" fallback applies only when the account has no second step at all (an admin reset, an emergency takeover); one that is set up but unusable answers `two_factor_unusable`. The web vault greys out the two-step login controls while travelling. (`a1145b9`) | Fixed (PR #14) |
| SV-H2 | High | Off-site backups | Downloading a backup asks for the master password, because a backup is the whole database with the key that signs access tokens. The off-site settings did not: an admin session that got away could point them at its own SFTP or S3 target with encryption off, and the next run (or the daily schedule) uploaded everything. Choosing encryption handed back the new recovery key without a password, dropped the existing one silently, and retention could be set to prune every older snapshot. (Reported as Backups H1, R4-2.) | Every change of the off-site settings and `forget-host-key` need the admin's master password; switching encryption off needs `forgetKey: true`, so no key is dropped silently. The portal asks for the password and forces encryption for SFTP and S3. (`e2a6ce5`) | Fixed (PR #14) |
| SV-H3 | High | Extras key, web vault (`uwulock-core`) | A malicious server could choose the extras key itself: when the user-key wrap was missing, the clients took the RSA wrap for the account's public key, which anybody who knows that key can make, and wrapped it under the user key for good. From then on the server could read file-request link secrets (and so make uploaders encrypt for its own key), labels, own icons, and in UwUSSH/UwURDP every host secret. The web vault used the same code. Same finding as CL-H1 in the client's review. (Reported as R4-1, R5-1, R6-1.) | The RSA wrap is gone. The second wrap is `privateKeyWrapped`: the extras key under HKDF-SHA256 of the account's private key, which only the key pair's owner can make and which official rotations keep. `POST /uwu/v1/keys` and rotate-keys take type 2 wraps only (400 `invalid`), `PUT /uwu/v1/keys/private-wrap` adds the wrap to older keys once (409 `exists` after), and the migration marks keys that only had the old RSA wrap as lost. The web vault opens the key only with the private key, refuses when the two wraps disagree, and shows no file-request link whose details encrypt for another key. (UwULock-Client PR #8; server PR #13) | Fixed (PR #13) |
| SV-M1 | Medium | Off-site backups | In plain mode a snapshot carried the token signing key, the security stamps and the device ids, so whoever reads the storage could forge access tokens. Putting a plain snapshot back online checked only that its token key was the same, so a crafted database was taken. (Reported as Backups M1.) | Unencrypted backups are allowed only into a folder of this machine and leave the server's own keys out: the token key is deleted from the copy (`secure_delete` and `VACUUM`), `secret.key` and `acme/` stay home. An unencrypted repository never goes back into the running server, only through the command line. Existing unencrypted SFTP or S3 settings no longer run; each attempt fails loudly (the `backupFailed` alert) and the view says `encryptionRequired`. (`e2a6ce5`) | Fixed (PR #14) |
| SV-M2 | Medium | Off-site backups, SFTP | Listing an SFTP folder collected every name the server sent, for as long as it sent them, and joined them in quadratic time. A hostile SFTP server could make the Lock server run out of memory at every hourly retry, and the busy lock blocked restores meanwhile. (Reported as Backups M2.) | Listings go page by page over a channel of their own, with the caps the S3 target has (2 million names, 128 MiB) and a limit on empty pages. A backup run and fetching a snapshot stop after 12 hours, listing after 10 minutes, and let go of the lock. (`d6f06db`) | Fixed (PR #14) |
| SV-M3 | Medium | Storage limits, organisations | The per-account storage limit counted only personal items. Attachments of organisation items were never checked, organisation versions and own icons counted for nobody, and a personal item's usage disappeared once it was shared. With the defaults every account may make a family of its own and so store without limit, up to the free-space guard, where uploads, Sends and file requests stop for everybody. A deleted sole member left the family and its files behind. (Reported as R2-2.) | A family's attachments, versions and own icons count fully against each confirmed owner. The limit is checked when a family item's attachment is announced (the old one-step upload too), when an own icon is stored, and when an item with files moves into a family. Deleting an account also deletes the families nobody else is in, invitations included. (`81e607a`) | Fixed (PR #14) |
| SV-M4 | Medium | Automatic icons, SVG | The guard against SVGs that grow when drawn searched the text for `<use`, which a namespace prefix hides: `<s:use>` is still a `use` element. A 1 KB favicon with 16 doubling levels cost about a second of CPU and 155 MB, anonymously, for every host not cached yet; eight at once could take a small server down. (Reported as R3-1.) | SVGs are parsed as XML first (no DTD, at most 20 000 nodes and 2 000 elements), and the size they have once drawn is counted without recursion: every `use` in any namespace and every `url(#…)` adds what it points to. More than 5 000, a cycle, `marker`, `feImage` or `url(` in `<style>` is refused. All decodes share a semaphore of two, held until the blocking work ends, so requests that time out cannot pile up decodes. The tests use the prefixed reproducer. (`2885834`) | Fixed (PR #14) |
| SV-M5 | Medium | Automatic icons, cache | Every fetched host left a file in the icon cache, nothing ever removed one, and there was no ceiling and no free-space check. With wildcard DNS an anonymous caller could write about 16 KiB per request until the disk, which holds the database too, was full. The metrics walked the whole folder at every scrape. (Reported as R3-2.) | The cache has a ceiling of 256 MiB and 100,000 files and evicts down to 80 %; expired entries are pruned daily, nothing is kept while the disk is nearly full, and the admin portal shows the ceiling. (`4a22390`) | Fixed (PR #14) |
| SV-M6 | Medium | Masked addresses, UwUMail | A user could start connecting to UwUMail and send the callback a made-up code again and again. UwUMail counts every failed token request against the Lock server's address and, after 30, refuses all of them, refreshes of other users included; about twelve tries per quarter hour kept masked addresses broken for the whole server. (Reported as R3-5.) | Codes that are not codes are not sent on, refused ones are rate-limited per account and per UwUMail server, and when UwUMail answers 429 its token endpoint is left alone for 15 minutes. (`34bbf9a`) | Fixed (PR #14) |
| SV-M7 | Medium | Outbound requests | Answers to the server's own requests were read whole: error texts from alert channels, Loki, send-domain certificates and OIDC, everything from UwUMail, and UwUAuth's 400 and 429 answers during pairing. A hostile or compromised endpoint, or somebody in the middle of an http address, could answer with an endless body and exhaust the memory; Loki and alerts retry by themselves, and anonymous SSO requests fetch discovery again while the provider fails. (Reported as R3-6; the pairing answer also as a note in R1.) | Every answer read from another server has a ceiling: error texts 4 KiB, OAuth and JSON answers 512 KiB, UwUMail 8 MiB. This covers notification channels, Loki, OIDC, masked addresses, UwUAuth pairing, health checks and the push relay. (`c288f81`) | Fixed (PR #14) |
| SV-M8 | Medium | Metrics | The request metrics used the HTTP method as a label as it came, before every guard and even with metrics switched off. The HTTP parser takes any token as a method, so an anonymous caller could make two new entries per request that were never removed, until the memory ran out. (Reported as R3-18.) | The standard HTTP methods are labelled as they are, everything else as `other`, and the number of series is capped. (`8901ccb`) | Fixed (PR #14) |
| SV-M9 | Medium | File requests | A public upload to a file request had no limit on uploads at once, and a file already uploaded could be uploaded again. Whoever has the link could open hundreds of slow uploads to the same files; free space was checked only when each began, so the partial files filled the disk past the floor that the previous review's fix keeps. (Reported as R3-19.) | One upload at a time per file and four per request, rate-limited per address; a file that arrived is never overwritten (409), and the free-space check reserves the room of every upload on its way. (`a70c649`) | Fixed (PR #14) |

## Low: accepted for 0.6.0-beta.1, fixed in 0.6.0-beta.2

These stayed as they were in 0.6.0-beta.1, each with a suggested follow-up. 0.6.0-beta.2 fixes
every one of them along its follow-up; where the fix differs, or a detail matters, it is said at
the end of the entry. Each fix has a test, except where the entry says why not.

Logging in and accounts:

- **SV-L1 Low, masked addresses: API keys work for a disabled account.** A `uwulock_ma_…` key is
  resolved to its user without looking at `disabled`, so an account an admin or SCIM disabled keeps
  making masked addresses at UwUMail. (Reported as R1-2, R3-7.) *Fixed in 0.6.0-beta.2 (`4fffef5`).*
  Follow-up: refuse disabled users in `key_owner`; a one-line fix for 0.6.0-beta.2. The check sits
  in `masked_api_key`, which resolves the key.
- **SV-L2 Low, SCIM: turns on accounts an admin turned off.** `active: true`, or a `PUT` without
  `active`, enables any disabled account, whoever disabled it and why. (Reported as R1-3.) *Fixed in
  0.6.0-beta.2 (`4fffef5`).* Follow-up: remember who disabled an account; SCIM enables only what it
  disabled, and a `PUT` without `active` leaves it alone. Migration 0018 adds `scim_disabled`;
  enabling the account otherwise (an admin) forgets the mark.
- **SV-L3 Low, SSO: any browser extension can get a silent login.** For the client
  `uwulock-extension` every extension's `chromiumapp.org` or `extensions.allizom.org` address is
  taken, so an unrelated extension with the `identity` permission can get tokens without a click
  when the provider asks nothing. The vault stays encrypted, and Lock's own two-step login still
  applies. (Reported as R1-4.) *Fixed in 0.6.0-beta.2 (`4fffef5`).* Follow-up: pin the ids of the
  released extensions, with a setting for self-built ones. The released Firefox add-on's redirect
  host is pinned; the Chromium build is installed by hand, so its id goes in the admin setting
  `extensionIds` (SSO page).
- **SV-L4 Low, two-step login duty: kept only by the web vault.** After the deadline an account
  without a second step still gets a full token for `client_id=web`, and any refresh token can be
  refreshed as `web`. (Reported as R1-5.) *Fixed in 0.6.0-beta.2 (`4fffef5`).* The account holder
  dodges their own policy; nobody else gains access. Follow-up: a setup-only token scope, and keep a
  device's client id at refresh. Such an account gets a token with the scope `uwu.twofactor-setup`:
  it may set up a second step and read its own profile, everything else is 403
  `two_factor_required`, and sync is empty. Once a second step exists, the next refresh is a full
  token. A device keeps its client id at refresh.
- **SV-L5 Low, invitations: an admin's rights outside the admin networks.** Invitations are not an
  admin path, so an admin session from outside the admin networks, or without SSO where that is
  required, still invites without quota. (Reported as R1-6.) *Fixed in 0.6.0-beta.2 (`4fffef5`).*
  Follow-up: count someone as admin there only inside the admin networks and with SSO where
  required.
- **SV-L6 Low, diagnosis: the admin's token in the WebSocket address.** The portal's WebSocket check
  puts the admin's access token in the URL. Caddy's example filters it from the logs, the nginx
  advice does not; the handler also skips the "admins only with SSO" rule. (Reported as R3-17,
  R4-4.) *Fixed in 0.6.0-beta.2 (`4fffef5`).* Follow-up: a short one-time ticket for the socket and
  the `Admin` rules; until then, the nginx advice covers the whole site. The portal asks for a
  one-time ticket (`POST /uwu/v1/admin/diagnosis/websocket-ticket`, 30 seconds) and puts that in the
  address; the ticket is only issued on the admin path, with every admin rule.

Who may see what:

- **SV-L7 Low, delta sync: organisation-wide ids to members who cannot see them.** A delta lists
  own-icon metadata and deletions of every item of an organisation, to members limited to some
  collections and to members who accepted but were never confirmed. Only ids and times, no contents;
  the full sync filters correctly. (Reported as R2-3.) *Fixed in 0.6.0-beta.2 (`f2af461`).*
  Follow-up: confirmed members only, filtered by the same access check as the items. Migration 0018
  keeps the collections of a deleted organisation item in its tombstone and starts a new sync epoch,
  so every client syncs in full once.
- **SV-L8 Low, travel mode: masked addresses and organisation attachments.** While travelling, the
  masked-address list still names hidden items and the site an address was made for, and a download
  link for an attachment of a hidden organisation item keeps working for its hour. (Reported as
  R2-4.) *Fixed in 0.6.0-beta.2 (`f2af461`).* Follow-up: filter masked links through `is_hidden`,
  check it at download, and name masked data in §9.2.
- **SV-L9 Low, reminders: kept after leaving an organisation.** A removed member keeps reminders and
  masked links for the organisation's items, and reminder mails go on. Ids only. (Reported as R2-5.)
  *Fixed in 0.6.0-beta.2 (`f2af461`).* Follow-up: remove them with the membership and filter by
  visibility. Migration 0018 adds triggers that remove the reminders and masked links of a member
  who leaves or is revoked, and removes those left over.
- **SV-L10 Low, suite vault: a push names no space.** After a rekey a stale or lost device can still
  push records sealed for the old space; other devices cannot open them, so they are lost, not read.
  The clients now look at the space before pushing, so only a race remains. (Reported as R2-6,
  R6-12.) *Fixed in 0.6.0-beta.2 (`f2af461`).* Follow-up: `spaceId` in the push and 409 on a
  mismatch, server and UwUSSH/UwURDP together; offer removing suite devices at rekey. The exact wire
  change: `POST /uwu/v1/suite/spaces/{space}/records` takes `spaceId` beside `schema` and `records`,
  the space id the records were sealed for; when the space was rekeyed since, the push is refused as
  a whole with 409 `space_changed` and nothing is written. A push without `spaceId` is still taken,
  for clients from before. UwUSSH and UwURDP send it (their own change); offering to remove suite
  devices at a rekey is theirs too, in the client apps.
- **SV-L11 Low, live updates: no cap on sockets that never log in.** `/uwu/v1/realtime` upgrades
  every request and waits 10 seconds for `auth`; nothing limits such sockets per address or in
  total. (Reported as R2-7.) *Fixed in 0.6.0-beta.2 (`f2af461`).* Follow-up: the anonymous hub's
  limits (per /64, a global ceiling) before the upgrade. At most 25 sockets per /64 (IPv4: per
  address) and 1000 in all may wait for their login; more answer 429 before the upgrade.

Icons and the network:

- **SV-L12 Low, automatic icons: which sites this server's users have.** A cached host answers
  differently from an uncached one once the caller's limit is used up, so anyone can test a list
  of hosts without side effects. (Reported as R3-3.) *Fixed in 0.6.0-beta.2 (`163dabf`).* Follow-up:
  check the limiter before the cache for callers without a session, and say in the admin page what
  automatic icons reveal.
- **SV-L13 Low, automatic icons: NAT64 ranges only partly known.** `64:ff9b:1::/48`, `::/8` and a
  network's own DNS64 prefix are taken as public, so on an IPv6-only host an icon fetch can reach a
  private IPv4 address through the NAT64 gateway. (Reported as R3-4.) *Fixed in 0.6.0-beta.2
  (`163dabf`).* Follow-up: refuse those ranges and learn the local prefix from `ipv4only.arpa`. Also
  refused: 64:ff9b:1::/48 and the rest of ::/8; a DNS64 prefix is learned from `ipv4only.arpa` (RFC
  7050) and the IPv4 address inside is checked.

Masked addresses:

- **SV-L14 Low, reconnecting to UwUMail keeps the old grant.** Connecting again to the same UwUMail
  account never revokes the previous grant, and `finish` runs without the per-account lock.
  (Reported as R3-8.) *Fixed in 0.6.0-beta.2 (`9fd1424`).* Follow-up: revoke the old grant, under
  the lock.
- **SV-L15 Low, the binding cookie can be planted on http.** Without https the cookie has neither
  `__Host-` nor `Secure`, which allows linking somebody's account to the wrong UwUMail account.
  (Reported as R3-9.) *Fixed in 0.6.0-beta.2 (`9fd1424`).* Follow-up: refuse masked connect unless
  the server is https (loopback aside).
- **SV-L16 Low, http UwUMail servers are accepted.** Tokens then travel in the clear. (Reported as
  R3-10.) *Fixed in 0.6.0-beta.2 (`9fd1424`).* Follow-up: https except loopback and private
  addresses, or a warning in the portal. http stays for private and loopback addresses and local or
  single-label names; connecting needs this server on https (400 `https_required`).

Alerts, logs, OIDC:

- **SV-L17 Low, the "mail failing" alert carries users' addresses.** The alert sends the mail
  server's raw error text, often with addresses, to ntfy, Gotify or Matrix, against the module's own
  rule; the push relay alert names its URL with push ids. (Reported as R3-11.) *Fixed in
  0.6.0-beta.2 (`a9fa7fd`).* Follow-up: a fixed text and the SMTP status for channels, the full text
  only in the portal and the log. Channels get "Mails do not go out (SMTP 550)" and the like; the
  push relay's address and push ids never go to a channel.
- **SV-L18 Low, channel and storage secrets are stored in plain.** Alert channel tokens, the Matrix
  token, the Loki password, the off-site S3/SFTP secrets and SMTP are kept unsealed, although
  `crate::secret` exists for this. (Reported as R3-12.) *Fixed in 0.6.0-beta.2 (`a9fa7fd`).*
  Follow-up: seal them and migrate existing rows. Also sealed: the push relay's installation key and
  the off-site recovery key. Unencrypted snapshots, which leave `secret.key` home, empty the sealed
  values in their copy of the database.
- **SV-L19 Low, admin requests to internal addresses with part of the answer.** The admin's test
  buttons reach any host and port and show the status and 200 characters; an OIDC issuer may end in
  `?`, which turns the fixed discovery path into a query. Admin only, behind the admin networks.
  (Reported as R3-13.) *Fixed in 0.6.0-beta.2 (`2db5f24`).* Follow-up: refuse query and fragment in
  the issuer, return only the status, and document the admin exception. The error of any admin-set
  address is its status and, for JSON, an OAuth `error` code; the start of the body goes to the
  debug log. The admin exception (admin-set hosts may be private) is written down in docs/uwu-api.md
  §21.3.
- **SV-L20 Low, OIDC endpoints are not bound to the issuer.** A hostile https provider can name an
  http token endpoint on loopback, so the client secret goes to a local service. (Reported as
  R3-14.) *Fixed in 0.6.0-beta.2 (`2db5f24`).* Follow-up: loopback http only when the issuer is on
  loopback.
- **SV-L21 Low, OIDC discovery failures are not remembered.** Every anonymous authorize call fetches
  again while the provider fails, and the key refetch has the same herd. (Reported as R3-15.) *Fixed
  in 0.6.0-beta.2 (`2db5f24`).* Follow-up: keep a failure for 30 to 60 seconds and fetch once for
  everybody waiting. A failure is kept for 30 seconds; while one fetch runs, everybody else waits
  for it.
- **SV-L22 Low, log lines for Loki have no size cap.** The portal's buffer cuts lines, the Loki
  queue counts entries, not bytes. (Reported as R3-16.) *Fixed in 0.6.0-beta.2 (`2db5f24`).*
  Follow-up: cut each line to `LINE_MAX` before it is queued. Too long, a line keeps half its
  message and 256 bytes of each field, with `truncated: true`.

Sends and file requests:

- **SV-L23 Low, a dot at the end of the host opens the vault on a send domain.** `Host:
  send.example.com.` is not the listed send domain, so the vault, the login and the admin portal
  answer there with the send domain's certificate; the separation of §14.1 is gone, though it is
  still the real server. (Reported as R3-20.) *Fixed in 0.6.0-beta.2 (`aae68a1`).* Follow-up: drop
  one trailing dot when reading the host, with a test. Every dot at the end is dropped, not only
  one.
- **SV-L24 Low, a Send's email code can be guessed slowly, and a recipient locked out.** Five tries
  for each of five codes an hour against a million give about 2 % over a month; five wrong tries end
  the real code. The whole link is needed. (Reported as R3-21.) *Fixed in 0.6.0-beta.2 (`aae68a1`).*
  Follow-up: a daily cap per Send and address, and 8 digits. Also: twenty wrong codes a day end
  every code of the Send and address until the day is over.
- **SV-L25 Low, Sends with listed addresses mail anyone.** A logged-in user can send about twelve
  code mails an hour to any address, with fixed content. (Reported as R3-22.) *Fixed in 0.6.0-beta.2
  (`aae68a1`).* Follow-up: a limit per owner and per Send. Ten code mails an hour per Send; thirty
  an hour and a hundred a day for one owner's Sends.
- **SV-L26 Low, file requests have no storage cap by default.** Uploads also go on after a request
  is disabled or has run out, as long as the submission began before. (Reported as R3-23.) *Fixed in
  0.6.0-beta.2 (`aae68a1`).* SV-M9 bounds the worst case. Follow-up: a byte cap per request by
  default; check that the request is open when a file and a submission finish.
  `fileRequests.maxRequestMb`, 2048 by default (0 for no cap), answers 422 `request_full`.

Off-site backups:

- **SV-L27 Low, SFTP sends the password before the host key is confirmed.** On first use the key is
  trusted and the password already sent; a restore on the command line without `--host-key` takes
  any key. (Reported as Backups L1.) *Fixed in 0.6.0-beta.2 (`02b82f6`, `8b7cafc`).* Follow-up:
  confirm the key before authenticating; require it on the command line. The portal shows the key
  and asks before it is trusted (`confirmed: false`, then a test with `hostKey`).
- **SV-L28 Low, a restore that fails at the files leaves the database replaced.** Without the audit
  entry and the steps after a restore. (Reported as Backups L2.) *Fixed in 0.6.0-beta.2
  (`02b82f6`).* Follow-up: put the files back first, or finish the restore steps on failure too. The
  steps after a restore run and the audit entry is written; the files are not put back first,
  because the snapshot's `secret.key` comes with them and would not fit the live database if the
  database step failed. No test: it needs a disk that fails halfway.
- **SV-L29 Low, the storage server's error text goes into admin alerts.** Up to 64 KiB, unfiltered,
  which lets a hostile storage server write to the admins. (Reported as Backups L3.) *Fixed in
  0.6.0-beta.2 (`a9fa7fd`).* Follow-up: a fixed text with the status, the rest in the log. The alert
  says the kind of failure with the HTTP status or S3 error code, never the storage server's words;
  the portal's status keeps at most 500 characters.
- **SV-L30 Low, the command line shows the recovery key as it is typed.** (Reported as Backups L4.)
  *Fixed in 0.6.0-beta.2 (`02b82f6`).* Follow-up: read it without echo.
- **SV-L31 Low, the storage owner can hide newer snapshots.** The command line restores the newest
  one listed without saying so. Encryption keeps it from being changed. (Reported as Backups L5.)
  *Fixed in 0.6.0-beta.2 (`02b82f6`, `8b7cafc`).* Follow-up: show the snapshot's date and ask;
  remember the newest one seen. A new machine has nothing to remember, so the command line shows the
  newest snapshot with its date and asks. The running server compares the listing with the last
  snapshot it wrote, and the portal warns when that one is missing.

Web vault:

- **SV-L32 Low, "Share as Send" skips the re-prompt.** Every other way to a secret checks the
  master-password re-prompt inside the WASM module; sharing an item as a Send did not, and the
  button is live while the item loads. Someone at an unlocked vault can share a protected item's
  password. (Reported as R4-3.) *Fixed in 0.6.0-beta.2 (`679fa6e`).* Follow-up: check the re-prompt
  in `share_item` and `shareable`, as `orgs::share` does, and disable the button until the item is
  there.

Importers (all of them run in the user's own tab, on a file the user chose; the worst is the tab
hanging):

- **SV-L33 Low, no limit on unpacking.** A KDBX with gzip, a 1PUX or a Proton zip can unpack without
  bound, and the file size has no cap. (Reported as Importers L1.) *Fixed in 0.6.0-beta.2
  (`95961ae`).* Follow-up: caps on input, unpacked size and entries. Input at most 256 MiB, unpacked
  at most 512 MiB, at most 50,000 zip entries (the importers read no ZIP64, so fewer than the
  suggested 100,000).
- **SV-L34 Low, KeePass KDF parameters from the file are not capped.** AES-KDF rounds and Argon2
  passes run on the main thread before the HMAC check, cannot be cancelled, and leave the WASM
  memory grown. (Reported as Importers L2.) *Fixed in 0.6.0-beta.2 (`95961ae`).* Follow-up: ceilings
  like the vault's own KDF, in a worker. Deviation: the KDF still runs on the page thread, not in a
  worker, because the WASM module only loads there. The ceilings (Argon2 at most 1 GiB of memory,
  memory times passes at most 10 GiB, 256 lanes; AES-KDF at most 100 million rounds) are wider than
  the vault's own ranges so real KeePassXC files still import.
- **SV-L35 Low, a quadratic regex in the Chrome CSV importer.** (Reported as Importers L3.)
  *Fixed in 0.6.0-beta.2 (`95961ae`).* Follow-up: parse the Android address without the regex.
- **SV-L36 Low, the DOCTYPE/ENTITY guard can be padded past and runs after `DOMParser`.** The
  browser does not fetch external entities, so this is about size. (Reported as Importers L4.)
  *Fixed in 0.6.0-beta.2 (`95961ae`).* Follow-up: check the whole prolog before parsing. The whole
  prolog is checked in `parseXml()` before `DOMParser` sees the text.
- **SV-L37 Low, many folders take quadratic time.** (Reported as Importers L5.) *Fixed in
  0.6.0-beta.2 (`95961ae`).* Follow-up: a map by name instead of a search.
- **SV-L38 Low, the KDBX 3.1 header hash is not checked.** The block hashes are, so a changed header
  gives garbage or an error, not a quiet change. (Reported as Importers L6.) *Fixed in 0.6.0-beta.2
  (`95961ae`).* Follow-up: compare `Meta/HeaderHash`.
- **SV-L39 Low, one bad value stops the import with a raw error.** The message can show part of the
  file on screen. (Reported as Importers L7.) *Fixed in 0.6.0-beta.2 (`95961ae`).* Follow-up: skip
  the entry and name it, without the value. The entry is skipped and named in the import summary,
  without its value.
- **SV-L40 Low, a 1PUX authenticator key in a section can become a visible text field.** (Reported
  as Importers L8.) *Fixed in 0.6.0-beta.2 (`95961ae`).* Follow-up: map section TOTP fields to the
  TOTP or a hidden field. A section's TOTP becomes the item's TOTP, or a hidden field when there is
  one already.
- **SV-L41 Low, KeePass key files 2.0 without a hash are refused.** A functional gap, no 32-byte
  check either. (Reported as Importers L9.) *Fixed in 0.6.0-beta.2 (`95961ae`).* Follow-up: accept
  them and check the length. Without a hash the key must be exactly 32 bytes.

## Info

- **SV-I1 Info, a missing `secret.key` is replaced quietly.** Every sealed value then fails with a
  bare 500. (Reported as a note in R3.) *Fixed in 0.6.0-beta.2 (`a9fa7fd`).* Follow-up: refuse to
  start when sealed values exist and the key is gone. `UWULOCK_NEW_SECRET_KEY=1` for one start
  empties the sealed values instead (docs/deployment.md).
- **SV-I2 Info, the admin's UwUMail check has no rate limit.** Admin only. (Reported as a note in
  R3.) *Fixed in 0.6.0-beta.2 (`2db5f24`).* Follow-up: the admin limiter. The check has its own
  bucket in the connect limiter: ten, one back every six minutes.
- **SV-I3 Info, the LastPass importer looks up inherited properties.** Nothing comes of it with
  the fields LastPass writes. (Reported as Importers Info.) *Fixed in 0.6.0-beta.2 (`95961ae`).*
  Follow-up: `Object.hasOwn`.
- **SV-I4 Info, imported addresses keep any scheme.** `javascript:` and `data:` come through; the
  web vault never links them and its CSP would stop them, but clients that open an item's address
  should check. (Reported as Importers Info.) *Fixed in 0.6.0-beta.2 (`95961ae`).* Follow-up: keep
  them as text, and the clients open only http and https (UwULock's already do). `javascript:`,
  `vbscript:`, `data:`, `file:` and `blob:` addresses become a text field "URL".

## The clients, the extension, UwUSSH and UwURDP

The desktop app, the extension, `uwulock-core` and the UwULock sync in UwUSSH and UwURDP are in
UwULock-Client's `docs/security-review-0.3.md`. In short:

- **CL-H1 High**, the extras key: the same finding as SV-H3 above, fixed in `uwulock-core`.
- **CL-M1, CL-M2 Medium**, the extension: it trusted a weaker key derivation from the server at a
  new login, and its in-page menu and save bar could be clickjacked. Both are fixed (UwULock-Client
  PR #7).
- **SA-M1 to SA-M3 Medium**, UwUSSH and UwURDP: the remember-me token went to any server, the key
  derivation could be lowered at a new sign-in, and a different space was taken without asking. All
  are fixed on their `sync-uwulock` branches (PR #3 in each).
- The low ones and the notes are listed there; SV-L10 (a push names no space) is counted here only.

## Stays as it is

- Automatic icons tell the server which hosts are in a vault, as Bitwarden's icon service does; the
  clients can switch them off. SV-L12 is about what the server then lets others learn.
- The server sees the first five characters of a password's SHA-1 hash while it asks Have I Been
  Pwned, as decided before.
- Organisation policies are still followed by the clients, not enforced by the server; Stufe 5 is
  no longer part of this program.

## Checked and fine

The point of saying so: these were looked at and held.

**Logging in.** The token endpoint takes a try from the limiter first and answers a wrong password
in the same time; suite client ids and scopes are coupled at login and refresh, and suite tokens
open nothing else. SSO checks the redirect per client, PKCE S256, a hashed one-time state with a
`__Host-` binding cookie, the issuer of the answer, and the ID token completely (no `none`, no HMAC,
RSA of at least 2048 bits); the one-time code is bound to client, redirect and challenge. Pairing
keeps the client secret sealed and the SCIM token only as a hash. SCIM compares its token in
constant time, protects the last admin, and a disable ends every session.

**Who may see what.** Every member and collection id is bound to its organisation in SQL. Only
confirmed members see an organisation, the last owner cannot leave, and invitations are signed and
bound to member and address. Delta sync windows come only from real memberships, so a crafted
cursor gives nothing extra. Rotation compares complete sets in one transaction and is refused while
travelling. Travel mode filters in the store, so every list, bulk action and emergency view follows
it.

**What the server fetches.** Every address an icon fetch resolves to is checked in the resolver and
used as it is, so DNS rebinding does not work; redirects go through the same check; sizes are
capped while reading; raster decodes are capped at 2048 px and 64 MiB; SVG reads nothing outside
the file. Masked addresses: state, PKCE and the binding cookie are single use, and discovered
endpoints must share the UwUMail server's origin, so a user cannot make the server fetch anything
else. Off-site backups: ChaCha20-Poly1305 with the header in the AAD, keyed ids, and the recovery
key handling.

**Sends and file requests.** Send domains answer only the Send and file-request pages and their
API (see SV-L23 for the dot); Send codes are drawn without bias, stored hashed and used once; file
request ids are random, password tries are taken first, and downloads are attachments with
`nosniff`. Branding is admin only and re-encoded as PNG with a `sandbox` CSP.

**The web vault.** Every page has `script-src 'self' 'wasm-unsafe-eval'`, `frame-ancestors 'none'`
and COOP; connector pages cannot connect anywhere. The only raw HTML is the QR code of the 2FA
setup. Downloads are blobs, sessionStorage holds only the session and the SSO state, and no key is
ever stored in the browser. Confirming a family member shows the fingerprint phrase first and wraps
for exactly that key. The emergency sheet escapes every string. The 2FA report matches locally, so
the server never learns which hosts are in the vault. The KDBX4 importer checks the header hash and
the HMAC before decrypting.

**The previous review.** The upload limits, the take-first rate limits, the anonymous hub's limits
and the emergency-contact fingerprints still hold where the new code touches them.
