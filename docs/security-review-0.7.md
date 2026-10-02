# Security review, 0.7 (October 2026)

Before 0.7.0-beta.1, everything new in the server since 0.6.0-beta.2 was reviewed by reading
the code paths end to end (`git diff v0.6.0-beta.2..origin/main`, PRs #25 to #28):

- what the server fetches: the change-password probe, XposedOrNot's passwords and its check of
  addresses, the public lists of breached sites, DB-IP's GeoIP databases;
- privacy of the breach sources: no account next to a prefix or an address, the check of
  addresses switched on by the admin and agreed to by the account (both checked by the server),
  its budget, the salted cache, nothing of it in the logs;
- the failed-logins page, the GeoIP lookups and the IP blocks: who may reach them, and whether a
  blocked client gets around a block (proxy headers, IPv6 forms, IPv4 in IPv6, other paths);
- resource use: list sizes, merging, parsing downloaded `.mmdb` files, rate limits, the queue of
  the address check;
- feature switches (404 `feature_off` when off), the encrypted ignore list and its 409;
- the web vault: breach names from third-party lists, the change-password link, Wi-Fi fields and
  the QR code, the importers for Wi-Fi networks, the failed-logins page, one vault per web vault,
  and the CSP.

Severity as in [security-review-0.6.md](security-review-0.6.md): **High** is a secret or the
whole database leaving the server, or a promise of the design broken for a normal user.
**Medium** needs a hostile server, an admin session that got away, or is resource exhaustion by
anybody. **Low** is defence in depth, a small leak of ids or metadata, or exhaustion that needs a
login or an admin. **Info** is worth knowing and nothing to do. New ids start at SV7-.

There was nothing critical and nothing high. The two medium findings and every low one are fixed
in this branch (`security-0.7`), each with a test.

## Fixed

| Id | Severity | Where | Finding | Fix | Status |
|---|---|---|---|---|---|
| SV7-M1 | Medium | Breached sites, merging the lists | Merging compared every breach of a domain with every other one of the other source. A list of 20 000 breaches per source for one domain (a compromised or impersonated source) cost about 4·10⁸ comparisons with date parsing on an async worker at every load, so the server's request handling stalled for minutes, at every start and every daily refresh. | At most 100 breaches per domain are kept; the rest of a domain is dropped. Test `a_hostile_list_cannot_make_merging_slow`. | Fixed |
| SV7-L1 | Low | XposedOrNot's and HIBP's password proxies | When a request failed, the warning in the log carried reqwest's error text, which names the URL — and so the prefix of a password's hash (ten hex digits of the Keccak-512 for XposedOrNot, five of the SHA-1 for HIBP), next to the time of the request. | Errors of these requests are logged without their URL (`breaches::quiet`, also used by the HIBP proxy and every breach fetch, the address check included). Test `errors_never_carry_the_prefix_or_the_address`. | Fixed |
| SV7-L2 | Low | Breached sites | While the lists were not on disk yet and a source was down, every request of a logged-in user fetched both lists again (up to 60 s each). Requests waited one after the other behind the refresh lock, and each then fetched once more. | A failed fetch for a request pauses further fetches for five minutes; requests waiting behind the one fetching take its result instead of fetching again. The daily refresh is not affected. Test `sources_that_are_down_are_not_asked_again_for_every_request`. | Fixed |
| SV7-L3 | Low | GeoIP downloads | The download client followed up to three redirects anywhere: plain http, where anybody on the way could change the file, or an address of the local network. | Redirects only to https, to a public name or address, without credentials, at most three. Test `downloads_are_redirected_only_to_https_on_the_internet`. | Fixed |
| SV7-L4 | Low | IP blocks, networks | An IPv4 network written as IPv6 (`::ffff:198.51.100.0/120`) kept the IPv6 prefix on the IPv4 address. The block was stored as `198.51.100.0/120`, which does not parse again, so it was listed but never enforced after the next reload; in a debug build the mask overflowed. The size check looked at how the network was written, so `::ffff:0.0.0.0/96` (all of IPv4) passed as an IPv6 /96. The same parsing serves `adminNetworks`. | Such a network is the IPv4 network it means (`198.51.100.0/24`), and the size check goes by the parsed family. Tests in `networks` and `a_blocked_address_logs_in_nowhere_…`. | Fixed |
| WV-1 | Medium | Web vault, password check | The change-password address from the server became the link of "Open page & change password". A hostile or compromised server could send any address — `javascript:`, `data:` (React 19 refuses `javascript:` links), or simply a phishing page on another host, opened from the vault for exactly the login whose password is about to be changed. Same finding as CL-M3 in the client's review. | The answer only says whether there is a page: the web vault builds `https://<login host>/.well-known/change-password` itself from the login's own plain host name (no port, no user info), and asks nothing for anything else. The endpoint stays as it is. Test `breaches.server.test.ts` › "only say whether there is one; the address is the login host's own". | Fixed |
| WV-2 | Low | Web vault, password check | The 2FA Directory's `documentation` link (a third-party list through the server) was linked unchecked. Older than 0.7, but in the reworked report. | Only http(s) addresses are linked (`webUrl` in `lib/links.ts`). Test in `links.test.ts`. | Fixed |
| WV-3 | Low | Web vault, Wi-Fi | A Wi-Fi item whose *Security* is `constructor` or `__proto__` (written by another app, or shared in an organisation) was looked up in plain objects (`SECURITY_LABEL`, the English texts), and the details, the editor and the QR dialog crashed. | Own keys only (`securityLabel`, `translate` with `Object.hasOwn`); the breach sources' names likewise. Test `items.test.ts`. | Fixed |
| WV-4 | Low | Admin portal, IP blocks | "Block address" was prefilled with the single IPv6 address, which its owner leaves by taking another of the 2⁶⁴ in its /64. | An IPv6 address is prefilled as its /64, an IPv4-mapped one as the IPv4 address; the field stays editable. Tests in `admin.test.ts`. | Fixed |

## Info

- **SV7-I1, the cache of the address check is shared.** Answers are cached for a week under the
  salted hash of the address, for the whole server: an account that checks an address somebody
  else on the server checked within the week gets the answer at once, without spending its
  budget, and so learns that somebody did. The answers are public at XposedOrNot anyway; a cache
  per account would spend the small daily budget several times for the same address. Stays.
- **SV7-I2, the queue of the address check is held while asking.** One request holds the
  server-wide queue for at most about 30 seconds (five fresh addresses, spaced); others wait up
  to 30 seconds and then get `retryAfter`. Each account may cause 24 questions a day, so nobody
  holds it long.
- **SV7-I3, any address can be checked.** The address check takes the addresses the client sends
  (the account's and usernames that are addresses, organisation items included, which can be
  colleagues' addresses), not only the account's own. XposedOrNot answers the same for anybody;
  the consent text says the addresses of the vault are sent. Stays.
- **SV7-I4, the change-password probe follows redirects.** Through the icons' checked client:
  every address checked in the resolver (no DNS rebinding), every redirect checked again, only
  public names, 16 KiB, per-account rate limit (60, one back every two seconds), and the answers
  are kept per account, so nobody learns another account's hosts.
- **SV7-I5, GeoIP databases are parsed as they come.** DB-IP's files are downloaded over TLS
  (with SV7-L3 also after redirects), size-capped packed and unpacked, opened once as a test
  before they replace the old ones, and read with `maxminddb` 0.32, whose decoder bounds its
  lengths. A malicious file from DB-IP itself could still give odd names in the admin portal,
  which shows them as text.
- **SV7-I6, the client address behind a proxy.** Blocks use the address the rest of the server
  believes: the last `X-Forwarded-For` entry, else `X-Real-IP`, only with `trustForwarded`. A
  proxy that sets only `X-Real-IP` and passes the client's own `X-Forwarded-For` on would let
  the client choose its address; docs/deployment.md sets `X-Forwarded-For` in its nginx example
  and says to trust it only behind a proxy that sets it.
- **SV7-I7, the ignore list's revision.** The 409 compares the revision the client read with the
  stored one (microseconds) in the same transaction, so two devices cannot overwrite each
  other's change. A list the client cannot decrypt (another extras key) starts empty and is
  replaced by the next save (WV-6 of the web review).
- **SV7-I8, XposedOrNot's passwords take ten hex digits.** 40 bits of the Keccak-512 narrow a
  password down further than HIBP's 20 bits of SHA-1; that is XposedOrNot's API. The server
  sees the prefix as it does HIBP's, keeps it a day in memory per account, and never writes it
  down (SV7-L1).
- **SV7-I9, the Wi-Fi QR code.** `\ ; , : "` are escaped and the QR is drawn in the browser; the
  password goes only into the code, never into a URL, a log or storage. A password that looks
  like hex is not quoted (a ZXing convention, not a security matter).

## Checked and fine

**What the server fetches.** The breach lists, XposedOrNot's passwords and addresses and the
change-password probe all go through the icons' client: the resolver hands on only public
addresses and is used for the connection itself, redirects are checked, no proxy from the
environment, bodies are read up to a cap (lists 16 MiB and 20 000 breaches, answers 256 KiB,
pages 16 KiB) within a time limit. The upstream addresses are fixed, not settings. The probe
takes host names only (no addresses, no local names), asks for `/.well-known/change-password`
and the W3C check address, and hands back nothing of the page.

**Privacy.** HIBP's and XposedOrNot's password caches are keyed by account and prefix in memory
only; nothing goes to them but the prefix. The address check needs the admin's switch and the
account's consent, both checked by the server for every request (403 `opt_in`, 404
`feature_off`), at most 50 addresses per request, five new ones, a server budget below
XposedOrNot's limits and 24 a day per account; 429 stops the queue for an hour. Addresses are
cached only under a SHA-256 salted with a value sealed by the server secret (outside the
database), never next to an account, pruned after a week, and no address is logged. The breach
lists carry no descriptions (HIBP's are HTML), only titles, dates, counts and data classes,
cut to length and without control characters.

**Endpoints.** Every new user endpoint needs a session; every source has its switch and answers
404 `feature_off` when off; `/uwu/v1/info` and `/uwu/v1/account` say which are on. The failed
logins, GeoIP and IP block endpoints sit under `/uwu/v1/admin/` (the `Admin` extractor and the
admin networks), with clamped limits and bound SQL parameters. The ignore list must be an
EncString (`2.…`, three parts), at most 256 KiB, and goes with the extras key and the account.

**IP blocks.** The guard sits in front of every login path: the token endpoint with every
grant, prelogin, registering, the password hint, the mail with a code, the passkey options, SSO
and log in with a device; the web vault and the admin portal log in through them. Axum matches
paths as they are, so other spellings are 404. Client addresses and block networks are compared
as IPv4 when they are IPv4-mapped. An admin cannot block their own address or more than a /8
(/16); the command line lifts any block. What the client says about itself (user agent, client,
version, device) is cut to length and without control characters before it is stored.

**The web vault.** No new raw HTML except the QR code's SVG, which holds no user text; breach
names, failed-login fields and GeoIP names are text; the account link is encoded; links open
with `noopener`. The new features need nothing of the CSP (`script-src 'self'
'wasm-unsafe-eval'`, unchanged). The Wi-Fi importers see strings only and keep the existing size
and archive limits; `uwulock-core` in WASM clamps odd counts. The web vault knows only its own
session: no second account, no other server.

## 0.7.0-beta.2: SSH/RDP entries

Before 0.7.0-beta.2, what PR #32 added (`git diff 8ff3bd3..5ada48a`) was reviewed by reading it
end to end: the suite bindings of the WebAssembly module (`web/wasm/src/suite.rs`, over
`uwulock_core::suite` at c87995c), `web/src/lib/suite/*` (sync, realtime, model, keys), the
sections and editors in `web/src/components/suite/*`, and the assistant kinds of the server's
space `ssh`. Attacker models: a hostile or compromised server, and a compromised device of the
same account that writes records (valid, sealed with the space key) with odd content. Fixed in
branch `security-suite` (WV-12 in `security-suite-clock`), each with a test. Nothing critical or high.

| Id | Severity | Where | Finding | Fix | Status |
|---|---|---|---|---|---|
| WV-5 | Medium | Web vault, host extras, *Copy command* | The SSH command was built from the host's address and its identity's user name, shell-quoted, but a value starting with `-` stayed an argument to ssh: an address (or user) `-oProxyCommand=…` written by another device made the copied `ssh -oProxyCommand=…` run a command on the user's computer when pasted. Quoting doesn't help against that; control characters (line breaks, escape sequences) also went into the clipboard. | A destination starting with `-` gets `--` before it, so ssh takes it as a host name; control characters (C0, C1, U+2028/9) are replaced by a space. Test `model.test.ts` › "copies the ssh command …". | Fixed |
| WV-6 | Low | Web vault, deleting a key or an identity | The record's `private_secret_id`, `passphrase_secret_id` or `password_secret_id` were tombstoned along with it if they named any live record. A key written by another device could name a host or a group, which a delete in the web vault then removed too. | Only records of kind `secret` go along. Test "takes along only secrets, whatever ids a record names as its own". | Fixed |
| WV-7 | Low | WebAssembly module, merging pulls | Envelope ids were kept as the server spelled them. A UUID in another spelling (upper case, without hyphens, `{…}`, `urn:uuid:…`) opens with the same AAD (the AAD holds the 16 bytes), so a hostile server could show one record twice, make pointers at it miss, and get its spelling into the link to the app (`encodeURIComponent` kept it harmless, but the apps refuse it). | The module takes only ids in the server's own spelling (lower case, hyphenated) and drops the rest; the web vault builds `uwussh://`/`uwurdp://connect/<id>` only for such a UUID and otherwise offers no link. Tests `records_of_the_apps_and_unknown_kinds_pass_through` and "opens the app with nothing but the record's id". | Fixed |
| WV-8 | Low | Web vault, `.rdp` file | Values had CR and LF replaced, but not other line breaks (VT, FF, NEL, U+2028/9) or control characters, which some `.rdp` readers may split on — a way to add a setting (drive redirection, `alternate shell`) to the downloaded file. | The same control-character filter as WV-5. Test "writes an .rdp file without a password and without drives". | Fixed |
| WV-9 | Low | Web vault, pull | A hostile server answering `hasMore` without moving the cursor, or `reset` again and again, kept the page pulling for 10 000 requests. | A pull stops with an error when the cursor doesn't move on with `hasMore`, at a second `reset` in a row, or when a page isn't one. Test "is not pulled forever from a server that goes nowhere". | Fixed |
| WV-10 | Low | Web vault, creating a space | *Create space* ran beside the space's loads (the realtime channel, the section opening): a load between the fresh key and the server's answer could open the listed space in the module over the one just made, or the other way round. | Creating runs in the same queue as loading and pulling the space. Test "is made in line with its loads". | Fixed |
| WV-11 | Low | Web vault, details | The auth type and the kind were looked up with `in` in plain objects: an identity whose `auth_type` is `constructor` (written by another device) broke its details, as WV-3. | `Object.hasOwn` (`authLabel`, `kindLabel`, `kindIcon`). A host's identity must be of kind `identity` (and its group of kind `group`) for the command and the `.rdp` file. | Fixed |
| WV-12 | Medium | WebAssembly module, edit and delete | Found by the client review (UwULock-Client CL-M5): an edit or tombstone takes its clock and `baseSeq` from the record as pulled, but the module never checked that record before sealing on top of it. A hostile server could serve a record (a secret, a tombstone, one that doesn't open) with a clock near the end of time; the web vault then sealed an edit or delete with a clock after it, under the real space key, and every device merging it inherited the clock. | The record is opened with the space key before an edit or tombstone is sealed on it; one that doesn't open can't be changed or deleted ("broken"). Test in `records_of_the_apps_and_unknown_kinds_pass_through`. | Fixed |

### Info

- **WV-I1, rollback by a hostile server.** A record's `seq` is not in its AAD: a server can serve
  an older sealed version of a record as the newest (or withhold changes). It can't forge one or
  move one to another id, kind, space or clock (the AAD binds id, kind, space id, `updatedAt` and
  `deleted`). An edit in the web vault on such an older copy gets a clock after it and so wins in
  the apps, taking the old values of the other fields along. Same for the apps; a check that a
  record's clock never goes back would hold only within one page load. Stays.
- **WV-I2, secrets in the page.** The module hands a secret to the page only when it is shown,
  copied or downloaded; the page shows it for at most a minute. As JavaScript strings these can't
  be wiped, and edits pass through the page as text. The space keys and the sealed records stay
  in the module (`SpaceKey` is zeroized on drop) and go at lock or another account
  (`suite::forget_all`), as does the page's state (`forgetSuite`).
- **WV-I3, the assistant's records reach the page.** `suiteRecords` hands over every known kind
  but `secret` and `manifest`, so the page gets `assist_config` (providers and models, the API
  key only as a pointer to a secret) and `assist_cache` (questions and commands). They are never
  shown or written; their secrets are never asked for.
- **WV-I4, the server sizes the pulls.** A page holds at most 500 records and 8 MiB; the web vault
  trusts the server's pages as it trusts the vault's sync. The space key itself is not bound to
  the space's name, but a key moved to another space opens none of its records (the AAD has the
  prefix and the space id).
- **WV-I5, the link into the app.** Offered only where the user agent isn't a phone or tablet;
  it is a navigation to a custom scheme with the record id only, so CSP needs nothing new. The
  realtime socket's token goes in the first message, not the URL (`connect-src 'self'`).

### Checked and fine

**Records.** Every record is opened with the space's key and the AAD of §6.2 (prefix of the
space, id, kind, space id, clock, `deleted`); kinds outside the space's list are neither opened
nor shown; `manifest` records are never shown, written or tombstoned; a secret's payload is never
in the list. Edits are sealed with a fresh 24-byte nonce from the OS, a clock after the record's
(`Hlc::after`) and `baseSeq` = its `seq`; tombstones are sealed empty; the module refuses a JSON
payload for a secret and text for any other kind, and a push of more than 500 records. Conflicts
take the server's version and ask the user again; 409 `space_changed` reads the space again.

**Rendering.** All record fields go into React as text: no raw HTML, file names of downloads are
filtered (`rdpFileName`), key downloads have fixed names, the `.rdp` file never carries a
password and always turns drives off. The device id in `localStorage` is a random number, nothing
else of the suite is stored in the browser, and nothing is logged.

**Server.** `assist_config` and `assist_cache` are accepted in `ssh` only (UwURDP has no such
kinds; discriminants 10 and 11 as in `uwussh-proto`), appended to the list; test
`the_assistant_kinds_are_uwusshs_only`.
