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

There was nothing critical and nothing high. The medium finding and every low one are fixed in
this branch (`security-0.7`), each with a test.

## Fixed

| Id | Severity | Where | Finding | Fix | Status |
|---|---|---|---|---|---|
| SV7-M1 | Medium | Breached sites, merging the lists | Merging compared every breach of a domain with every other one of the other source. A list of 20 000 breaches per source for one domain (a compromised or impersonated source) cost about 4·10⁸ comparisons with date parsing on an async worker at every load, so the server's request handling stalled for minutes, at every start and every daily refresh. | At most 100 breaches per domain are kept; the rest of a domain is dropped. Test `a_hostile_list_cannot_make_merging_slow`. | Fixed |
| SV7-L1 | Low | XposedOrNot's and HIBP's password proxies | When a request failed, the warning in the log carried reqwest's error text, which names the URL — and so the prefix of a password's hash (ten hex digits of the Keccak-512 for XposedOrNot, five of the SHA-1 for HIBP), next to the time of the request. | Errors of these requests are logged without their URL (`breaches::quiet`, also used by the HIBP proxy and every breach fetch, the address check included). Test `errors_never_carry_the_prefix_or_the_address`. | Fixed |
| SV7-L2 | Low | Breached sites | While the lists were not on disk yet and a source was down, every request of a logged-in user fetched both lists again (up to 60 s each). Requests waited one after the other behind the refresh lock, and each then fetched once more. | A failed fetch for a request pauses further fetches for five minutes; requests waiting behind the one fetching take its result instead of fetching again. The daily refresh is not affected. Test `sources_that_are_down_are_not_asked_again_for_every_request`. | Fixed |
| SV7-L3 | Low | GeoIP downloads | The download client followed up to three redirects anywhere: plain http, where anybody on the way could change the file, or an address of the local network. | Redirects only to https, to a public name or address, without credentials, at most three. Test `downloads_are_redirected_only_to_https_on_the_internet`. | Fixed |
| SV7-L4 | Low | IP blocks, networks | An IPv4 network written as IPv6 (`::ffff:198.51.100.0/120`) kept the IPv6 prefix on the IPv4 address. The block was stored as `198.51.100.0/120`, which does not parse again, so it was listed but never enforced after the next reload; in a debug build the mask overflowed. The size check looked at how the network was written, so `::ffff:0.0.0.0/96` (all of IPv4) passed as an IPv6 /96. The same parsing serves `adminNetworks`. | Such a network is the IPv4 network it means (`198.51.100.0/24`), and the size check goes by the parsed family. Tests in `networks` and `a_blocked_address_logs_in_nowhere_…`. | Fixed |
| WV-1 | Low | Web vault, password check | The change-password address from the server became a link without a check of its scheme; a hostile server could hand over `javascript:` or `data:` (React 19 refuses `javascript:` links, hence Low). | Only http(s) addresses are linked (`webUrl` in `lib/links.ts`), else the login's own https address. Tests in `breaches.server.test.ts`, `links.test.ts`. | Fixed |
| WV-2 | Low | Web vault, password check | The 2FA Directory's `documentation` link (a third-party list through the server) was linked unchecked. Older than 0.7, but in the reworked report. | `webUrl` as well. | Fixed |
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
