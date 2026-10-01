# Failed logins and blocked addresses

*Admin portal → Security & sign-in → Failed logins* lists every refused login of the last 90 days
(the event log keeps 90 days). The tile "Failed logins" on the overview leads there.

## What is shown

For each attempt:

- **when**, and **why** it was refused: wrong password (the account exists), the account does not
  exist, the account is disabled, a wrong API key (the CLI), a wrong second step;
- **the account**: the address that was typed, with a link to the account in *Users* while it
  exists, or "does not exist";
- **where from**: the IP address (behind a trusted proxy the one the proxy forwarded, as
  everywhere in the server), and with GeoIP on its country, city and network (AS number and
  operator);
- **the client**: the device's name and type (`deviceName`/`deviceType` of the token request),
  the app and its version (Bitwarden's `Bitwarden-Client-Name` and `Bitwarden-Client-Version`
  headers, else the request's `client_id`), and the `User-Agent`.

Logins that worked keep the same client details from 0.7 on, for the history of an address.
Events written before 0.7 have no client details and their reason is derived from what was
written then.

Filters: the time range (1 hour to 90 days), the account (its address or a part of it), the IP
address (`203.0.113.7`, or `203.0.113.*` for every address that starts like this) and the reason.
**By IP address** groups the attempts per address for the chosen range: how many, how many
accounts were tried (and how many of those do not exist), the addresses tried most, the first and
the last attempt, and how many logins worked from the same address. **History** shows everything
of one address in the 90 days, logins that worked included.

## Blocking an address

**Block IP …** (on an attempt, a group or a history) blocks an address — or a network such as
`203.0.113.0/24` or `2001:db8::/64` — for 1 hour, 24 hours, 7 days, 30 days or until it is lifted,
with an optional note. *Security & sign-in → Blocked addresses* lists the blocks with their end
and who set them, lifts them, and adds one by hand. A block that ran out stops at once and is
swept away by the nightly maintenance.

A blocked address gets **403** with `"code": "ip_blocked"` from every endpoint that logs in or
leads to a login:

| Endpoint | What it is |
|---|---|
| `POST /identity/connect/token` | every grant: password (web vault, admin portal, apps, extension), refresh token, API key (CLI), passkey, SSO code, Send access |
| `POST /identity/accounts/prelogin`, `/identity/accounts/prelogin/password`, `/api/accounts/prelogin` | the KDF before a login |
| `GET /identity/accounts/webauthn/assertion-options` | the start of a passkey login |
| `GET /identity/sso/prevalidate`, `GET /identity/connect/authorize` | the start of an SSO login |
| `POST /identity/accounts/register…` | registering with an invitation |
| `POST /api/two-factor/send-email-login` | the mail with a code for the second step |
| `POST /api/accounts/password-hint` | the master password hint |
| `POST /api/auth-requests`, `GET /api/auth-requests/{id}/response` | "log in with a device", from the side that logs in |

Everything else stays reachable: a device that is logged in already keeps working until its
access token runs out (it cannot refresh it). The admin portal refuses to block the address the
admin is at (`would_lock_out`), and networks larger than a /8 (IPv4) or a /16 (IPv6).

On the command line, also with the server stopped: `uwulock-server blocks` lists the blocks,
`uwulock-server blocks remove 203.0.113.7` lifts one. A running server notices within a minute
(at once for the address that was lifted).

## GeoIP

Countries, cities and networks come from **DB-IP's free databases** "IP to City Lite" and "IP to
ASN Lite" (<https://db-ip.com>, licence
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), "IP Geolocation by DB-IP"). The
server downloads both files once a month from `https://download.db-ip.com/free/` (the month's
files once they are out, the previous month's until then), unpacks and checks them, and keeps them
in `<data>/geoip` (about 130 MB). Addresses are looked up there and nowhere else: nobody outside
the server learns which addresses tried to log in. Addresses in no database (the local network,
documentation networks) show no origin.

The setting **Use GeoIP** (`geoip` in the settings, on by default) is at the foot of the failed
logins page. Switched off, nothing is downloaded or shown, and the nightly maintenance deletes the
files. Switched on, the download starts at once; **Download now** starts it by hand. The page
shows the month of the files and what went wrong last time.

## Admin API

All under an admin session (docs/uwu-api.md §21.13):

- `GET /uwu/v1/admin/failed-logins?hours=24&user=&ip=&reason=&all=false&before=&limit=100` →
  `{ "object": "failedLogins", "attempts": [{ "id", "time", "kind", "reason", "email", "account": { "id", "email" } | null, "ip", "place": { "country", "countryName", "region", "city", "asn", "network" } | null, "deviceType", "deviceName", "userAgent", "clientName", "clientVersion", "detail" }], "more": false, "geoip": true }`.
  `reason` is `password`, `unknown-account`, `disabled`, `api-key` or `two-factor`; `all=true`
  adds the logins that worked (`kind` `login`); `before` is the last `id` of the previous page.
- `GET /uwu/v1/admin/failed-logins/by-ip?hours=…` (same filters) →
  `{ "groups": [{ "ip", "attempts", "first", "last", "targets", "unknown", "emails", "logins", "place", "blocked" }] }`,
  the most attempts first.
- `GET /uwu/v1/admin/ip-blocks` → `{ "blocks": [{ "id", "network", "reason", "created", "expires", "createdBy", "place" }], "yourAddress" }`;
  `POST` with `{ "network": "203.0.113.7", "reason": "…", "hours": 24 }` (`hours` left out or
  `null`: until lifted; at most a year); `DELETE /uwu/v1/admin/ip-blocks/{id}`. Both are written
  to the event log.
- `GET /uwu/v1/admin/geoip` → `{ "enabled", "ready", "month", "cityBytes", "asnBytes", "attempted", "error", "updating", "source" }`;
  `POST /uwu/v1/admin/geoip/update` → 202, the download runs beside the request.
