# Security review, 0.8 (October 2026)

Before 0.8.0-beta.1, the server, the web vault and the admin portal were reviewed by reading the
code paths end to end (review round R1, everything since 0.7.0-beta.3): logins and their limits,
the client address behind proxies, the admin portal's SSO and user actions, API keys and backups,
the delta sync and the SignalR hub for organizations, file requests, bulk endpoints, attachment
links, connections, the XposedOrNot queue, migration 0023, and the web vault's new entry Sends,
passkeys and generator.

The apps, the browser extension and `uwulock-core` (entry Send contract v2, passkey deletion,
generator, one-time codes) were reviewed at the same time; those findings and their fixes are in
UwULock-Client's [docs/security-review-0.5.md](https://github.com/MinifyX/UwULock-Client/blob/main/docs/security-review-0.5.md).
The web vault pins that core (`b9580a2`).

Severity as in [security-review-0.7.md](security-review-0.7.md): **High** is a secret or the
whole database leaving the server, or a promise of the design broken for a normal user.
**Medium** needs a hostile server, an admin session that got away, or is resource exhaustion by
anybody. **Low** is defence in depth, a small leak of ids or metadata, or exhaustion that needs a
login or an admin. **Info** is worth knowing.

There was nothing critical and nothing high. The three medium findings and every low one are fixed
in branch `security-0.8`, each with a test. Of the info items, five are done and two are written
down for later.

## Fixed

| Id | Severity | Finding | Fix | Commit |
| --- | --- | --- | --- | --- |
| R1-1 | Medium | A last `X-Forwarded-For` entry with a non-ASCII byte fell back to the client's own `X-Real-IP` | The last entry is read from the raw bytes; not an IP → the peer address; `X-Real-IP` only without any `X-Forwarded-For`. Test with an obs-text value | `6839ed1` |
| R1-2 | Medium | Logins: no bucket coarser than a /64, none per account, an unbounded hashing queue | A second bucket per IPv6 /48 (100, then one per 6 s); per account 30 wrong passwords, one back every 2 minutes, for unknown devices only (`429 account_limited`, no lockout, keyed by the typed address so nothing is enumerated); `503 busy` with `Retry-After: 2` at once when 8 per hashing slot are waiting | `6839ed1` |
| R1-3 | Medium | SSO provider, pairing, *make admin* and *reset second step* without the master password | The admin's master password (`password_required`) for issuer, client id/secret, unverified addresses, extension ids, on/off, pairing, and both user actions; web portal asks for it | `5ff01fb` |
| R1-4 | Low | API keys in plain text in unencrypted backups | `forget_secrets_in` empties `api_keys` | `d79bf5a` |
| R1-5 | Low | API keys survived a password change, *log out everywhere*, key rotation, takeover | Keys carry the security stamp they were made under (migration 0024); a new stamp ends them, a new key is made on the next ask | `d79bf5a` |
| R1-6 | Low | Prelogin answered PBKDF2 600k for unknown addresses only | A stand-in KDF from an HMAC of the normalized address under the server secret: Argon2id 3/64/4 for three quarters, PBKDF2 600 000 for the rest, stable per address | `1aae51d` |
| R1-7 | Low | Delta sync named organization items and collections out of a member's reach | Only ids the member could see; a `cipher-left` tombstone (migration 0025) still removes an item moved out of their collections; collection ids filtered by reach | `79c417d` |
| R1-8 | Low | SignalR hub sent item ids and collection ids to every member | Item messages only to members who see it; everyone else a plain vault sync | `11d4d4c` |
| R1-9 | Low | Attaching file-request files into a family item skipped the owners' storage check | `check_owner_storage` before the move | `ea59c57` |
| R1-10 | Low | Message-only submissions counted against no storage | Message and sender count to the owner's storage and the request's cap | `28d8ee5` |
| R1-11 | Low | Quadratic move, no cap on id lists or items | A `HashSet`; at most 5 000 ids (`too_many_ids`), at most 100 000 own items (`too_many_items`) | `73583df` |
| R1-12 | Low | Attachment links kept working after losing access | The link checks again that its viewer sees the item | `5b5034a` |
| R1-13 | Low | `--proxy-network` trusted forwarding headers from every container on the network | `UWULOCK_TRUSTED_PROXIES` (IPs/CIDRs): forwarding headers count only from those peers; `install.sh --trusted-proxy`, asked for with `--proxy-network`, a warning without it | `6839ed1` |
| R1-14 | Low | No connection caps, uploads without a deadline | 8 192 connections overall, 256 per /64 when the server does TLS itself (behind a proxy only the total); a public file-request upload gets 120 s + 1 s per 16 KiB | `34fa4ea` |
| R1-15 | Low | One account could fill the XposedOrNot queue for everybody | At most 4 waiting questions per account, else `busy` at once; a `busy` answer gives its HIBP/XON try back | `395e7cf` |
| R1-16 | Low | Editing an entry Send left the old values in its marker line | An entry Send's text is shown read-only in the editor with "delete it and share again" | `d5ae904` |
| R1-17 | Low | "One-time codes (only the codes, never the key)" was untrue | *One-time codes (with their key)*, and ticking asks once more with the client's wording ("the key travels in the Send … whoever has the link can read it out"), *Better not* as default | `d5ae904` |
| R1-18 | Low | Send page showed the raw marker before decoding; Copy never cleared the clipboard | "…" while a marker is being read, *Show original text* (readable lines only), every Copy through the clearing clipboard | `d5ae904` |

## Info

| Id | Finding | Status | Commit |
| --- | --- | --- | --- |
| R1-19 | No mailed code for a new device when the account has no second step | Open, for a later release: the new-device mail stays the signal. Accounts should turn on a second step | – |
| R1-20 | One SCIM token for the whole server, with admin rights over every account | Documented (docs/sso.md, docs/uwu-api.md §21.9): keep it like an admin password | `7dfaad7` |
| R1-21 | GeoIP redirects checked only by host name | Open, low value: only DB-IP over https could redirect, and only to a blind GET | – |
| R1-22 | Pre-0.8 backups may still hold the push relay's installation key | Upgrade note in CHANGELOG: regenerate or delete the installation id at bitwarden.com/host | `7dfaad7` |
| R1-23 | `rustls-pemfile` unmaintained, `yoke-derive` 0.8.3 yanked | PEM parsing through `rustls-pki-types`, dependency dropped; `yoke-derive` 0.8.4 | `85721f8` |
| R1-24 | Generator read every password aloud | The value is out of the live region; a status says "New password generated" | `d5ae904` |
| R1-25 | No bidi isolation on the Send page | `unicode-bidi: isolate` on the shared entry's values, labels, websites and the Send text | `d5ae904` |

## Also in this branch

- The web vault follows the client's contract changes: entry Sends are `uwulock-entry:v2:` with an
  HMAC tag keyed from the Send's link secret, so a marker line in an item's notes or from another
  Send is plain text; only `http`/`https` websites become links. Passkeys are deleted by credential
  id or fingerprint, never by their place alone, and the list is read again afterwards.
