# UwULock API contract for 0.6

This is the contract that UwULock Server 0.6, the web vault, UwULock Client 0.3 (desktop), the
UwULock browser extension, UwUSSH, UwURDP, UwUMail Server and UwUAuth Server implement at the
same time. It covers everything the official Bitwarden clients do **not** cover (UwULock's own API
under `/uwu/v1`), and, for the Bitwarden features that arrive with Stufe 4b, 4c, 4d and 5, which
of Bitwarden's endpoints the server has to speak and where UwULock adds something.

Implementers follow it literally. Where something here is wrong or impossible, change this file in
the same pull request that deviates from it, so it stays the truth.

- The plan and its reasons: [plan.md](plan.md) (German).
- Wire formats marked **[BW]** are Bitwarden's, copied from the named source file; they must stay
  byte-compatible with the official clients. Sources are `bitwarden/server`, `bitwarden/clients`,
  `bitwarden/sdk-internal`, `bitwarden/directory-connector` and `dani-garcia/vaultwarden` at their
  `main`/`HEAD` of 2026-09-28. Paths in `bitwarden/server` omit the `/api` prefix; the server adds
  it (`/api/...`), except for identity (`/identity/...`).
- Everything else is **[UwU]**: our own, free to evolve, versioned by `/uwu/v1`.

## Contents

1. [Conventions](#1-conventions)
2. [Server information](#2-server-information)
3. [The extras key and key rotation](#3-the-extras-key-and-key-rotation)
4. [Delta sync](#4-delta-sync)
5. [Realtime channel](#5-realtime-channel)
6. [Suite vault, suite logins and the move from UwUSync](#6-suite-vault-suite-logins-and-the-move-from-uwusync)
7. [Icons](#7-icons)
8. [Entry versions](#8-entry-versions)
9. [Travel mode](#9-travel-mode)
10. [Password renewal reminders](#10-password-renewal-reminders)
11. [File requests](#11-file-requests)
12. [Security notices](#12-security-notices)
13. [Masked addresses](#13-masked-addresses)
14. [Sends: domains, addresses, branding](#14-sends-domains-addresses-branding)
15. [Reports: password health and 2FA directory](#15-reports-password-health-and-2fa-directory)
16. [Family (Stufe 4d)](#16-family-stufe-4d)
17. [Secrets Manager (Stufe 5)](#17-secrets-manager-stufe-5)
18. [Directory Connector (Stufe 5)](#18-directory-connector-stufe-5)
19. [SSO / OIDC and UwUAuth pairing](#19-sso--oidc-and-uwuauth-pairing)
20. [Server policies the clients see](#20-server-policies-the-clients-see)
21. [Admin API additions](#21-admin-api-additions)
22. [Metrics](#22-metrics)
23. [Browser extension](#23-browser-extension)
24. [Who uses what](#24-who-uses-what)

---

## 1. Conventions

### 1.1 Transport

- Everything is HTTPS on the server's public address (`ApiConfig.public`, e.g.
  `https://lock.example.com`), plus the send domains of §14 for the few paths they serve.
- Request and response bodies are JSON (`Content-Type: application/json`), UTF-8, keys in
  **camelCase**, unless a section says otherwise (raw file bodies are
  `application/octet-stream`). Unknown request keys are ignored; clients ignore unknown response
  keys.
- Every JSON object the server returns under `/uwu/v1` has an `"object"` key naming its kind,
  like Bitwarden's models. Lists are `{"object": "list", "data": [...], "continuationToken": null|string}`.
- Paging, where there is any: `?continuationToken=<opaque>` and `?limit=<n>`; the answer carries
  the next token or `null`.
- IDs are UUIDs, lowercase and hyphenated. Where a section allows the client to choose an id
  (suite records), the server refuses one that exists for another account with 409.
- Times the server writes: RFC 3339 UTC with microseconds, `2026-09-28T12:00:00.000000Z` (the
  store's `clock` format). Times the server reads: any RFC 3339; no zone means UTC. Calendar days
  (reminders): `YYYY-MM-DD`, UTC.
- Bodies are limited to 2 MiB (the router's `BODY_LIMIT`) unless a section says otherwise.
- Responses carry `Cache-Control: no-store` unless a section says otherwise (icons).

### 1.2 Authentication

| Name in this file | What the request carries | Checked how |
| --- | --- | --- |
| `none` | nothing | Public. Rate-limited per client IP (`limits.anonymous` or the named limiter). |
| `user` | `Authorization: Bearer <access token>` from `/identity/connect/token` | The `Session` extractor (signature, security stamp, device still logged in, account enabled) **and** scope `api` in the token. |
| `suite` | the same header, token with scope `uwu.suite` | `Session`, then: the token's `client_id` names the one suite space it may touch (§6.5). A `suite` token is refused with 403 `scope` everywhere else, including all of `/api`. |
| `admin` | `user`, and the account is an admin | The `Admin` extractor, **and** the client IP is inside the admin networks (§21.4); outside them the answer is 404 `Not found.` as if the path did not exist. |
| `masked-key` | a masked-address API key (§13.6) | Only on the addy.io/SimpleLogin endpoints. |
| `sm` | access token of a machine account (§17) | Only on Secrets Manager endpoints. |
| `org-key` | access token from an organization API key (§18) | Only on `/api/public/**`. |
| `scim` | `Authorization: Bearer <SCIM token>` (§19.4) | Only on `/scim/v2/**`. |
| `link` | a short-lived token the server issued for one object (file-request upload token, download link) | Signed like the existing file and Send tokens (`Tokens::file_token`), issuer suffix per purpose. |

`user` tokens exist today and are unchanged. The `uwu.suite` scope is new (§6.5).

### 1.3 Errors

Every error is Bitwarden's `ErrorResponseModel` exactly as `crates/uwulock-api/src/errors.rs`
writes it (`message`, `validationErrors`, `errorModel`, `object: "error"`), so a message reaches
the person whatever client they use. Under `/uwu/v1` the body **additionally** carries
`"code": "<snake_case>"`, a stable machine-readable reason the clients branch on. Codes named in
this file are part of the contract; messages are not (they are English, readable, and may change).

| Status | Used for | Typical `code` |
| --- | --- | --- |
| 400 | invalid input | `invalid`, or a specific one |
| 401 | no or bad session | `unauthorized` |
| 403 | authenticated but not allowed | `forbidden`, `scope` |
| 404 | not found, not yours, or the feature is switched off | `not_found`, `feature_off` |
| 409 | the object changed underneath (optimistic concurrency) or already exists | `conflict`, `exists` |
| 413 | too large | `too_large` |
| 422 | would exceed a quota | `quota` |
| 429 | rate limit; `Retry-After: <seconds>` header | `rate_limited` |
| 502 | an upstream (UwUMail, IdP, icon site) failed | `upstream` |

A message without a named code carries the one of its status in the table above (`error` for
any other status); the Bitwarden-shaped bodies of `/identity` (`invalid_grant` and friends) carry
none. Named so far: `would_lock_out` (§21.4), `kdf_too_weak` (§20), `upstream`.

"Not yours" is always 404, never 403, so ids cannot be probed. A switched-off feature (admin
setting) answers 404 `feature_off` on all its endpoints, and `/uwu/v1/info` says it is off.

### 1.4 Encryption notation

- **EncString type 2** — `"2.<iv b64>|<ciphertext b64>|<mac b64>"`: AES-256-CBC with PKCS#7,
  HMAC-SHA256 over `iv || ciphertext`, key = 64 bytes (32 encryption, 32 MAC). Bitwarden's
  `AesCbc256_HmacSha256_B64`; `uwulock_core::crypto::EncString::encrypt`.
- **EncString type 4** — `"4.<b64>"`: RSA-2048 OAEP with SHA-1 over a 64-byte symmetric key,
  Bitwarden's `Rsa2048_OaepSha1_B64`; `uwulock_core::crypto::wrap_for`. This is how Bitwarden wraps
  an organization key for a member.
- **EncArrayBuffer** — binary: byte `0x02`, IV (16), MAC (32), ciphertext. Used for files
  (attachments, Send files); `uwulock_core::crypto::encrypt_file`.
- **Shareable key** — `derive_shareable_key(secret16, name, info)`: HKDF-SHA256, salt
  `"bitwarden-" + name`, 64 bytes (Bitwarden's `derive_shareable_key`). Sends use `("send", "send")`.
- "Under X" means "an EncString type 2 with key X".

The server never decrypts anything in this file, and never holds a key that could. Where the
server validates an encrypted value it checks only the syntax (type prefix, three base64 parts,
IV 16 bytes, MAC 32 bytes, ciphertext a multiple of 16) and the length.

### 1.5 Live-update hooks

"Notify" in this file means: tell the account's devices through **both** channels — Bitwarden's
SignalR hub and push relay with the named `PushType` (so the official clients sync), and the
realtime channel of §5 with the named area. The device that made the change is left out, as
today (`uwulock_notify::Update`).

---

## 2. Server information

### `GET /uwu/v1/info` — auth `none`

What this server is and can do, for a client before it logs in. Extends today's answer; the
existing keys keep their meaning. Rate-limited like any anonymous request. Answered on the main
host and on every send domain; on a send domain it contains only `name`, `version`, `apiVersion`,
`branding` and `features` restricted to `sends`, `send-emails` and `file-requests`.

```json
{
  "object": "info",
  "name": "UwULock Server",
  "version": "0.6.0",
  "apiVersion": 1,
  "publicUrl": "https://lock.example.com",
  "webVault": true,
  "mail": true,
  "features": [
    "vault", "folders", "trash", "archive", "import", "attachments", "sends", "emergency-access",
    "two-factor-authenticator", "two-factor-email", "two-factor-webauthn", "passkeys",
    "login-with-device", "api-key", "hibp", "admin",
    "delta-sync", "realtime", "suite", "icons", "own-icons", "icon-library", "versions",
    "travel-mode", "reminders", "file-requests", "security-notices", "masked-addresses",
    "send-domains", "send-emails", "families", "organizations", "secrets-manager",
    "directory-connector", "sso", "health-report", "twofa-directory"
  ],
  "sendDomains": [
    { "id": "5b0c…", "url": "https://send.example.com" }
  ],
  "icons": {
    "automatic": true,
    "url": "https://lock.example.com/icons",
    "ownMaxBytes": 98304,
    "ownPixels": 128,
    "library": true
  },
  "sso": { "enabled": true, "only": false, "identifier": "uwulock", "label": "UwUAuth" },
  "branding": {
    "name": "UwULock",
    "color": "#ff4d8d",
    "custom": false,
    "logoLight": null,
    "logoDark": null,
    "favicon": null
  },
  "policies": { "masterPassword": { "minLength": 12, "minComplexity": 3 } },
  "limits": {
    "maxFileBytes": 524288000,
    "versionsPerItem": 20,
    "versionDays": 365,
    "fileRequestMaxFiles": 20,
    "fileRequestMaxDays": 90
  }
}
```

- `apiVersion`: the `/uwu/v1` revision; 1 for 0.6. A client that needs a newer one says so.
- `features`: a name is present only when the server has the feature **and** it is switched on.
  `masked-addresses` means an admin allowed at least one UwUMail server; whether *this* account
  is connected is in §13.2. `send-emails` needs mail. `sso` needs an OIDC provider (§19).
- `sendDomains`: the admin's send domains (§14.1), without the main host. Empty list when none.
- `icons.url`: where the official clients and ours get automatic icons (§7.1). `automatic:false`
  means `/icons/…` answers 404 for everything.
- `sso.identifier`: the value to type as "SSO identifier" in the official clients (any value
  works, §19.1); `label` is what the web vault writes on the button.
- `branding.logoLight`/`logoDark`/`favicon`: absolute URLs of §14.4 (with `?v=<version>`, which
  changes with every change) or `null`; `color` is UwULock's `#ff4d8d` when none was chosen. On a send domain,
  that domain's branding.
- `policies.masterPassword`: §20, for the registration and change-password pages; it also carries
  `enforceOnLogin`.
- `limits`: what the web vault and clients show before the server would refuse.

Clients cache the answer for the session and fetch it again after a realtime `info` message (§5).

### `GET /uwu/v1/account` — auth `user`

Unchanged keys plus:

```json
{
  "sendDomainId": null,
  "travel": { "enabled": false },
  "families": { "mayCreate": true, "maxMembers": 6 },
  "policy": { "twoFactorRequired": false, "twoFactorDeadline": null, "kdfBelowMinimum": false },
  "maskedConnected": false,
  "securityNoticesUnseen": 0,
  "storage": { "usedBytes": 1234567, "limitBytes": null }
}
```

`policy` also carries `twoFactorEnforced` (the deadline passed: only the web vault gets a token
without two-step login) and `minimumKdf` (§20's object), so the web vault can offer settings that
meet it.

`sendDomainId` is §14.2, `travel` §9, `families` §16.4, `policy` §20, `storage` counts
attachments, Send files, file-request submissions, versions and own icons.

---

## 3. The extras key and key rotation

Everything UwULock encrypts beyond Bitwarden's own objects — suite spaces, own icons, file-request
labels, the health report — is encrypted under one **extras key** per account, not directly under
the user key. The reason is key rotation by an official client: it re-encrypts only what Bitwarden
knows, and anything else under the old user key would be lost. The extras key is kept wrapped
**twice**:

- `userKeyWrapped`: the 64-byte extras key under the user key (EncString type 2);
- `publicKeyWrapped`: the same key wrapped for the account's RSA public key (EncString type 4,
  exactly like an organization key for a member).

Bitwarden's clients keep the account's RSA key pair when they rotate (they re-wrap the private key
under the new user key; `accountKeys.publicKeyEncryptionKeyPair.publicKey` stays the same). So
after an official rotation the server drops `userKeyWrapped`, keeps `publicKeyWrapped`, and the
next UwULock client opens the extras key with the private key and wraps it again for the new user
key. Nothing under the extras key needs re-encrypting, ever.

Personal **entry versions** (§8) are copies of Bitwarden ciphers under the user key (or under a
cipher key that is under the user key). They cannot survive an official rotation, and they are
dropped then (decided). A rotation through UwULock's own endpoint re-encrypts them.

### `GET /uwu/v1/keys` — auth `user` or `suite`

```json
{
  "object": "uwuKeys",
  "extrasKey": {
    "userKeyWrapped": "2.…",
    "publicKeyWrapped": "4.…",
    "revisionDate": "2026-09-28T12:00:00.000000Z"
  },
  "lost": false
}
```

- `extrasKey` is `null` until a client has made one.
- `userKeyWrapped` is `null` after an official rotation, until a client wraps it again.
- `lost: true` (and `extrasKey: null`): the account's public key changed in a rotation, so
  neither wrap opens any more. The client says so and offers to start over (`DELETE` below).

### `POST /uwu/v1/keys` — auth `user` or `suite`

Makes the extras key; the first UwULock client (web vault, desktop, extension, UwUSSH, UwURDP)
that needs it does this. Body:

```json
{ "userKeyWrapped": "2.…", "publicKeyWrapped": "4.…" }
```

The client makes 64 random bytes, wraps them for the user key and for the public key it has from
the token response (`AccountKeys.publicKeyEncryptionKeyPair.publicKey`, SPKI DER, base64). Answer:
the `GET` body. 409 `exists` when there is one already (two clients raced): the loser fetches it.
400 `no_key_pair` if the account has no key pair (only possible for accounts that never finished
registration), 400 `invalid` when a wrap is not an EncString of its type. A key that is `lost`
makes way for the new one, without a `DELETE` first. The server keeps the account's public key
beside the wraps: `lost` is that it differs from the account's now. A rotation through Bitwarden's
`/api/accounts/key-management/rotate-user-account-keys` (by any client) drops `userKeyWrapped` in
the same transaction.

### `PUT /uwu/v1/keys/user-wrap` — auth `user` or `suite`

After an official rotation. Body `{ "userKeyWrapped": "2.…" }`. Only allowed while
`userKeyWrapped` is `null`; otherwise 409 `exists`. Answer: the `GET` body.

### `DELETE /uwu/v1/keys` — auth `user`

Only when `lost` is true, or to start over on purpose. Body `{ "masterPasswordHash": "…" }` (the
existing `check_password`, with its rate limit). Deletes the extras key **and everything under
it**: suite spaces and their records, own icons, the health report; file requests lose their
labels (the web vault shows them as "unnamed"). Security notice `extrasKeyReset` (§12). Answer 200.

### `POST /uwu/v1/accounts/rotate-keys` — auth `user`

A key rotation made by the web vault or UwULock Client. Body limit: the router's
`VAULT_BODY_LIMIT` (64 MiB). Body:

```json
{
  "rotation": { "oldMasterKeyAuthenticationHash": "…", "accountUnlockData": {}, "accountKeys": {}, "accountData": {} },
  "extrasKey": { "userKeyWrapped": "2.…", "publicKeyWrapped": "4.…" },
  "versions": [
    { "id": "7f1c…", "cipher": { "type": 1, "name": "2.…", "notes": null, "key": null, "login": {}, "fields": [], "passwordHistory": [], "reprompt": 0 } }
  ],
  "dropVersions": false
}
```

- `rotation` is exactly the body of **[BW]** `POST /api/accounts/key-management/rotate-user-account-keys`
  (`RotateUserAccountKeysAndDataRequestModel`, as the server already parses it in
  `accounts.rs::RotateKeys`), checked the same way.
- `extrasKey`: the extras key wrapped again (for the new user key; `publicKeyWrapped` again only
  if the key pair changed, else the old value). `null` if the account has none.
- `versions`: every **personal** version of the account (§8.5, `GET /uwu/v1/versions`), each
  re-encrypted for the new user key. The server compares the set of ids with what it holds; any
  difference is 409 `versions_changed` and nothing is written (the client fetches the list again).
  Or `dropVersions: true` and `versions: []`: the personal versions are deleted.
- All of it in one transaction with the Bitwarden part. Then as today: security stamp, logout of
  other devices, notify `LogOut`. Security notice `keysRotated`.
- While travel mode is on (§9), this and Bitwarden's rotation are refused with 400
  `travel_active`: the hidden items could not be re-encrypted by a client that does not see them.
- `versions[].cipher` is read like a cipher of `accountData.ciphers` (Bitwarden's
  `CipherRequestModel` keys; `organizationId` must be null).

### When an official client rotates

On `POST /api/accounts/key-management/rotate-user-account-keys` (and any other Bitwarden endpoint
that replaces the user key), in the same transaction:

1. delete all personal versions (§8);
2. set `extrasKey.userKeyWrapped = null`;
3. if `accountKeys.publicKeyEncryptionKeyPair.publicKey` differs from the stored public key, the
   extras key is lost (`lost: true`); keep the data until `DELETE /uwu/v1/keys`;
4. bump the sync epoch (§4.3).

Organization keys do not change in a user's rotation, so organization versions and organization
icons stay.

---

## 4. Delta sync

`/api/sync` stays exactly as it is for the official clients. UwULock's clients use
`/uwu/v1/sync`, which gives the same data in the same JSON, plus UwULock's own, and after the
first time only what changed.

### 4.1 Change numbers

- Every account has a **change counter** `seq` (64-bit, starts at 0). Each write that changes
  something the account sees in a sync — a cipher, folder, Send, the profile, a suite record, an
  own icon, a reminder, a travel-mode flag, a Send's domain, the extras key — takes the next
  number and stores it on the changed row (`seq` column) in the same transaction.
- Every organization has its own counter, for its ciphers and collections, so a change to a
  shared cipher is written once and not once per member.
- Hard deletes write a **tombstone** `(owner = user|org, owner id, kind, object id, seq, time)`.
  Tombstones are kept for 90 days.
- Soft deletes (trash) are ordinary changes: the cipher comes again with its `deletedDate`.

### 4.2 The cursor

The cursor is an opaque string of at most 4 KiB, base64url, that the client stores and sends
back unchanged. The server encodes in it (suggested, not contract): a format version, the server
epoch, the account's sync epoch, the account `seq`, and one `seq` per organization the account was
in. Clients never parse it.

### 4.3 Epochs: when a delta is not enough

A delta cannot express everything. The account's **sync epoch** (an integer on the account) is
bumped by:

- a key rotation (either kind), a change of KDF or master password, a new security stamp;
- joining, leaving, being confirmed in, removed from or revoked from an organization; a change of
  the collections, groups or permissions the account has in one; an organization deleted;
- travel mode switched on or off, or its folders changed while it is on (§9);
- `POST /api/ciphers/purge`, a vault import of more than 1000 items;
- the extras key being lost or deleted.

The **server epoch** is bumped when a backup is restored into the running server (§21) or the
database is migrated from another backend. A cursor with an old epoch, or older than the oldest
tombstone that is left, cannot be served; the answer is then a full sync with `reset: true`.

### 4.4 `GET /uwu/v1/sync?since=<cursor>&include=<areas>&limit=<n>` — auth `user` or `suite`

- `since`: absent for a full sync.
- `include`: comma-separated among `vault`, `suite`, `uwu`. Default `vault,uwu`. A `suite` token
  may only ask for `suite` (anything else is 403 `scope`) and gets only its own space.
  The include set is part of the cursor; a cursor used with another set means a full sync.
- `limit`: most changed objects per answer in a delta, default 500, at most 1000. A full sync is
  never paged.

Answer (full sync: every list complete, `deleted` lists empty, `reset: true`):

```json
{
  "object": "uwuSync",
  "reset": false,
  "cursor": "djEuMy4xNy4…",
  "hasMore": false,
  "vault": {
    "profile": null,
    "folders": [],
    "collections": [],
    "ciphers": [],
    "sends": [],
    "policies": null,
    "domains": null,
    "userDecryption": null,
    "deleted": { "folders": [], "collections": [], "ciphers": [], "sends": [] }
  },
  "suite": {
    "records": [],
    "spaces": []
  },
  "uwu": {
    "extrasKey": null,
    "icons": [],
    "iconsDeleted": [],
    "reminders": null,
    "travel": null,
    "sendDomains": {},
    "maskedLinks": null,
    "unseen": { "securityNotices": 0, "fileRequestSubmissions": 0 }
  }
}
```

- `vault.*` elements are **[BW]** exactly the objects of `/api/sync` (`CipherDetailsResponseModel`,
  `FolderResponseModel`, `CollectionDetailsResponseModel`, `SendResponseModel`, `ProfileResponseModel`,
  `PolicyResponseModel`, `DomainsResponseModel`, `UserDecryption`) as the server renders them for
  `/api/sync` today, including the SSH-key gating by client version and the travel-mode filter
  (§9). In a delta, `profile`, `policies`, `domains` and `userDecryption` are `null` unless they
  changed since the cursor; then they are complete.
- `vault.deleted`: ids that are gone for this account since the cursor (hard delete, moved out of
  reach without an epoch bump, or a collection deleted).
- `suite.records`: envelopes of §6.3 with `seq` greater than the cursor's, of the spaces this
  token sees; deleted records are envelopes with `deleted: true` (they are the tombstones).
  `suite.spaces`: the §6.2 space objects that changed (new, or their key changed).
- `uwu.extrasKey`: the §3 object when it changed, else `null`.
- `uwu.icons`: `[{ "cipherId", "revisionDate", "keyType" }]` of own icons that changed (§7.3);
  `iconsDeleted`: cipher ids whose own icon is gone.
- `uwu.reminders`: the full §10 list when any reminder changed, else `null`.
- `uwu.travel`: the §9 object when it changed, else `null`.
- `uwu.sendDomains`: `{ "<sendId>": "<sendDomainId>" | null }` for Sends whose domain choice
  changed (§14.2); full map in a full sync.
- `uwu.maskedLinks`: `{ "<cipherId>": { "id": "x42", "email": "…" } }`, the full map of §13.3
  links when any changed, else `null`.
- `uwu.unseen`: always present; counts for the badges.
- `hasMore: true`: there is more; call again at once with the new cursor. Objects are delivered
  in `seq` order across all areas; `cursor` always points after the last one delivered.

Errors: 400 `invalid` for an unreadable cursor (the client drops it and does a full sync).

**Clients:** web vault (optional; it may keep `/api/sync`), UwULock desktop, browser extension,
UwUSSH and UwURDP (`include=suite`).

---

## 5. Realtime channel

One WebSocket per device that says **that** something changed, never what. The client then asks
`/uwu/v1/sync` with its cursor. So the channel carries no secrets, needs no ordering guarantees,
and a lost message costs nothing but a moment: the sync endpoint is the truth.

### 5.1 Connecting

`GET /uwu/v1/realtime` with a WebSocket upgrade and subprotocol `uwu.realtime.v1`
(`Sec-WebSocket-Protocol`). No token in the URL (proxies log URLs). Text frames, one JSON object
each, at most 4 KiB. Answered on the main host only.

The first client message, within 10 seconds:

```json
{ "type": "auth", "token": "<access token>", "cursor": "<last cursor or null>" }
```

Server answers:

```json
{ "type": "ready", "connectionId": "c0d1…", "expires": 1790000000, "heartbeat": 25 }
```

- `expires`: the access token's `exp` (Unix seconds). Before it passes, the client sends a new
  `auth` message with a fresh token (and its current cursor) on the same connection; the server
  answers `ready` again. When `exp` passes without one, the server closes with 4401.
- `heartbeat`: the server sends a WebSocket ping every this many seconds; a client that saw no
  frame for `3 × heartbeat` reconnects. Clients that cannot see pings (browsers) may send
  `{ "type": "ping" }`; the server answers `{ "type": "pong" }`. At most one client message per
  second on average (burst 10); more closes with 4429.
- If `cursor` is given and the account has changed since it (for this token's areas), the server
  sends `changed` right after `ready`. That is the whole of "resume".

### 5.2 Server messages

| Message | Meaning | Client does |
| --- | --- | --- |
| `{ "type": "changed", "areas": ["vault", "uwu"], "spaces": ["ssh"] }` | Something in these areas changed. `spaces` only with `suite`. | Delta sync (debounce 250 ms). |
| `{ "type": "logout", "reason": "securityStamp" }` | The session ended: `securityStamp`, `deviceRemoved`, `disabled`, `keysRotated`. Then close 4401. | Log out locally (keep nothing decrypted). |
| `{ "type": "authRequest", "id": "…" }` | A "log in with device" request for this account (not for suite tokens). | Show the approval prompt (Bitwarden's `/api/auth-requests/{id}`). |
| `{ "type": "notice", "kind": "securityNotice", "id": 123 }` | A new security notice (§12). | Badge, optional OS notification. |
| `{ "type": "notice", "kind": "fileRequest", "id": "<requestId>" }` | Something arrived for a file request (§11). | Badge, optional OS notification. |
| `{ "type": "notice", "kind": "reminderDue" }` | A reminder became due (§10). | Badge. |
| `{ "type": "info" }` | `/uwu/v1/info` changed (admin settings). | Fetch it again. |

A `suite` token only ever gets `changed` (for its space), `logout` and `info`.

The change that a device made itself is not announced back to it (same rule as §1.5; the device
is taken from the access token).

### 5.3 Closing and reconnecting

| Close code | Meaning | Client does |
| --- | --- | --- |
| 1000/1001 | normal / server going away | reconnect after 1–5 s |
| 1012 | server restarting | reconnect after 2–10 s |
| 4400 | bad message | fix the client; reconnect after 60 s |
| 4401 | token missing, invalid or expired | refresh the token, then reconnect |
| 4403 | not allowed (scope) | do not reconnect |
| 4408 | no `auth` within 10 s | reconnect |
| 4429 | too many connections or messages | reconnect after at least 60 s |

Otherwise: exponential backoff from 1 s to 60 s with ±30 % jitter, reset after a connection
lived 60 s. On every reconnect the client sends its cursor, so nothing is missed. At most 20
connections per account (the 21st is closed with 4429); the server rechecks the session (security
stamp, device) at every heartbeat, like the SignalR hub.

**Clients:** UwULock desktop (replaces its polling), browser extension (from the background
service worker; MV3 keeps it alive by the heartbeat traffic, and the extension falls back to a
delta sync on `chrome.alarms` every 5 min when the worker was stopped), web vault (may use it
instead of SignalR), UwUSSH, UwURDP.

---

## 6. Suite vault, suite logins and the move from UwUSync

UwUSSH and UwURDP keep their sync engine (records with hybrid logical clocks, optimistic
concurrency by `baseSeq`, last-writer-wins merge, manifests) and their record encryption. What
changes with UwULock as backend is only the transport, the login and where the key comes from.
So the suite vault speaks UwUSync's record model (`uwussh-proto` `sync.rs`), in camelCase, under
`/uwu/v1/suite`, and the key of each space is kept under the account's extras key (§3). The
records are **not** Bitwarden ciphers and never appear in `/api/sync` (unknown types would break
the official clients).

### 6.1 Spaces and record types

A **space** is one app's data in one account. Spaces and the record kinds in them:

| Space | App | Kinds (`kind` on the wire, discriminant for the AAD) | Types named in the plan |
| --- | --- | --- | --- |
| `ssh` | UwUSSH | `host` 0, `group` 1, `identity` 2, `key` 3, `snippet` 4, `port_forward` 5, `known_host` 6, `terminal_profile` 7, `secret` 8, `manifest` 9 | ssh-host = `host`, ssh-key = `key` |
| `rdp` | UwURDP | the same list as UwURDP's `uwurdp-proto` `EntityKind` (same numbers) | rdp-connection = `host` |
| `mail` | UwUMail apps (reserved) | `account` 0, `secret` 8, `manifest` 9 | uwumail-account = `account` |
| `generic` | any other UwU app | `item` 0, `secret` 8, `manifest` 9 | generic = `item` |

Kinds are append-only per space; a server accepts any kind name of the table and refuses others
with 400 `invalid`. The plaintext payloads are the apps' business (UwUSSH's `HostPayload`,
`KeyPayload`, … unchanged). For the reserved spaces: `mail.account` is JSON with at least
`label`, `server` (URL), `email`; `generic.item` is JSON `{ "app": "<reverse-DNS app id>",
"label": "…", "data": {} }`.

### 6.2 Space objects

```json
{
  "object": "suiteSpace",
  "space": "ssh",
  "id": "3f0e…",
  "key": "2.…",
  "records": 214,
  "bytes": 98231,
  "creationDate": "…",
  "revisionDate": "…"
}
```

- `id`: chosen by the client that made the space; it is the `vault_id` in every record's AAD.
- `key`: the space key, 32 random bytes, under the extras key (EncString type 2).

**Record encryption** (unchanged for `ssh` and `rdp`, the same construction for the others):
XChaCha20-Poly1305 under the space key, a random 24-byte nonce, and as associated data
`prefix || id (16 bytes) || kind (u8) || spaceId (16 bytes) || updatedAt.wallMs (u64 BE) ||
updatedAt.counter (u32 BE) || updatedAt.device (u32 BE) || deleted (u8)`, with prefix
`"uwussh/record/v2"` (`ssh`), `"uwurdp/record/v2"` (`rdp`), `"uwulock/suite/v1"` (`mail`,
`generic`). A tombstone carries a sealed empty payload. So the server can neither read a record
nor move it, nor fake a delete.

### 6.3 Envelopes

```json
{
  "id": "9b2d…",
  "kind": "host",
  "updatedAt": { "wallMs": 1790000000000, "counter": 0, "device": 305419896 },
  "baseSeq": 0,
  "deleted": false,
  "nonce": "<base64, 24 bytes>",
  "blob": "<base64>",
  "seq": 17
}
```

Field for field UwUSync's `Envelope` (`vault_id` is implied by the space). `seq` is set by the
server (the account's change number, §4.1); `baseSeq` is what the client last saw for this id, 0
for a new one. Limits: blob ≤ 256 KiB, nonce exactly 24 bytes, id a UUID.

### 6.4 Endpoints

All take `user` (any space) or `suite` (its own space only; others are 403 `scope`).

- `GET /uwu/v1/suite/spaces` → `{ "object": "list", "data": [suiteSpace…] }`.
- `PUT /uwu/v1/suite/spaces/{space}` — make it. Body `{ "id": "<uuid>", "key": "2.…" }`. 409
  `exists` if there is one (the loser of a race fetches it). Answer: the space.
- `POST /uwu/v1/suite/spaces/{space}/rekey` — new key and id for everything, e.g. after a device
  was lost. Body `{ "id": "<new uuid>", "key": "2.…", "records": [envelope…] }`: every live record
  and tombstone, re-sealed for the new id and key, `baseSeq` = its current `seq`. One transaction;
  any missing or stale record is 409 `conflict` and nothing changes. Body limit 64 MiB. The
  space's epoch is bumped: other devices' next pull says `reset`.
- `DELETE /uwu/v1/suite/spaces/{space}` — `user` only; body `{ "masterPasswordHash": "…" }`.
  Deletes the space and all its records.
- `GET /uwu/v1/suite/spaces/{space}/records?since=<seq>&limit=<n>` — pull. `limit` default and
  maximum 500. Answer:

  ```json
  { "object": "suitePull", "reset": false, "records": [], "cursor": 181, "hasMore": false }
  ```

  Records with `seq > since`, in `seq` order, tombstones included. `reset: true` (and no
  records): `since` is older than the space's epoch or than the oldest tombstone kept (90 days);
  the client pulls again from `since=0` and merges as after a fresh install.
- `POST /uwu/v1/suite/spaces/{space}/records` — push. Body limit 8 MiB, at most 500 records:

  ```json
  { "schema": 2, "records": [envelope…] }
  ```

  Answer `{ "object": "suitePush", "accepted": [{ "id": "…", "seq": 182 }], "conflicts": [envelope…], "cursor": 182 }`.
  Exactly UwUSync's semantics: a record is accepted when `baseSeq` equals the stored `seq` (0 for
  a new id), otherwise returned in `conflicts` as the server holds it; the client merges and
  pushes again. One push is one transaction. A record id that belongs to another space or account
  is 409 `exists`. `schema` other than 2 is 400 `schema`.
- Quotas: at most `suite.maxRecords` records (default 50 000) and `suite.maxMb` MiB (default 256)
  per account across spaces, counted in the account's storage; over it, 422 `quota` and nothing
  of the push is written.

Every accepted push notifies realtime area `suite` with the space (§5); no Bitwarden push.

### 6.5 Logging in as a suite app

UwUSSH and UwURDP log in to UwULock like a Bitwarden client, as a device of the account, and get
a token that can do nothing but their space:

1. `POST /identity/accounts/prelogin` **[BW]** `{ "email" }` → KDF.
2. The app derives the master key and master password hash as Bitwarden does
   (`uwulock_core::crypto::master_key`, `master_password_hash`; the apps depend on `uwulock-core`).
3. `POST /identity/connect/token` **[BW]** form, as the password grant today, with:
   `grant_type=password`, `username=<email>`, `password=<master password hash>`,
   `scope=uwu.suite offline_access`, `client_id=uwussh` (or `uwurdp`; §6.5 table),
   `deviceType=<6 Windows | 7 macOS | 8 Linux desktop>`, `deviceIdentifier=<stable UUID per install>`,
   `deviceName=UwUSSH` (or `UwURDP`). Two-step login works as for every Bitwarden client (400 with
   `TwoFactorProviders2`, then again with `twoFactorProvider`, `twoFactorToken`,
   `twoFactorRemember`). SSO works too (§19.2), with a loopback redirect like Bitwarden's CLI.
4. The answer is Bitwarden's token response with `"scope": "uwu.suite offline_access"`; the
   access token's `scope` claim is `["uwu.suite", "offline_access"]`, its `client_id` the app's.
   `Key`, `PrivateKey` and `AccountKeys` are in it as always: the app opens the user key with the
   master key, the private key with the user key, then the extras key (`GET /uwu/v1/keys`,
   `userKeyWrapped`, or `publicKeyWrapped` with the private key and then `PUT …/user-wrap`), then
   the space key.
5. Refresh with `grant_type=refresh_token` as usual; the scope stays.

| `client_id` | space |
| --- | --- |
| `uwussh` | `ssh` |
| `uwurdp` | `rdp` |
| `uwumail` | `mail` |
| `uwusuite` | `generic` |

`scope=uwu.suite` with any other `client_id` is `{"error": "invalid_client"}`. The server stores
the `client_id` with the device; `GET /uwu/v1/devices` gets `"app": "uwussh" | … | null`, so the
web vault can show and remove suite devices. The new-device mail and security notices apply.

A `suite` token may use: `/identity/**`, `/api/accounts/prelogin`, `/uwu/v1/info`,
`GET|POST /uwu/v1/keys`, `PUT /uwu/v1/keys/user-wrap`, its space's endpoints of §6.4 except
`DELETE`, `/uwu/v1/sync?include=suite`, `/uwu/v1/realtime`. Nothing else (403 `scope`).

The app keeps the space key sealed locally as it keeps its UwUSync vault key today (DPAPI,
Keychain, Secret Service) and needs the master password again only when the refresh token has
expired, the device was removed, or the space was rekeyed.

### 6.6 Choosing the backend, and the one-click move

In UwUSSH and UwURDP, *Settings → Sync* offers **UwUSync** (as today) or **UwULock**. The sync
engine has one transport per backend; records, merge and manifests are shared.

| | UwUSync | UwULock |
| --- | --- | --- |
| Login | challenge signed by the device key | §6.5 |
| Key | vault key wrapped by the Argon2 master key | space key under the extras key |
| Pull / push | `/v1/records` | `/uwu/v1/suite/spaces/{space}/records` |
| Live | `/v1/events` (SSE) | `/uwu/v1/realtime` (`changed` with the space) |
| New device | SPAKE2 pairing | log in with the UwULock account |

**Move to UwULock** (one button, on a device that is synced with UwUSync and unlocked):

1. Log in to UwULock (§6.5); get or make the extras key (§3).
2. `GET /uwu/v1/suite/spaces`. No space yet: make a **fresh** space key and id and
   `PUT /uwu/v1/suite/spaces/{space}`. There is one (another device moved first): take it.
3. Pull everything from UwUSync (`GET /v1/records?since=0`, all pages) and open it with the
   UwUSync vault key.
4. Seal every record again for the UwULock space — same `id`, `kind`, `updatedAt` and `deleted`,
   new nonce, the space's id and key — except `manifest` records, which are per device and per
   vault and are written fresh. Push in pages of 500 with `baseSeq: 0`; conflicts (records another
   device moved already) go through the normal merge.
5. Check: pull from UwULock from `since=0` and compare ids and clocks with what was read in step 3.
   Any difference: stop, stay on UwUSync, show what differs.
6. Switch the backend setting to UwULock and forget the UwUSync session (not its data).
7. Offer to remove this device from UwUSync (`POST /v1/devices/{id}/revoke`), and, on the last
   device, say that the UwUSync account can now be deleted by its admin.

Running it again, or on another device of the same person, is safe: it merges. The copy on
UwULock shares no key with the one on UwUSync. Moving back is the apps' existing file export and
import.

The plan's "Übernahme aus der UwUSync-Datenbank" is this move. UwULock Server does not read
UwUSync's database itself: the records there are sealed with keys only the apps have, so a
server-side import would still need the app to re-key everything.

**Clients:** UwUSSH, UwURDP (backend and move), UwULock desktop and web vault (list and delete
spaces, show suite devices).

---

## 7. Icons

Order everywhere: own icon (§7.3), else automatic icon (§7.1), else the client's default glyph.

### 7.1 Automatic icons: `GET /icons/{host}/icon.png` — auth `none`

The path the official clients use for a self-hosted server (`<base>/icons/<host>/icon.png`), the
same on UwULock's clients. `host` is what the client puts there: a hostname.

- Normalize: percent-decode, lowercase, IDNA to ASCII, drop one trailing dot. Refuse (404) unless
  it matches `^[a-z0-9-]+(\.[a-z0-9-]+)+$`, is at most 253 characters, is not an IP address, and
  its last label is not one of `local`, `lan`, `home`, `internal`, `intranet`, `localhost`,
  `localdomain`, `test`, `invalid`, `example`, `onion`, `arpa`, `corp`, `private`. The server
  never asks the local network (the plan's rule): local devices get own icons.
- Answer `200` `Content-Type: image/png`, `Cache-Control: public, max-age=604800`, the PNG (at most
  64 × 64, never scaled up); or `404` with an empty body and `Cache-Control: public, max-age=86400`
  when there is none (as Bitwarden's icon service: the clients then show their glyph). Switched
  off: always 404. The global `no-store` header does not apply here.
- Rate limit: answers from the cache are free; each uncached host costs one try of a per-IP bucket
  (60, one back per second). Out of tries: 404 without caching it.
- Fetching (the server's own HTTP client; never follows the client's input anywhere but to the
  host): `https://<host>/` first, then `http://<host>/`; resolve every name, and before each
  connection check **every** resolved address: refuse loopback, private (RFC 1918), CGNAT
  100.64/10, link-local, ULA fc00::/7, multicast, unspecified, broadcast, documentation and
  benchmarking ranges, 0/8, IPv4-mapped and 6to4/Teredo forms of these; connect to the checked
  address (no second lookup, against DNS rebinding). At most 5 redirects, each checked the same
  way. Connect 5 s, whole fetch 10 s, HTML read up to 512 KiB (the `<head>` is enough), an icon
  up to 512 KiB. Candidates: `<link rel="icon" | "shortcut icon" | "apple-touch-icon" |
  "apple-touch-icon-precomposed">`, then `/favicon.ico`; the one nearest to 64 px that is at least
  32 px wins, else the largest. ICO, PNG, JPEG, GIF, WebP, SVG (rasterized) are read; the result is
  PNG. At most 8 fetches at a time server-wide, one per host.
- Cache: on disk under the data directory, keyed by SHA-256 of the host, 30 days for an icon,
  3 days for "none" (a site that could not be reached counts as "none"). The admin portal switches
  the feature and empties the cache (§21.10).
- Redirects go only to `http`/`https` on the usual ports (80, 443), never to a name that
  normalizes to nothing (local names) or an address refused above; a page's `<link>` may point to
  another host (a CDN), checked the same way. `data:` URLs in a `<link>` are read in place. A
  proxy from the environment is never used (it would resolve names past the checks). SVG is drawn
  without text, fonts or anything the file points to; files with `<!ENTITY` or more than 16
  `<use>` are refused. Raster images are decoded up to 2048 × 2048 pixels and 64 MiB.
- Log lines and metrics never name the host.

### 7.2 Icon library

The server mirrors the index of the libraries (daily, and when the admin clicks) and fetches an
icon when somebody picks it; the browser never talks to selfh.st or a CDN.

**`GET /uwu/v1/icons/library`** — auth `user`. `ETag` / `If-None-Match` (304). Gzip/brotli as
all JSON.

```json
{
  "object": "iconLibrary",
  "updated": "…",
  "sources": [
    {
      "id": "selfhst",
      "name": "selfh.st Icons",
      "url": "https://selfh.st/icons/",
      "license": "CC BY 4.0",
      "licenseUrl": "https://creativecommons.org/licenses/by/4.0/",
      "attribution": "Icons by selfh.st"
    }
  ],
  "icons": [
    { "source": "selfhst", "id": "nextcloud", "name": "Nextcloud", "variants": ["default", "light", "dark"], "aliases": [] }
  ]
}
```

Sources: selfh.st Icons first; Dashboard Icons and Simple Icons only if their licence allows it
(check before shipping, and write source and licence into the index; Simple Icons are brand marks,
so the vault shows their note). The licence strings above are what the implementer must verify
against the sources' repositories at build time, not assumptions to copy.

**`GET /uwu/v1/icons/library/{source}/{id}.png?variant=default`** — auth `user`. The icon as PNG,
128 × 128 at most, fetched on first use (SSRF rules of §7.1, from the source's fixed upstream
host only), cached on disk. `Cache-Control: private, max-age=604800`. 404 if not in the index.

The client does not link to the library icon: it downloads it, encrypts it, and stores it as an
own icon (§7.3), so the server does not learn which icon belongs to which item.

As built for 0.6: only selfh.st Icons. Its licence was checked in its repository
(`github.com/selfhst/icons`, `LICENSE`: Creative Commons Attribution 4.0 International, SPDX
`CC-BY-4.0`) on 2026-09-28. The server reads `<upstream>/index.json` (entries with `PNG: "Yes"`;
`Light`/`Dark: "Yes"` add the variants `light`/`dark`; `aliases` stays empty) and fetches icons
from `<upstream>/png/<id>[-light|-dark].png`, upstream `https://cdn.jsdelivr.net/gh/selfhst/icons@main`.
Ids are `[a-z0-9._-]{1,100}` not starting with a dot; others are left out of the index. The index
answer carries `Cache-Control: private, no-cache`; an uncached library icon costs a try of the
§7.1 per-IP bucket (429 `rate_limited`), and 502 `upstream` when the library did not answer.
Dashboard Icons and Simple Icons are not mirrored (not checked yet).

### 7.3 Own icons

A PNG of at most 128 × 128 pixels (the client resizes and converts: PNG, JPEG, WebP accepted from
the person; SVG only rasterized in the client), encrypted and stored per cipher id.

- Key: for a personal cipher, the **extras key** (`keyType: "extras"`); for an organization
  cipher, the **organization key** (`keyType: "organization"`), so every member sees it.
- Moving a cipher into an organization (`/api/ciphers/{id}/share`, `/api/ciphers/share`) deletes
  its own icon (the key no longer fits); UwULock's clients upload it again under the organization
  key after sharing.
- Deleting a cipher for good deletes its icon.

Endpoints (auth `user`; the cipher must be visible to the account and not hidden by travel mode,
§9; writing needs edit rights on it; otherwise 404):

- `PUT /uwu/v1/icons/own/{cipherId}` — body `{ "data": "2.…", "keyType": "extras" }`. `data` is
  an EncString type 2 of the PNG bytes, at most 96 KiB as text (413 `too_large`). `keyType` must
  match the cipher (400 `invalid`). Answer `{ "object": "ownIcon", "cipherId", "keyType",
  "revisionDate" }`. Notify: `CipherUpdate` for the cipher is **not** sent (official clients do not
  care); realtime area `uwu`.
- `GET /uwu/v1/icons/own/{cipherId}` → `{ "object": "ownIcon", "cipherId", "keyType", "data", "revisionDate" }`.
- `POST /uwu/v1/icons/own/get` — body `{ "cipherIds": ["…"] }`, at most 500 → list of `ownIcon`
  (those that exist and are visible).
- `GET /uwu/v1/icons/own` → list of `ownIcon` **without** `data` for every item the account sees
  (added for the web vault, which uses `/api/sync` and not `uwu.icons` of §4.4).
- `PUT` for a personal item counts toward `storagePerUserMb` (422 `quota`); the answer has no
  `data`.
- `DELETE /uwu/v1/icons/own/{cipherId}` → 200.

Which ciphers have one comes with the sync (`uwu.icons`, §4.4).

Icons of **local addresses** (private IPs, `.local`, `.lan`, dotless names): the web vault and
UwULock desktop fetch `http(s)://<device>/favicon.ico` (and the page's `<link rel=icon>`) from the
person's own device, and store the result as an own icon. In the browser this often fails
(mixed content, CORS); then the desktop app or a manual upload does it. No server endpoint.

**Clients:** official clients and all of ours: §7.1. Web vault, UwULock desktop, extension: §7.2
(web vault and desktop) and §7.3 (all three).

---

## 8. Entry versions

The server keeps the previous encrypted state of a cipher whenever it changes, so an old password
or note can be brought back. Attachments are not versioned.

### 8.1 What makes a version

A version is written (in the same transaction as the change) when a cipher's encrypted content
changes through:

- **[BW]** `PUT|POST /api/ciphers/{id}`, `PUT|POST /api/ciphers/{id}/admin`;
- **[UwU]** a restore (§8.4): the state being replaced becomes a version.

Not versioned: `PUT /api/ciphers/{id}/partial` (folder, favorite), archive, trash and restore from
trash, collection changes, attachments, imports, creation. A change whose content is byte-for-byte
the same as before writes nothing.

The version holds the cipher's encrypted content as the cipher JSON has it: `type`, `name`,
`notes`, `key`, `login`, `card`, `identity`, `secureNote`, `sshKey`, `fields`,
`passwordHistory`, `reprompt`, and the `revisionDate` that state had. Not folder, favorite,
collections, attachments.

### 8.2 Retention

- Admin settings (§21): `versions.perItem` (default 20, 0 switches versions off, at most 100) and
  `versions.days` (default 365, 0 = no limit). Oldest first out; pruned at write and daily.
- Versions count toward the storage of the cipher's owner (the organization's for organization
  ciphers).
- A cipher deleted for good loses its versions. Sharing a personal cipher into an organization
  deletes its versions (their key does not fit the organization).
- An official client's key rotation deletes all **personal** versions (§3); UwULock's rotation
  re-encrypts them.

### 8.3 Who may

Personal cipher: its owner. Organization cipher: members who may edit it (not `readOnly`, not
`hidePasswords`). Travel mode hides the versions of hidden ciphers. Anything else: 404.

### 8.4 Endpoints

- `GET /uwu/v1/ciphers/{cipherId}/versions` → list, newest first:

  ```json
  {
    "object": "list",
    "data": [
      {
        "object": "cipherVersion",
        "id": "7f1c…",
        "cipherId": "…",
        "revisionDate": "2026-09-01T10:00:00.000000Z",
        "replacedDate": "2026-09-20T08:30:00.000000Z",
        "size": 1834,
        "cipher": { "type": 1, "name": "2.…", "notes": null, "key": null, "login": {}, "card": null, "identity": null, "secureNote": null, "sshKey": null, "fields": [], "passwordHistory": [], "reprompt": 0 }
      }
    ],
    "continuationToken": null
  }
  ```

  `cipher` uses the same keys and encodings as the cipher in `/api/sync`. Both the version and its
  `cipher` also carry `organizationId` (null for a personal item), so a client knows the key.
- `GET /uwu/v1/ciphers/{cipherId}/versions/{versionId}` → one `cipherVersion`.
- `POST /uwu/v1/ciphers/{cipherId}/versions/{versionId}/restore` — body
  `{ "lastKnownRevisionDate": "<the cipher's current revisionDate>" }`; a different date is 409
  `conflict`. The version's content replaces the cipher's (the current content becomes a version),
  the cipher gets a new `revisionDate`. Answer: **[BW]** the cipher exactly as `PUT /api/ciphers/{id}`
  answers. Notify `CipherUpdate` (and realtime `vault`).
- `DELETE /uwu/v1/ciphers/{cipherId}/versions/{versionId}` and
  `DELETE /uwu/v1/ciphers/{cipherId}/versions` → 200.

### 8.5 For a key rotation

`GET /uwu/v1/versions?scope=personal` → list of every personal `cipherVersion` of the account (no
paging; the rotation needs all). The client re-encrypts each `cipher` (its `key`, or its fields if
it has none) for the new user key and sends them in `POST /uwu/v1/accounts/rotate-keys` (§3).

**Clients:** web vault, UwULock desktop (list, compare, restore; rotation).

---

## 9. Travel mode

Folders marked "hide when travelling"; with the mode on, the server leaves their ciphers out of
everything, and the official clients drop them locally at their next sync.

### 9.1 Endpoints

- `GET /uwu/v1/travel` — auth `user`:

  ```json
  { "object": "travelMode", "enabled": false, "enabledDate": null, "folderIds": ["…"], "hiddenCount": 0 }
  ```

  `hiddenCount`: ciphers currently hidden (0 while off).
- `PUT /uwu/v1/travel/folders` — auth `user`. Body `{ "folderIds": ["…"] }`, the full set; only
  the account's own folders (400 `invalid` otherwise). While the mode is on, folders may be added
  but not removed (400 `travel_active`). Adding a folder while on bumps the sync epoch.
- `POST /uwu/v1/travel/enable` — auth `user`, body `{}`. Needs at least one marked folder (400
  `no_folders`) and two-step login set up on the account (400 `two_factor_required`, since the
  second factor is what switching off asks for).
- `POST /uwu/v1/travel/disable/send-email` — auth `user`, body `{ "masterPasswordHash": "…" }`:
  mails a code, for accounts with the e-mail provider.
- `POST /uwu/v1/travel/disable/webauthn-challenge` — auth `user`, body
  `{ "masterPasswordHash": "…" }` → the assertion options, the same JSON the login's WebAuthn step
  gets in `TwoFactorProviders2["7"]`.
- `POST /uwu/v1/travel/disable` — auth `user`:

  ```json
  { "masterPasswordHash": "…", "twoFactorProvider": 0, "twoFactorToken": "123456" }
  ```

  `twoFactorProvider` as Bitwarden numbers them: 0 authenticator, 1 e-mail, 7 WebAuthn (token = the
  assertion JSON as the login sends it). The recovery code is not accepted. Wrong password or code:
  400 `invalid`; both are counted per account (5 tries, one back every 3 minutes; then 429) and
  a failure writes security notice `travelDisableFailed`. `twoFactorToken` may also be sent as a
  JSON object (the assertion itself). A wrong password on `send-email` and `webauthn-challenge`
  counts and is noticed the same way; both answer 400 `invalid` while the mode is off, and
  `send-email` 400 `invalid` without two-step login by mail (or without a mail server).
  When the account has no usable second step any more (the recovery code was used, an admin
  reset it), the master password alone switches the mode off — otherwise nothing ever could;
  `twoFactorProvider`/`twoFactorToken` are then ignored. `GET /uwu/v1/versions` leaves out the
  versions of hidden items.

Switching on or off: sync epoch bumped (§4.3), the account's revision date bumped, notify
`SyncVault` (Bitwarden `PushType` 5) to all devices including the one that did it, security
notice `travelModeEnabled` / `travelModeDisabled` (mail).

### 9.2 What is hidden while it is on

For the account in travel mode, a cipher is **hidden** if it is personal and in a marked folder,
or an organization cipher the account has put into a marked folder (its per-user folder). Hidden
ciphers, their attachments, own icons, versions and reminders are left out of, or 404 in:

`/api/sync`, `/api/ciphers`, `/api/ciphers/{id}` and all its sub-paths (details, attachments,
downloads), `/api/ciphers/organization-details` rows *for this account*, `/uwu/v1/sync`,
`/uwu/v1/ciphers/{id}/versions`, `/uwu/v1/icons/own/*`, `/uwu/v1/reminders`, and emergency access
views and takeover of this account's vault.

Writes to a hidden cipher are 404 as well. Moving a visible cipher into a marked folder hides it.

The marked folders themselves are hidden too while the mode is on (left out of `/api/sync` and
`/api/folders`; renaming or deleting one answers as for a folder that does not exist), so their
names do not show either. `PUT /uwu/v1/travel/folders` still takes their ids. While it is on,
`POST /api/ciphers/purge` and both key rotations (§3) answer 400 `travel_active`; download links
of a hidden item's attachments issued before stop working.
Organization-wide views of admins (`/api/ciphers/organization-details` as an organization admin,
organization export) are organization data and are not filtered.

**Clients:** web vault (marks, switches), UwULock desktop (switches, shows state); official
clients only see the effect.

---

## 10. Password renewal reminders

The server knows only cipher id and date; the mail names no item.

- `GET /uwu/v1/reminders` — auth `user`:

  ```json
  {
    "object": "list",
    "data": [
      { "object": "reminder", "cipherId": "…", "due": "2027-01-15", "everyMonths": 6, "isDue": false, "mailedDate": null }
    ],
    "continuationToken": null
  }
  ```
- `PUT /uwu/v1/reminders/{cipherId}` — body `{ "due": "YYYY-MM-DD" | null, "everyMonths": 1–60 | null }`,
  at least one of them. Only `everyMonths`: `due` = the login's `passwordRevisionDate` (else the
  cipher's `creationDate`) plus that many months. The cipher must be visible to the account (404).
  Answer: the reminder.
- `DELETE /uwu/v1/reminders/{cipherId}` → 200.

Rules:

- Reminders are per account; for an organization cipher, each member has their own.
- When a cipher's `login.passwordRevisionDate` (stored unencrypted in the cipher, as Bitwarden's)
  moves forward: with `everyMonths`, `due` becomes the new date plus the months; with a fixed date
  only, and the date passed, the reminder is deleted.
- A job runs hourly. A reminder with `due` ≤ today (UTC) is `isDue`; once per due date, one mail
  per account for all that became due ("An item in your vault is due for a new password"), with a
  link to `<public>/#/vault?due=1`. No mail without a mail server; hidden (travel) reminders are
  skipped. Realtime `notice` `reminderDue` (with the realtime channel, Stufe 6). Setting a reminder
  also works for organization items the account may only read. `due` in the past is allowed (the
  item is due at once).
- Deleting the cipher for good deletes its reminder.

**Clients:** web vault, UwULock desktop (set, list, mark due items).

---

## 11. File requests

Sends in the other direction: the owner makes a link, somebody without an account uploads files
and text to it. Encrypted in the uploader's browser for the owner's RSA public key; the server
stores only ciphertext. Mail to the owner when something arrives; the owner reads it, and takes
it over into an item, in the web vault or UwULock desktop (the official clients do not know it).

### 11.1 The link and what it carries

The owner's client makes a **link secret** `s`: 16 random bytes. From it:

- `linkKey = derive_shareable_key(s, "filerequest", "filerequest")` (§1.4; HKDF-SHA256, salt
  `"bitwarden-filerequest"`, info `"filerequest"`, 64 bytes).
- `publicInfo` = EncString type 2 under `linkKey` of the UTF-8 JSON

  ```json
  { "v": 1, "title": "Passport scan", "note": "Please upload both pages.", "publicKey": "<base64 of the owner's RSA public key, SPKI DER>", "owner": "Lorin" }
  ```

  `note` and `owner` may be `null`. `publicKey` is the account's public key as the owner's client
  has it (from its token response), **not** as the server hands it out later: the uploader's page
  takes the key it encrypts for from this authenticated blob, so the server cannot swap in a key
  of its own without the link secret (it could only break the link).
- Optional password: `passwordHash = base64(PBKDF2-HMAC-SHA256(password, salt = s, 100 000
  rounds, 32 bytes))`, the same construction as a Send's (`send_password_hash` with `s` as the
  seed). The server stores Argon2id of it, as for Sends.

The **link**, `accessId` = base64url without padding of the request id's 16 bytes (as for Sends),
`secret` = base64url without padding of `s`:

- main host: `https://lock.example.com/#/request/<accessId>/<secret>`
- a send domain (§14): `https://send.example.com/r/<accessId>#<secret>`

The secret is always after `#`, so it never reaches the server.

For the owner the client also stores, under the **extras key** (§3): `name` (the owner's label,
e.g. "Passport for the bank") and `linkSecret` (EncString type 2 of `s`), so the owner can show
the link again. So file requests survive any key rotation that keeps the key pair (§3).

### 11.2 The envelope of a submission

The uploader's page (web vault code, on either host) does, per submission:

1. Makes `K`: 64 random bytes (32 AES key, 32 HMAC key).
2. `wrappedKey = "4." + base64(RSA-OAEP(SHA-1, MGF1-SHA-1)(publicKey, K))` — EncString type 4,
   exactly like `uwulock_core::crypto::wrap_for` (Bitwarden's organization-key wrapping).
3. `text` (optional): EncString type 2 under `K` of the UTF-8 message, at most 100 000 characters
   before encryption.
4. `sender` (optional): EncString type 2 under `K` of the UTF-8 JSON `{ "name": "…", "email": "…" }`
   as the uploader typed it (unverified; the owner's client says so).
5. Per file: `Kf`, 64 random bytes; `key` = EncString type 2 of `Kf` under `K`; `fileName` =
   EncString type 2 of the UTF-8 file name under `K`; the contents as an **EncArrayBuffer** under
   `Kf` (§1.4); `size` = the byte length of that EncArrayBuffer.

The owner opens it with the private key (which the user key opens): `wrappedKey` → `K` → text,
sender, file names, file keys → files. A file has its own key so that taking it into an item
(§11.4) only re-wraps `Kf` and the name for the item; the bytes on disk stay as they are, like a
Bitwarden attachment (whose `key` is the attachment key under the item key).

### 11.3 Public endpoints — auth `none` / `link`

Answered on the main host and on every send domain. All errors on unknown, expired, disabled or
full requests are the same 404 `gone`, so a link cannot be probed.

- `GET /uwu/v1/public/file-requests/{accessId}` → `{ "object": "fileRequestAccess", "passwordRequired": true }`.
- `POST /uwu/v1/public/file-requests/{accessId}/open` — body `{ "passwordHash": null | "…" }`:

  ```json
  {
    "object": "fileRequestOpen",
    "publicInfo": "2.…",
    "token": "<upload token>",
    "expiresIn": 3600,
    "expirationDate": "…",
    "maxFiles": 10,
    "maxFileBytes": 104857600,
    "textAllowed": true
  }
  ```

  400 `password_required` / `password_invalid`. Wrong passwords count per request (10, one back
  per minute) and per IP (`limits.anonymous`); then 429. The token is a `link` token (issuer suffix
  `|filerequest`, subject the request id, one hour); it may start several submissions, bounded by
  the request's limits.
- `POST /uwu/v1/public/file-requests/{accessId}/submissions` — `Authorization: Bearer <upload token>`:

  ```json
  {
    "wrappedKey": "4.…",
    "sender": "2.…",
    "text": "2.…",
    "files": [ { "fileName": "2.…", "key": "2.…", "size": 204849 } ]
  }
  ```

  Checks: at least a text or a file; `text` only if `textAllowed`; at most `maxFiles` files; each
  `size` at most `maxFileBytes + 65` (the EncArrayBuffer's header and padding); submissions left;
  the owner's storage (422 `quota`); per IP 10 submissions an hour (429). Answer:

  ```json
  {
    "object": "fileRequestSubmissionStarted",
    "id": "<submission id>",
    "files": [ { "id": "<file id>", "url": "/uwu/v1/public/file-requests/<accessId>/submissions/<id>/files/<file id>" } ]
  }
  ```
- `PUT <file url>` — `Authorization: Bearer <upload token>`, body `application/octet-stream`,
  exactly `size` bytes, first byte `0x02` (checked while streaming: more is 413 `too_large`, less
  400 `incomplete`). No body limit but this one (upload router). May be repeated until the
  submission is complete.
- `POST /uwu/v1/public/file-requests/{accessId}/submissions/{id}/complete` — same token. 400
  `incomplete` while a file is missing. Then the submission is visible to the owner: the request's
  `submissionCount` goes up (a full request closes), realtime `notice` `fileRequest` to the owner,
  and a mail ("Something arrived for one of your file requests", link to
  `<public>/#/file-requests/<request id>`), at most one per request per 15 minutes.

Submissions not completed within 24 hours are deleted with their files.

Also answered: `POST …/submissions` 401 `unauthorized` without a valid upload token (the page
opens the link again), 413 `too_large` for a file above `maxFileBytes + 65`, 400 `invalid` for
anything not of the form above; `PUT <file url>` 400 `invalid` when the first byte is not `0x02`.
The upload token of one request does not open another (404 `gone`). The main host serves the page
at `GET /r/<accessId>` too, the path a send domain's link has (§14.1).

### 11.4 Owner endpoints — auth `user`

The request object:

```json
{
  "object": "fileRequest",
  "id": "…",
  "accessId": "…",
  "name": "2.…",
  "linkSecret": "2.…",
  "publicInfo": "2.…",
  "passwordSet": false,
  "expirationDate": "…",
  "deletionDate": "…",
  "maxSubmissions": 1,
  "submissionCount": 0,
  "maxFiles": 10,
  "maxFileBytes": 104857600,
  "textAllowed": true,
  "sendDomainId": null,
  "disabled": false,
  "unseen": 0,
  "bytes": 0,
  "creationDate": "…",
  "revisionDate": "…"
}
```

- `GET /uwu/v1/file-requests` → list; `GET /uwu/v1/file-requests/{id}` → one.
- `POST /uwu/v1/file-requests` — body: `name`, `linkSecret`, `publicInfo`, `passwordHash`
  (or `null`), `expirationDate` (one hour to `fileRequests.maxDays` days ahead, default 7 days in
  the clients), `maxSubmissions` (1–100 or `null` for "until it expires"), `maxFiles` (0–20, and
  at most the admin's limit), `maxFileBytes` (at most the server's file limit), `textAllowed`,
  `sendDomainId` (§14; only for the link the clients show), `disabled`. At most
  `fileRequests.perUser` (default 50) requests per account (422 `quota`). Answer: the request.
- `PUT /uwu/v1/file-requests/{id}` — the same body; `passwordHash` left out keeps the password,
  `"removePassword": true` removes it. A new `linkSecret`/`publicInfo` makes old links useless
  (the way to withdraw a link).
- `DELETE /uwu/v1/file-requests/{id}` — the request, its submissions and files.
- `deletionDate` = `expirationDate` + 30 days: then the server deletes the request with
  everything in it. The web vault says so.
- `GET /uwu/v1/file-requests/{id}/submissions` → list of

  ```json
  {
    "object": "fileRequestSubmission",
    "id": "…",
    "requestId": "…",
    "creationDate": "…",
    "wrappedKey": "4.…",
    "sender": "2.…",
    "text": "2.…",
    "files": [ { "id": "…", "fileName": "2.…", "key": "2.…", "size": 204849 } ],
    "seen": false
  }
  ```
- `GET /uwu/v1/file-requests/{id}/submissions/{sid}/files/{fid}` → the EncArrayBuffer,
  `application/octet-stream`.
- `POST /uwu/v1/file-requests/{id}/submissions/{sid}/seen` → 200.
- `DELETE /uwu/v1/file-requests/{id}/submissions/{sid}` → 200.
- `POST /uwu/v1/file-requests/{id}/submissions/{sid}/files/{fid}/attach` — take a file into an
  item. Body `{ "cipherId": "…", "fileName": "2.…", "key": "2.…" }`: the file name and `Kf`, both
  under the item's key (the cipher's `key` if it has one, else the user or organization key), as
  for a Bitwarden attachment. The server moves the file into the item's attachments (no second
  upload), removes it from the submission, counts it to the item owner's storage. The cipher must
  be editable by the account (404). Answer: **[BW]** the cipher as after an attachment upload.
  Notify `CipherUpdate`.

"Take over as an item" in the clients: create the item with Bitwarden's API (e.g. a secure note
with the text), then `attach` each file, then delete the submission.

Checks on the owner's side: `name`, `linkSecret` (at most 4000 characters) and `publicInfo` (at
most 20 000) must be EncStrings of type 2 (400 `invalid`); `maxFileBytes` is ignored when
`maxFiles` is 0, and then `textAllowed` must be true. `GET` lists newest first; `unseen` counts
completed submissions not marked seen, `bytes` the files (those still arriving included).
`attach` answers 404 `not_found` for an item the account may not change. The files lie at
`file-requests/<request id>/<file id>` in the data directory and are part of the off-site
backups (§21.2). With `fileRequests.enabled` off, every endpoint here and in §11.3 answers 404
`feature_off`.

**Clients:** web vault (owner pages; the public upload page on the main host and send domains),
UwULock desktop (owner side: list, open, take over).

---

## 12. Security notices

What happened on the account, for *Settings → Security* in the web vault and a mail in the
account's language. The Stufe 5 event log builds on the same table.

### 12.1 Kinds

| `kind` | When | `detail` |
| --- | --- | --- |
| `failedLogins` | 3 or more wrong master passwords for the account within 15 minutes | `{ "count": 5 }` |
| `failedTwoFactor` | 3 or more wrong second-step codes within 15 minutes | `{ "count": 3, "provider": 0 }` |
| `newDevice` | a device logs in for the first time (today's mail, now also listed) | `{ "app": null }` |
| `passwordChanged`, `emailChanged`, `kdfChanged`, `keysRotated` | the account's credentials changed | `{}` |
| `twoFactorEnabled`, `twoFactorDisabled` | a provider switched | `{ "provider": 0 }` |
| `apiKeyCreated`, `apiKeyRotated` | Bitwarden's personal API key | `{}` |
| `maskedApiKeyCreated` | §13.6 | `{ "name": "Firefox" }` |
| `emergencyAccessRequested`, `emergencyAccessTakenOver` | §4 emergency access | `{ "grantee": "a@example.com" }` |
| `loginWithDeviceRequested` | a "log in with device" request | `{ "approved": null }` |
| `vaultExported` | reported by a client (§12.2) or by Bitwarden's event 1007 | `{ "format": "json" }` |
| `travelModeEnabled`, `travelModeDisabled`, `travelDisableFailed` | §9 | `{}` |
| `extrasKeyReset` | §3 | `{}` |
| `kdfBelowMinimum` | §20 | `{}` |
| `ssoLinked` | an SSO identity was linked to the account for the first time (§19) | `{ "issuer": "https://auth.example.com" }` |
| `maskedConnected`, `maskedDisconnected` | §13 | `{ "server": "https://mail.example.com" }` |

Every notice has the time, the client IP, and the device (name, type, app) where there is one.

**Mails:** collected per account for 5 minutes after the first notice, then one mail listing all
of them (failed attempts summed); at most one mail per account per 15 minutes, the rest goes into
the next. `emailChanged` also goes to the old address, at once. Notices whose event has its own
mail already — `newDevice` (as before, governed by the `newDeviceMail` setting too), the
emergency access mails, `twoFactorDisabled` by the recovery code — are listed with `mailed: true`
and not bundled again. The admin switches kinds off for mail
(`securityNotices.mailOff`, §21); they stay in the list. Without a mail server: list only.
Kept 180 days.

### 12.2 Endpoints — auth `user`

- `GET /uwu/v1/security/notices?continuationToken=&limit=50` →

  ```json
  {
    "object": "list",
    "data": [
      {
        "object": "securityNotice",
        "id": "1042",
        "kind": "failedLogins",
        "date": "…",
        "ip": "203.0.113.7",
        "deviceType": 9,
        "deviceName": "chrome",
        "app": null,
        "detail": { "count": 5 },
        "mailed": true,
        "seen": false
      }
    ],
    "continuationToken": "1000",
    "unseen": 1
  }
  ```

  Newest first. `id` is a string (a number today).
- `POST /uwu/v1/security/notices/seen` — body `{ "upToId": "1042" }`: this one and all older are
  seen.
- `POST /uwu/v1/security/notices/report` — body `{ "kind": "vaultExported", "detail": { "format": "json" | "encrypted_json" | "csv" } }`.
  Only `vaultExported` can be reported; 10 an hour per account.
- **[BW]** `POST /events/collect` (today a no-op): an event with `type: 1007`
  (`User_ClientExportedVault`) from an official client becomes `vaultExported`; everything else
  stays ignored.

**Clients:** web vault (list, badge), UwULock desktop (badge, report exports), extension (report
exports if it can export).

---

## 13. Masked addresses

UwULock Server creates masked addresses for an account at UwUMail Server, through UwUMail's JMAP
`MaskedEmail` (see UwUMail's `docs/jmap-masked-email.md`), with an OAuth grant the person gives
once. The refresh token lives encrypted on the Lock server (not in the vault), so the official
Bitwarden clients can create addresses too, through an addy.io- or SimpleLogin-compatible API.

### 13.1 UwUMail side: the `maskedemail` scope (built in UwUMail-Server)

UwUMail's OAuth scope `mail` opens the whole mailbox. New scope **`maskedemail`** (one word like
`mail`, `smtp`, `dav`; named after the JMAP capability's last segment):

- listed in `scopes_supported` of `/.well-known/oauth-authorization-server`;
- consent text: "*<client name>* wants to create and manage your masked addresses. It cannot read
  or send your mail.";
- a token whose scopes include `maskedemail` but not `mail` is accepted **only** on:
  `/.well-known/jmap` and `/jmap/session` (the session then lists only the capabilities
  `urn:ietf:params:jmap:core` and `https://www.fastmail.com/dev/maskedemail`, the account with
  only the latter in `accountCapabilities` — including UwUMail's `{ domains, defaultDomain }` — and
  `primaryAccounts` only for it); `/jmap/api` for `Core/echo` and `MaskedEmail/get`, `/set`,
  `/changes` (any other method is the JMAP method error `forbidden`); `/jmap/eventsource` and
  `/jmap/ws` for `MaskedEmail` state changes only. Everything else — IMAP, SMTP submission, Sieve,
  DAV, JMAP upload/download, the portal API — refuses it;
- `mail` keeps including everything it includes today (masked addresses too);
- refresh tokens keep rotating on every use with a fresh 90-day lifetime, so a connection that is
  used at least every 90 days never expires; reusing an old refresh token ends the grant (as today);
- `MaskedEmail` objects created through such a token get `createdBy: "OAuth:<client name>"`
  (today `JMAP` or `Portal`); the portal shows it;
- the grant appears under *My account → Security → Apps signed in with OAuth* like any other and
  can be signed out there.

### 13.2 Connecting — auth `user` (web vault only)

The admin lists the UwUMail servers the Lock server may talk to (§21.8). The Lock server talks
only to those origins, follows no redirects, and uses only endpoints on the same origin as the
server's discovery document. Admin-listed servers may be on private addresses (the admin trusts
them); nothing else may.

1. `POST /uwu/v1/masked/connect` — body `{ "server": "https://mail.example.com" }` (must be listed:
   403 `server_not_allowed`). The Lock server:
   - reads `<server>/.well-known/oauth-authorization-server` (its `issuer` is remembered, and
     `maskedemail` must be in `scopes_supported`, else 502 `upstream`);
   - registers itself once per UwUMail server (RFC 7591 `POST <registration_endpoint>`,
     `{ "client_name": "UwULock (lock.example.com)", "redirect_uris": ["https://lock.example.com/uwu/v1/masked/callback"] }`)
     and keeps the `client_id`; on `invalid_client` later it registers again (UwUMail forgets unused
     clients after 7 days);
   - makes a PKCE verifier (32 random bytes, base64url), a `state` (32 random bytes, base64url)
     and a browser binding (32 random bytes), stores `{ sha256(state) → account, server, verifier,
     sha256(binding), expires in 10 minutes }`;
   - answers `{ "object": "maskedConnect", "authorizeUrl": "<authorization_endpoint>?response_type=code&client_id=…&redirect_uri=https%3A%2F%2Flock.example.com%2Fuwu%2Fv1%2Fmasked%2Fcallback&scope=maskedemail&state=…&code_challenge=…&code_challenge_method=S256&prompt=consent" }`
     and sets the cookie `__Host-uwu-masked=<binding>; Secure; HttpOnly; SameSite=Lax; Path=/;
     Max-Age=600`.
2. The web vault navigates the tab to `authorizeUrl`; the person logs in at UwUMail and agrees.
3. `GET /uwu/v1/masked/callback?code=…&state=…&iss=…` (or `?error=…&state=…`) — auth: the state
   and the binding cookie (both must match; state single-use). `iss` must equal the remembered
   issuer (RFC 9207). The Lock server exchanges the code (`grant_type=authorization_code`, `code`,
   `redirect_uri`, `client_id`, `code_verifier`), reads `/jmap/session` with the access token
   (account id from `primaryAccounts["https://www.fastmail.com/dev/maskedemail"]`, `username`,
   domains and default domain), stores the connection, deletes the cookie, writes notice
   `maskedConnected`, and answers `303` to `<public>/#/settings/masked?result=connected` or
   `?result=error&reason=denied|expired|invalid_state|upstream`.

Tokens at rest: access and refresh token encrypted with AES-256-GCM under a server secret kept in
a file in the data directory (made on first use, mode 0600, part of every backup of §21.2), with
the account id and server as associated data. Never logged.

Refreshing: one refresh at a time per connection (a lock), and the rotated refresh token is
written to the database **before** the new access token is used — UwUMail ends the grant when an
old refresh token comes again. `invalid_grant` on refresh: the connection's `status` becomes
`revoked`.

- `GET /uwu/v1/masked/connection` →

  ```json
  {
    "object": "maskedConnection",
    "connected": true,
    "server": "https://mail.example.com",
    "username": "lorin@example.com",
    "domains": ["example.com", "masked.example.com"],
    "defaultDomain": "masked.example.com",
    "status": "ok",
    "connectedDate": "…",
    "lastUsedDate": "…",
    "allowedServers": [ { "url": "https://mail.example.com", "name": "UwUMail" } ]
  }
  ```

  `status`: `ok`, `revoked` (connect again), `unreachable` (last call failed). Not connected:
  `connected: false` and the rest `null`, `allowedServers` filled.
- `DELETE /uwu/v1/masked/connection` → revokes at UwUMail (`POST <revocation_endpoint>` with the
  refresh token and `client_id`, best effort), deletes it here, notice `maskedDisconnected`.
  Addresses stay at UwUMail.

### 13.3 Addresses — auth `user`

Without a connection: 409 `not_connected`; with `status: revoked`: 409 `revoked`. UwUMail
unreachable: 502 `upstream`. UwUMail's `invalidProperties`: 400 `invalid` with its description;
`forbidden`: 403; its 5000-address limit: 422 `quota`. Per account 30 creations a minute and 500 a
day (429).

```json
{
  "object": "maskedAddress",
  "id": "x42",
  "email": "quiet.otter17@masked.example.com",
  "state": "enabled",
  "forDomain": "https://shop.example.com",
  "description": "Shop",
  "url": "https://lock.example.com/#/vault?itemId=…",
  "createdAt": "…",
  "lastMessageAt": null,
  "createdBy": "OAuth:UwULock (lock.example.com)",
  "cipherId": "…"
}
```

- `GET /uwu/v1/masked/addresses[?cipherId=…]` → list (UwUMail's `MaskedEmail/get` with
  `ids: null`, joined with the links kept here).
- `POST /uwu/v1/masked/addresses` — body
  `{ "forDomain": "https://shop.example.com", "description": "", "domain": null, "emailPrefix": null, "cipherId": null }`
  → `MaskedEmail/set` `create` with `state: "enabled"` (not `pending`: an address in a password
  manager must not vanish after 24 hours without mail), the chosen `domain` (UwUMail's default
  when `null`), and `url` = `<public>/#/vault?itemId=<cipherId>` when a cipher is named. Answer: the
  address.
- `PATCH /uwu/v1/masked/addresses/{id}` — any of `{ "state": "enabled" | "disabled" | "deleted", "description", "forDomain", "cipherId" }`;
  a new `cipherId` (or `null`) also sets (or clears) `url` at UwUMail.
- `DELETE /uwu/v1/masked/addresses/{id}` → `state: "deleted"` (UwUMail never reuses it; mail to it
  is refused).

Links: the Lock server keeps `(account, masked id, cipher id)`, at most one address per cipher and
one cipher per address; the cipher must be visible to the account. Deleting a cipher for good
removes its link; the web vault asks first whether to switch the address off (default: yes,
`disabled`, not deleted). The links come with the sync (`uwu.maskedLinks`, §4.4) so a client
shows "masked address" at an item without asking UwUMail.

### 13.4 addy.io-compatible endpoint (for the official clients) — auth `masked-key`

In the official clients' generator: *Username → Forwarded email alias → addy.io*, "Self-host
server URL" `https://lock.example.com/uwu/v1/masked/addy`, API token = a key of §13.6, domain =
one of the UwUMail domains. The web vault's masked-address page shows both values to copy.

**[BW]** What the clients send (`libs/tools/generator/core/src/integration/addy-io.ts`,
`engine/rpc/create-forwarding-address.ts`; mobile: `sdk-internal`
`crates/bitwarden-generators/src/username_forwarders/addyio.rs`):

```
POST /uwu/v1/masked/addy/api/v1/aliases
Authorization: Bearer <key>
Content-Type: application/json
Accept: application/json
X-Requested-With: XMLHttpRequest          (mobile only)

{ "domain": "masked.example.com", "description": "Website: shop.example.com. Generated by Bitwarden." }
```

- Also accept the path with a doubled slash (`/uwu/v1/masked/addy//api/v1/aliases`): the clients
  append `/api/…` to whatever base the person typed.
- `domain` equal (case-insensitively) to one of the connection's domains: that one. Anything else
  (the web clients refuse an empty field, so people type something): UwUMail's default domain.
- `forDomain`: the web clients localize the description, the SDK writes English. Take the text
  after `Website: ` up to `. ` if present, else the first token of the description that is a
  hostname (`[a-z0-9-]+(\.[a-z0-9-]+)+`); as `https://<host>`; none: `""`. `description` is kept as
  sent, cut to 200 characters.
- `state: "enabled"`, no cipher link.
- Answer **201**, `Content-Type: application/json`. The clients read only `data.email`:

  ```json
  { "data": { "id": "x42", "user_id": "<account id>", "local_part": "quiet.otter17", "domain": "masked.example.com", "email": "quiet.otter17@masked.example.com", "active": true, "description": "Website: shop.example.com. Generated by Bitwarden.", "created_at": "2026-09-28 12:00:00", "updated_at": "2026-09-28 12:00:00" } }
  ```

### 13.5 SimpleLogin-compatible endpoint — auth `masked-key`

Generator service *SimpleLogin*, "Self-host server URL"
`https://lock.example.com/uwu/v1/masked/simplelogin`, API key = a key of §13.6.

**[BW]** (`simple-login.ts`; SDK `simplelogin.rs`):

```
POST /uwu/v1/masked/simplelogin/api/alias/random/new?hostname=shop.example.com
Authentication: <key>
Content-Type: application/json
Accept: application/json

{ "note": "Website: https://shop.example.com/login. Generated by Bitwarden." }
```

- The header is `Authentication` (no `Bearer`). `hostname` is not URL-encoded by the clients and
  may be a whole URL (SDK); take its host. `forDomain` = `https://<host>`, or from the note as in
  §13.4 when there is no `hostname`. Domain: UwUMail's default. `description` = the note, cut to 200.
- Also accept the doubled slash.
- Answer **201**; the clients read only `alias`:

  ```json
  { "alias": "quiet.otter17@masked.example.com", "email": "quiet.otter17@masked.example.com", "enabled": true, "note": "…", "creation_timestamp": 1790000000 }
  ```

### 13.6 Errors of §13.4/§13.5, and the keys

Errors are JSON `{ "error": "<short>", "message": "<readable>" }` (the web clients show
`error: message`; the SDK shows only the status), never a redirect:

| Status | When |
| --- | --- |
| 401 | no key, unknown or deleted key |
| 403 | not connected, connection revoked, feature off, UwUMail refused (`forbidden`, limit) |
| 429 | 30 a minute / 500 a day per key; wrong keys count per IP like logins |
| 502 | UwUMail unreachable |

The message says what to do ("Connect UwUMail in the web vault under Settings → Masked
addresses."). CORS: the existing middleware answers preflights on these paths for the allowed
origins (the Bitwarden desktop app's `bw-desktop-file://bundle`); extensions and apps need none.

**Keys** (auth `user`):

- `GET /uwu/v1/masked/api-keys` → list of `{ "object": "maskedApiKey", "id", "name", "hint": "…3fQa", "creationDate", "lastUsedDate" }`.
- `POST /uwu/v1/masked/api-keys` — body `{ "name": "Firefox", "masterPasswordHash": "…" }` →
  the object plus `"key": "uwulock_ma_<id base64url>_<32 random bytes base64url>"`, shown once;
  stored as SHA-256, compared in constant time. At most 10 per account (422 `quota`). Notice
  `maskedApiKeyCreated`.
- `DELETE /uwu/v1/masked/api-keys/{id}` → 200.

A key works only on §13.4 and §13.5, never as a login.

**Clients:** web vault (connect, manage, keys, generator, at the item), UwULock desktop and
extension (generator and item, through §13.3 with their session), official clients (§13.4/§13.5).

---

## 14. Sends: domains, addresses, branding

### 14.1 Send domains — admin

Extra hosts (e.g. `send.example.com` beside `lock.example.com`) that serve only Sends and file
requests. TLS per domain: the server's own Let's Encrypt (TLS-ALPN-01, like the main host; needs
the name pointing here and port 443) or `proxy` (a proxy in front terminates TLS and passes the
`Host`).

```json
{
  "object": "sendDomain",
  "id": "5b0c…",
  "host": "send.example.com",
  "tls": "acme",
  "certificate": { "status": "ok", "expires": "…", "error": null },
  "branding": null,
  "creationDate": "…"
}
```

`certificate.status`: `ok`, `pending`, `failed`, `proxy`. `branding` as §14.4 or `null` (the
server's).

- `GET /uwu/v1/admin/send-domains` → list.
- `POST /uwu/v1/admin/send-domains` — `{ "host": "send.example.com", "tls": "acme" | "proxy" }`.
  The host: lowercase, no scheme or port, not the main host, not an IP, unique. `acme` starts the
  certificate order.
- `PUT /uwu/v1/admin/send-domains/{id}` — `{ "tls": … }`.
- `DELETE /uwu/v1/admin/send-domains/{id}` — Sends and file requests that chose it fall back to
  the main host; links under it stop working.
- `POST /uwu/v1/admin/send-domains/{id}/check` → `{ "dns": { "ok": true, "addresses": ["203.0.113.5"] }, "https": { "ok": true, "error": null }, "routing": { "ok": true } }`
  (the server resolves the host and fetches `https://<host>/alive` from itself).
- Branding per domain: §14.4.

**What a send domain answers** (by the `Host` header; `X-Forwarded-Host` only with
`trust_forwarded`): the web vault's files (the Send and file-request pages, assets), `GET /<accessId>`
(the Send page), `GET /r/<accessId>` (the file-request page), **[BW]** `/api/sends/access`,
`/api/sends/access/file/{fileId}`, `/api/sends/access/{accessId}`,
`/api/sends/{id}/access/file/{fileId}`, `/api/sends/{id}/{fileId}` (file download with token),
`POST /identity/connect/token` with `grant_type=send_access` only, and `/uwu/v1/info`,
`/uwu/v1/branding*`, `/uwu/v1/public/file-requests/**`, `/alive`. Everything else: 404. No web
vault, no login, no admin portal.

Send link on a send domain: `https://send.example.com/<accessId>#<key>` (the same `accessId` and
`key` as Bitwarden's `https://lock.example.com/#/send/<accessId>/<key>`, which keeps working).

### 14.2 Which domain a Send uses

Every Send (and file request) is reachable on the main host **and** every send domain; the
choice only decides the link the UwULock clients show and the branding of the page. So old links
keep working and deleting a domain loses nothing.

- `PUT /uwu/v1/account/send-domain` — auth `user`, `{ "sendDomainId": "…" | null }`: the account's
  default (`null` = main host). In `GET /uwu/v1/account` as `sendDomainId`.
- A Send created through Bitwarden's API gets the account's default at creation (stored in the
  Send's row, `domain_id`), since the official clients cannot send one.
- `PUT /uwu/v1/sends/{sendId}/domain` — auth `user`, owner only, `{ "sendDomainId": "…" | null }`
  → `{ "object": "sendDomainChoice", "sendId", "sendDomainId" }`. Realtime `uwu`.
- `GET /uwu/v1/sends/domains` → `{ "<sendId>": "<sendDomainId>" | null, … }` (all the account's
  Sends; also in the sync as `uwu.sendDomains`).
- File requests carry `sendDomainId` themselves (§11.4).

The official clients build their links from their own server URL (the main host); their links
work, they just do not use the send domain.

### 14.3 Sends only for given addresses — [BW]

Bitwarden's "Send with email verification" (server `src/Core/Tools/Enums/AuthType.cs`,
`src/Api/Tools/Models/Request/SendRequestModel.cs`,
`src/Identity/IdentityServer/RequestValidators/SendAccess/*`; clients
`libs/tools/send`, `apps/web/src/app/tools/send/send-access/send-auth.component.ts`; SDK
`crates/bitwarden-auth/src/send_access/`). Needs mail: without a mail server the server refuses
`emails` (400, "Sends for given addresses need the server to send mail.") and `/uwu/v1/info`
leaves out `send-emails`.

**The Send model** gains, on create/update requests and in the owner's responses
(`SendResponseModel`, in `/api/sends`, `/api/sync`, `/uwu/v1/sync`):

- `authType`: 0 = Email, 1 = Password, 2 = None (today the server writes 1 or 2).
- `emails`: **plaintext**, comma-separated, lowercase (`"a@example.com,b@example.com"`), at most
  4000 characters as stored after trimming and lowercasing each address (Bitwarden's service
  limit is 2500); each must be an address; values starting with `P|` are refused.
- `password` and `emails` exclude each other: `authType` 0 clears the password, 1 clears the
  addresses, 2 both. `authType` missing: inferred (addresses → 0, password → 1); with neither,
  a change keeps what the Send had (a key rotation, an older client) and a new Send is 2.
  `authType` 1 without a password keeps the one there is.
- `PUT /api/sends/{id}/remove-auth` clears both (`remove-password` stays as an alias).
- The recipient's view (`SendAccessResponseModel`) gains `authType`; never the addresses.

**The grant**, `POST /identity/connect/token`, form-encoded: `client_id=send`,
`grant_type=send_access`, `scope=api.send.access`, `send_id=<accessId>`, and then exactly one of
`password_hash_b64`, `email`, or `email` + `otp`. For a Send with `authType` 0:

| Request | Answer (HTTP 400, JSON) |
| --- | --- |
| no `email` | `{ "error": "invalid_request", "error_description": "email is required.", "send_access_error_type": "email_required" }` |
| `email`, no `otp`, address on the list | a 6-digit code is mailed; `{ "error": "invalid_request", "error_description": "email and otp are required.", "send_access_error_type": "email_and_otp_required" }` |
| `email`, no `otp`, address not on the list | the same answer, no mail (nobody learns the list) |
| `email` + wrong or expired `otp` | the same answer |
| `email` + right `otp` | `{ "access_token", "expires_in", "token_type": "Bearer", "scope": "api.send.access" }`; the token also names the address |

Bitwarden's older way of opening a Send (`POST /api/sends/access/{accessId}` with the password
hash in the body, and `/api/sends/{id}/access/file/{fileId}`) answers 401 for a Send with
addresses: only the grant opens those.

The code: 6 digits (`auth::random_code(6)`), stored hashed per (Send, address), 5 minutes,
single use, compared in constant time. UwULock adds limits Bitwarden leaves out: 5 wrong codes
per (Send, address) end the code; at most one mail per (Send, address) a minute and 5 an hour;
the per-IP anonymous limit and the existing per-address mail limit apply. The mail ("Your Send
verification code is 123456") is in the server's default language, with the branding of the host
the page was opened on. After the token: **[BW]** `POST /api/sends/access` and
`POST /api/sends/access/file/{fileId}` with `Authorization: Bearer`, as today. The access count
goes up when the text or file is handed out, as today.

Statuses: the existing `invalid_grant` answers of the grant keep the status they have today
(404, which the newest clients accept); the new `invalid_request` ones are 400 as at Bitwarden.

The web vault's Send page follows Bitwarden's flow: ask without credentials; on
`email_required` show the address field; on `email_and_otp_required` show the code field (after
a wrong code: "invalid code"). UwULock desktop's Send editor gets "Only for these addresses".
Sends of type 2 (item) are not offered (no feature flag in `/api/config`).

### 14.4 Branding — public

- `GET /uwu/v1/branding` — auth `none`, by host (a send domain's own, else the server's):
  `{ "object": "branding", "name", "color", "custom", "logoLight", "logoDark", "favicon" }` (the
  URLs absolute or `null`).
- `GET /uwu/v1/branding/logo/light`, `/logo/dark`, `/favicon` — the image (`image/png`),
  `Cache-Control: public, max-age=3600`, `X-Content-Type-Options: nosniff`,
  `Content-Security-Policy: default-src 'none'; sandbox`; 404 when there is none.
- The web vault's HTML (`/`, `/admin`, `/r/<accessId>`) carries it too, when the branding is not
  UwULock's: its `<title>` is the name, the favicon link points at `/uwu/v1/branding/favicon?v=…`,
  and `<style id="uwu-branding">` sets the accent tokens (`--uwu-pink`, `--uwu-pink-solid`, …)
  for `html:root` and `html:root[data-theme="dark"]`, worked out from the colour (UwUMail's
  palette: each shade moved until text on it reads at 4.5:1), plus `<meta name="theme-color">`.

Admin (auth `admin`):

- `GET /uwu/v1/admin/branding` → the public object plus `nameSet`, `colorSet` (whether they are
  the admin's, not UwULock's) and `contrast: { light, dark, ok }` of the colour.
- `GET /uwu/v1/admin/branding/preview?color=%23rrggbb` → `{ light: {token: value}, dark: {…},
  contrast: { light, dark, ok } }`: the shades a colour would give, for a preview before saving.
- `PUT /uwu/v1/admin/branding` — `{ "name": "…" | null, "color": "#rrggbb" | null }` (`null` or
  `""` = UwULock's); answers like `GET`. The name is trimmed, at most 40 characters, without
  control characters (400 `brandName`). The colour must reach 3:1 contrast against white and
  the dark background `#141016` (400 `brandContrast`, the message names both ratios; 400
  `brandColor` for anything but `#rrggbb`).
- `PUT /uwu/v1/admin/branding/logo/{light|dark}`, `PUT /uwu/v1/admin/branding/favicon` — raw
  image body (PNG, JPEG, WebP, GIF, ICO or SVG), recognized by its content, at most 512 KiB
  (favicon 128 KiB); stored re-encoded as PNG, at most 512 pixels (favicon 192) on the longer
  side, which drops metadata and anything hidden in it. An SVG is drawn (resvg) without text,
  fonts or anything it refers to, so nothing of it but the pixels survives. 400 `brandImage` /
  `brandImageSize`. `DELETE` the same paths. All answer like `GET`.
- The same under `/uwu/v1/admin/send-domains/{id}/branding` (`PUT` name/colour, `…/logo/{variant}`,
  `…/favicon`) for one send domain — with Stufe 6's send domains. Branding is stored per scope
  (`""` the server, a send domain's id its own; migration 0010), and the lookup by `Host` is in
  place (`branding::scope_for_host`), so those routes only need registering.

Every change is written to the admin event log; a restore brings the backup's branding back.

Branding applies to the web vault, login, Send and file-request pages and mails; the official
clients stay as they are.

**Clients:** web vault (all of §14), UwULock desktop (§14.2 choice, §14.3 editor), extension
(§14.2 link only if it makes Sends).

---

## 15. Reports: password health and 2FA directory

The client computes; the server keeps what the client encrypted and proxies what it must not ask
itself.

- `GET /uwu/v1/reports/health` — auth `user` → `{ "object": "healthReport", "data": "2.…" | null, "revisionDate": "…" | null }`.
- `PUT /uwu/v1/reports/health` — `{ "data": "2.…" }`: the last password-health report, JSON
  encrypted under the extras key, at most 1 MiB; anything but an EncString of type 2 is refused
  (400). Answer: the object. Resetting the extras key deletes it.
- `DELETE /uwu/v1/reports/health` → 200.
- `GET /uwu/v1/hibp/{prefix}` — unchanged (k-anonymity range query through the server).
- `GET /uwu/v1/twofa-directory` — auth `user`, `ETag`/`If-None-Match`. The server mirrors the
  list of [2fa.directory](https://2fa.directory/) from its public API,
  **`https://api.2fa.directory/v3/all.json`** (pinned; `[["Name", {domain, "additional-domains",
  tfa, documentation, …}], …]`). **Licence, checked 2026-09-29:** the data is in
  github.com/2factorauth/twofactorauth under the **MIT licence** (© 2factorauth and contributors;
  before 2021 Josh Davis); passing the data on needs attribution, which travels as `source` in
  every answer and is shown under the report. The server fetches it the first time an account
  asks, then once a day while somebody uses it, through the icons' checked client (every address
  checked, no private networks), at most 8 MiB. It keeps only sites with a second factor, only
  `domain` (and extra domains) that look like host names, `name`, `methods` (`tfa`) and
  `documentation` when it is an `https://` link. 502 `upstream` when there is no copy yet and the
  fetch fails.

  ```json
  {
    "object": "twofaDirectory",
    "updated": "…",
    "source": { "name": "2FA Directory", "url": "https://2fa.directory/", "license": "MIT, © 2factorauth and contributors (github.com/2factorauth/twofactorauth)" },
    "entries": [
      { "domain": "example.com", "additionalDomains": ["example.net"], "name": "Example", "methods": ["totp", "u2f"], "documentation": "https://example.com/help/2fa" }
    ]
  }
  ```

  The web vault compares the items' hosts with it in the browser: items for sites that offer
  `totp` but have no TOTP stored go into the report "2FA possible, not set up" (a host matches
  its own entry or the nearest domain above it, never a bare top-level domain; `www.` is
  ignored). The server never learns which sites are in a vault.

**Clients:** web vault; UwULock desktop may use both.

---

## 16. Family (Stufe 4d)

A family is a Bitwarden organization with the "Families" tier: roles Owner and User only, no
groups, no policies, no account recovery. UwULock's own web vault is the management UI (the
official web vault is not served), and it uses **Bitwarden's** organization API, so the official
clients see families like any organization (sync, collections, sharing an item). The same
endpoints serve Stufe 5's organizations (§16.5).

Field values below are from the research of 2026-09-28: member types Owner 0, Admin 1, User 2,
Custom 4 (Manager 3 is gone); member status Invited 0, Accepted 1, Confirmed 2, Revoked -1;
`productTierType` Free 0, Families 1, Teams 2, Enterprise 3; `planType` FamiliesAnnually 22,
EnterpriseAnnually 20 (server `src/Core/AdminConsole/Enums/*`, `src/Core/Billing/Enums/*`).

### 16.1 Creating and changing — [BW]

- `POST /api/organizations` (server `OrganizationsController.cs`, model
  `OrganizationCreateRequestModel.cs`): body `{ "name" (≤ 50), "billingEmail", "planType",
  "key" (the organization key under the user key), "keys": { "publicKey", "encryptedPrivateKey" },
  "collectionName" (EncString, the first collection) }`; billing fields are ignored. UwULock reads
  `planType`: **22 → family**, **20 → organization** (Stufe 5); anything else 400. Who may: §16.4
  (403 `forbidden` with a message). The creator becomes Owner, Confirmed; the first collection is
  made with them in it. Answer: `OrganizationResponseModel` (`object: "organization"`).
- `GET /api/organizations/{id}` → `OrganizationResponseModel`; `PUT /api/organizations/{id}`
  `{ name, billingEmail }` (Owner); `DELETE /api/organizations/{id}` `{ masterPasswordHash }` (Owner);
  `POST /api/organizations/{id}/leave` (a member leaves; the last Owner cannot, 400);
  `GET /api/organizations/{id}/keys` → `{ "object": "organizationKeys", "publicKey", "privateKey" }`;
  `GET /api/organizations/{id}/public-key` → `{ "object": "organizationPublicKey", "publicKey" }`.

For a family, `OrganizationResponseModel` and the profile organization (`profileOrganization` in
the sync, `organizations.rs::profile_organization`) say: `productTierType: 1`, `planType: 22`,
`seats: <maxMembers>`, `maxCollections: null`, `usersGetPremium: true`, `selfHost: true`,
`hasPublicAndPrivateKeys: true`, `usePasswordManager: true`, `useTotp: true`,
`limitCollectionCreation: true`, `limitCollectionDeletion: true`, `limitItemDeletion: false`,
`allowAdminAccessToAllCollectionItems: true`, and every other `use*` flag `false`.

### 16.2 Members — [BW]

Server `OrganizationUsersController.cs` (`/api/organizations/{orgId}/users`):

- `GET …/users?includeCollections=true&includeGroups=false` → list of
  `organizationUserUserDetails` (`id, userId, type, status, externalId, name, email, avatarColor,
  twoFactorEnabled, collections[{id, readOnly, hidePasswords, manage}], groups[], hasMasterPassword,
  resetPasswordEnrolled, ssoBound, permissions, creationDate`).
- `GET …/users/{id}` → the same for one.
- `POST …/users/invite` — `{ "emails": [], "type": 0 | 2, "collections": [{ "id", "readOnly", "hidePasswords": false, "manage": false }], "groups": [], "permissions": null, "accessSecretsManager": false }`.
  A family refuses other types (400). At most `seats` members counting invited ones (400 with
  Bitwarden's wording "You have reached the maximum number of users"). Answer 200, empty.
- `POST …/users/{id}/reinvite`, `POST …/users/reinvite` `{ "ids": [] }` → bulk result
  `{ object: "list", data: [{ "object": "OrganizationBulkConfirmResponseModel", "id", "error": "" }] }`.
- `POST …/users/{id}/accept` — `{ "token", "resetPasswordKey": null }`, by the invited account.
- `POST …/users/public-keys` — `{ "ids": [] }` → list of
  `{ "object": "organizationUserPublicKeyResponseModel", "id", "userId", "key" }`.
- `POST …/users/{id}/confirm` — `{ "key": "4.…" }` (the organization key wrapped for the member's
  public key); `POST …/users/confirm` — `{ "keys": [{ "id", "key" }] }` → bulk result.
- `PUT …/users/{id}` (and `POST`) — `{ "type", "collections": [], "groups": [], "permissions", "accessSecretsManager" }`.
- `DELETE …/users/{id}`, `DELETE …/users` `{ "ids": [] }`.
- `PUT …/users/{id}/revoke`, `PUT …/users/{id}/restore` (and the bulk `PUT …/users/revoke|restore` `{ ids }`).

**Invitation mail and link** (server `OrganizationUserInvitedViewModel.cs`):
`<public>/#/accept-organization?organizationId=…&organizationUserId=…&email=<urlencoded>&organizationName=<urlencoded>&token=<urlencoded>&initOrganization=False&orgUserHasExistingUser=True|False`
(capitalized booleans). The token is a `link` token (issuer suffix `|orginvite`, subject the
membership id and address, 5 days). An address with an account: the web vault logs in and posts
`accept`. An address without one: the organization invitation also lets the person register
(like a server invitation, and counted against the inviter's quota of §21 unless the inviter is an
admin); `POST /identity/accounts/register/finish` **[BW]** takes `orgInviteToken` and
`organizationUserId` beside the usual fields (server `RegisterFinishRequestModel.cs`) and accepts
the membership in the same step.

**Confirming** needs the fingerprint phrase: the web vault fetches the member's public key
(`public-keys`), shows `uwulock_core::crypto::fingerprint(<member userId>, <public key>)` to the
Owner, who compares it with what the member sees in their account settings, and only then posts
`confirm`.

### 16.3 Collections — [BW]

Server `CollectionsController.cs` (`/api/organizations/{orgId}/collections`):

- `GET …/collections` → `{ id, organizationId, name, externalId, type }` (`object: "collection"`);
  `GET …/collections/details`, `GET …/collections/{id}/details` → plus
  `groups[], users[{id, readOnly, hidePasswords, manage}], assigned, readOnly, hidePasswords, manage`
  (`object: "collectionAccessDetails"`).
- `POST …/collections`, `PUT …/collections/{id}` — `{ "name": "2.…", "externalId": null, "groups": [], "users": [{ "id": "<organization user id>", "readOnly": false, "hidePasswords": false, "manage": false }] }`.
  A family uses only `readOnly` (read or write, the plan's two rights); Owners manage everything.
- `DELETE …/collections/{id}`, `DELETE …/collections` `{ "ids": [] }`.
- `GET /api/collections` (the account's, exists) and moving items in
  (`PUT /api/ciphers/{id}/share` `{ cipher, collectionIds }`, `PUT /api/ciphers/share`,
  `…/collections_v2`, all exist) — the official clients use these too.

Changes to membership, rights or collections bump the affected accounts' sync epochs (§4.3) and
notify `SyncOrgKeys`/`SyncVault` as Bitwarden does.

Organizations imported from Vaultwarden are families if they use only Owners and Users and no
groups or policies; otherwise organizations (§16.5).

### 16.4 UwULock additions

Admin settings (§21.1) `families`: `whoMayCreate` (`everyone` | `admins` | `nobody`, default
`everyone`), `maxMembers` (2–50, default 6; Bitwarden's Families has 6), `perUser` (families one
account may own, 0–10, default 1). `organizations` (Stufe 5) the same keys with defaults
`admins`, 500, 5.

`GET /uwu/v1/account` carries `"families": { "mayCreate": true, "maxMembers": 6, "owned": 0, "perUser": 1 }`
and `"organizations": { "mayCreate": false, … }`. Nothing else is UwULock's own: families are
plain Bitwarden organizations.

### 16.5 Stufe 5 organizations — [BW]

Everything of §16.1–16.3 with `planType: 20`, `productTierType: 3`, all roles (Owner, Admin,
User, Custom with `permissions`), plus the Bitwarden endpoints the web vault's organization pages
need (paths per `bitwarden/server`; request models there): groups
`/api/organizations/{orgId}/groups[/{id}]` (with `/details`, `/users`); policies
`GET /api/organizations/{orgId}/policies`, `PUT /api/organizations/{orgId}/policies/{type}`
(`{ enabled, data }`; the profile's `usePolicies: true`; `GET /api/policies` returns the account's);
account recovery `PUT …/users/{id}/reset-password-enrollment` (`{ resetPasswordKey, masterPasswordHash }`),
`GET …/users/{id}/reset-password-details`, `PUT …/users/{id}/reset-password`; the event log
`GET /api/organizations/{orgId}/events?start=&end=&continuationToken=`,
`GET …/users/{id}/events`, `GET /api/ciphers/{id}/events` (from the security-notice table of §12
plus organization events); the organization API key of §18.

---

## 17. Secrets Manager (Stufe 5)

Bitwarden-compatible, so `bws`, Bitwarden's SDKs, the GitHub Action (`bitwarden/sm-action`) and
the Kubernetes operator work against UwULock. Secrets are encrypted under the organization key;
a machine account's access token carries a key that opens an encrypted copy of the organization
key. The server sees no secret. Only organizations (not families) with Secrets Manager switched on
(§17.4). All paths below are under `/api` except the token endpoint. Sources: server
`src/Api/SecretsManager/Controllers/*`, `bitwarden_license/src/Commercial.Core/SecretsManager/*`,
`src/Identity/IdentityServer/ClientProviders/SecretsManagerApiKeyProvider.cs`; SDK
`sdk-internal` `crates/bitwarden-core/src/auth/{access_token.rs,login/access_token.rs,jwt_token.rs}`,
`bitwarden_license/bitwarden-sm/src`.

### 17.1 Access tokens and their login — [BW]

- The token as the person copies it: `0.<accessTokenId>.<clientSecret>:<base64 of 16 bytes>`.
  The 16 bytes never reach the server. The SDK derives
  `tokenKey = derive_shareable_key(bytes16, "accesstoken", "sm-access-token")` (64 bytes).
  Test vector (SDK `access_token.rs`): `0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==`
  gives the key `H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg==`.
- Login: `POST /identity/connect/token`, form `grant_type=client_credentials`,
  `scope=api.secrets`, `client_id=<accessTokenId>`, `client_secret=<clientSecret>` (no device
  fields). The server finds the access token by id, compares `base64(SHA-256(clientSecret))` with
  the stored value in constant time, and checks: not revoked, not past `expireAt`, the machine
  account and organization exist, the organization is enabled and has Secrets Manager on. Wrong:
  `{"error": "invalid_client"}` (400). Rate-limited like logins.
- Answer: `{ "access_token", "expires_in": 3600, "token_type": "Bearer", "scope": "api.secrets", "encrypted_payload": "2.…" }`.
  `encrypted_payload` is the value stored at creation (§17.3), returned unchanged.
- The access token (a JWT signed like all of the server's) has the claims the SDK reads: `sub` =
  machine account id, `type` = `"ServiceAccount"`, `organization` = organization id,
  `scope` = `["api.secrets"]`, `client_id` = access token id, `exp`, `nbf`, `iss`. The `Session`
  extractor refuses it (no user); a `MachineSession` extractor accepts it only on §17.2.

### 17.2 What the SDK calls — [BW]

Auth: `sm` (machine token) or `user` (a member with `accessSecretsManager`; the web vault).
A machine account sees what its access policies grant (read/write per project); a user what theirs
grant, Owners and Admins everything.

| Method and path | Body | Answer |
| --- | --- | --- |
| `GET /api/organizations/{orgId}/projects` | – | list of `project` |
| `POST /api/organizations/{orgId}/projects` | `{ "name" }` | `project` |
| `GET /api/projects/{id}` | – | `project` |
| `PUT /api/projects/{id}` | `{ "name" }` | `project` |
| `POST /api/projects/delete` | `["<id>", …]` | list of `{ "object": "BulkDeleteResponseModel", "id", "error": null \| "access denied" }` |
| `GET /api/organizations/{orgId}/secrets` | – | `{ "object": "SecretsWithProjectsList", "secrets": [{ id, organizationId, key, creationDate, revisionDate, projects: [{ id, name }], read, write }], "projects": [{ id, name }] }` (no value, no note) |
| `GET /api/projects/{projectId}/secrets` | – | the same shape |
| `POST /api/organizations/{orgId}/secrets` | `{ "key", "value", "note", "projectIds": [], "accessPoliciesRequests": null }` | `secret` |
| `GET /api/secrets/{id}` | – | `secret` |
| `PUT /api/secrets/{id}` | as create, plus `"valueChanged": true` | `secret` |
| `POST /api/secrets/get-by-ids` | `{ "ids": [] }` | list of `baseSecret` |
| `POST /api/secrets/delete` | `["<id>", …]` | bulk result as above |
| `GET /api/organizations/{orgId}/secrets/sync?lastSyncedDate=<RFC 3339>` | – | `{ "object": "secretsSync", "hasChanges": true, "secrets": { "object": "list", "data": [baseSecret…] } \| null }` |

- `project`: `{ "object": "project", "id", "organizationId", "name", "creationDate", "revisionDate", "read", "write" }`.
- `secret`: `{ "object": "secret", "id", "organizationId", "key", "value", "note", "creationDate", "revisionDate", "projects": [{ "id", "name" }], "read", "write" }`;
  `baseSecret` the same without `read`/`write`, `object: "baseSecret"`.
- `name`, `key`, `value`, `note` are EncStrings under the organization key; limits (as
  `[EncryptedStringLength]`): name/key 1000, value 35 000, note 10 000 characters. `note` is
  required (the SDK sends an encrypted empty string).
- `secrets/sync`: only machine tokens (400 for users); `lastSyncedDate` in the future is 400;
  without it, or when anything the machine account may read changed after it (a secret, its
  projects, the account's access), `hasChanges: true` and all readable secrets; else
  `hasChanges: false, secrets: null`.

### 17.3 Machine accounts and access policies (web vault) — [BW]

Auth `user`, Owners/Admins of the organization or members with the right policies:

- `GET|POST /api/organizations/{orgId}/service-accounts` (`{ "name": "2.…" }`) →
  `{ "object": "serviceAccount", "id", "organizationId", "name", "creationDate", "revisionDate", "accessToSecrets" }`;
  `GET|PUT /api/service-accounts/{id}`; `POST /api/service-accounts/delete` `["<id>"]`.
- `GET /api/service-accounts/{id}/access-tokens` → list of
  `{ "object": "accessToken", "id", "name", "scopes": ["api.secrets"], "expireAt", "creationDate", "revisionDate" }`.
- `POST /api/service-accounts/{id}/access-tokens` — `{ "name": "2.…", "encryptedPayload": "2.…", "key": "2.…", "expireAt": null | "…" }`
  → `{ "object": "accessTokenCreation", "id", "name", "clientSecret", "expireAt", "creationDate", "revisionDate" }`.
  The web vault made 16 random bytes and `tokenKey` (§17.1); `encryptedPayload` = EncString type
  2 under `tokenKey` of `{"encryptionKey": "<organization key, base64 of 64 bytes>"}` (at most 4000
  characters); `key` = `tokenKey` under the organization key. The server makes `clientSecret`
  (30 random characters, as Bitwarden), stores its SHA-256, returns it once. The web vault shows
  `0.<id>.<clientSecret>:<base64 of the 16 bytes>`.
- `POST /api/service-accounts/{id}/access-tokens/revoke` — `{ "ids": [] }`.
- Access policies: `GET|PUT /api/projects/{id}/access-policies/people`
  (`{ "userAccessPolicyRequests": [{ "granteeId", "read", "write" }], "groupAccessPolicyRequests": [] }`),
  `GET|PUT /api/projects/{id}/access-policies/service-accounts`
  (`{ "serviceAccountAccessPolicyRequests": [{ "granteeId", "read", "write" }] }`),
  `GET|PUT /api/service-accounts/{id}/granted-policies`
  (`{ "projectGrantedPolicyRequests": [{ "grantedId", "read", "write" }] }`),
  `GET|PUT /api/service-accounts/{id}/access-policies/people`,
  `GET /api/secrets/{secretId}/access-policies`,
  `GET /api/organizations/{id}/access-policies/{people|service-accounts|projects}/potential-grantees`.
  Response models as in server `AccessPoliciesController.cs`.

### 17.4 Switching it on

- Admin setting `secretsManager.enabled` (default on) switches the feature server-wide.
- Per organization, its Owners switch it on in UwULock's web vault:
  `PUT /uwu/v1/organizations/{orgId}/secrets-manager` — auth `user` (Owner) —
  `{ "enabled": true }`. Then the profile organization says `useSecretsManager: true`, and members
  get access through `accessSecretsManager` in **[BW]** `POST …/users/invite` / `PUT …/users/{id}`
  or `PUT /api/organizations/{orgId}/users/enable-secrets-manager` (`{ "ids": [] }`); the profile
  says `accessSecretsManager` per member. Families: 400.

**Clients:** `bws`, Bitwarden SDKs, `bitwarden/sm-action`, the Kubernetes operator (§17.1–17.2);
web vault (§17.3–17.4).

---

## 18. Directory Connector (Stufe 5)

Bitwarden's Directory Connector syncs users and groups from LDAP or Entra ID into an
organization. It uses only the organization API key and one import call. Sources:
`bitwarden/directory-connector` `src/services/api.service.ts`, `src/models/request/*`,
`src/services/{sync.service,batch-request-builder,single-request-builder}.ts`; server
`src/Api/AdminConsole/Public/Controllers/OrganizationController.cs`,
`src/Identity/IdentityServer/ClientProviders/OrganizationClientProvider.cs`.

### 18.1 The organization API key — [BW], auth `user` (Owner)

- `POST /api/organizations/{id}/api-key` — `{ "type": 0, "masterPasswordHash": "…" }` → makes the
  key if there is none: `{ "object": "apiKey", "apiKey": "<30 random characters>", "revisionDate" }`.
  Wrong password: 400 with `validationErrors.MasterPasswordHash: ["Invalid password."]`.
- `POST /api/organizations/{id}/rotate-api-key` — the same body → a new key.
- `GET /api/organizations/{id}/api-key-information/{type?}` → list of
  `{ "object": "keyInformation", "keyType": 0, "revisionDate" }`.
- The web vault shows `client_id = organization.<orgId>` and the key. Stored as SHA-256; only
  type 0 is used. Only organizations (not families); the profile says `useApi: true`,
  `useDirectory: true`.

### 18.2 Login — [BW]

`POST /identity/connect/token`, form `grant_type=client_credentials`, `scope=api.organization`,
`client_id=organization.<orgId>`, `client_secret=<apiKey>`, `deviceType`, `deviceIdentifier`,
`deviceName`. Answer `{ "access_token", "expires_in": 3600, "token_type": "Bearer", "scope": "api.organization" }`
(no refresh token; the connector logs in again). Token claims `sub` = organization id,
`type` = `"Organization"`, `scope` = `["api.organization"]`. Wrong: `{"error":"invalid_client"}`.
Accepted only on `/api/public/**` (`org-key`).

### 18.3 The import — [BW]

`POST /api/public/organization/import`, auth `org-key`:

```json
{
  "groups": [ { "name": "Office", "externalId": "cn=office,ou=groups,dc=example,dc=com", "memberExternalIds": ["uid=a,…"] } ],
  "members": [ { "email": "a@example.com", "externalId": "uid=a,…", "deleted": false } ],
  "overwriteExisting": false,
  "largeImport": false,
  "inviteUsersAfterProvisioning": false
}
```

- Limits as Bitwarden's model: group `name` ≤ 100, `externalId` ≤ 300, `email` ≤ 256;
  `overwriteExisting` required. `largeImport` is ignored (self-hosted: no 2000 limit). The
  connector sends batches of 2000.
- Members: a new address becomes an invited member (type User) and gets the invitation mail of
  §16.2 (whatever `inviteUsersAfterProvisioning` says, since a person without an account cannot
  otherwise join); an existing member is matched by `externalId`, else by address, and gets the
  `externalId`; `deleted: true` removes the member with that `externalId`. With
  `overwriteExisting: true`, members **with** an `externalId` that is not in the import are
  removed (members without one — added by hand — stay).
- Groups: matched by `externalId`, created or renamed; their members set to
  `memberExternalIds`; with `overwriteExisting`, groups with an `externalId` not in the import are
  deleted.
- Answer 200 with an empty body; errors 400 `ErrorResponseModel`. Seat limits apply (400).
- Bumps sync epochs and notifies like §16.

**Clients:** Bitwarden Directory Connector (desktop and CLI); web vault (§18.1).

---

## 19. SSO / OIDC and UwUAuth pairing

Login through an OpenID Connect provider — UwUAuth or any other (Entra ID, Keycloak, …). SSO
proves who someone is; the vault is still opened with the master password, which the server
never sees. Password login stays available beside it. What the official clients call is
Bitwarden's; how the server does it mirrors Vaultwarden 1.34+ (`src/sso.rs`, `src/sso_client.rs`,
`src/api/identity.rs`), with the differences named.

### 19.1 Settings (admin, §21.9)

```json
{
  "enabled": true,
  "issuer": "https://auth.example.com",
  "clientId": "…",
  "clientSecretSet": true,
  "scopes": ["openid", "email", "profile", "groups"],
  "pkce": true,
  "identifier": "uwulock",
  "label": "UwUAuth",
  "only": false,
  "signups": "group",
  "userGroup": "vault-users",
  "adminGroup": "vault-admins",
  "adminsOnlyWithSso": false,
  "trustUnverifiedEmail": false,
  "groupsClaim": "groups",
  "rolesClaim": null,
  "paired": null
}
```

- `identifier`: what `/api/organizations/domain/sso/verified` hands out; the clients' "SSO
  identifier" may be anything (the plan: it does not matter).
- `only`: when true, `grant_type=password` is refused (400, "Log in with SSO.", code
  `sso_required`) except for the CLI's API key and accounts that are admins without
  `adminsOnlyWithSso`; so is `grant_type=webauthn` (a passkey login), under the same rule.
- `signups`: `off` (only existing accounts), `invitation` (plus pending invitations), `group`
  (plus anyone in `userGroup`; `userGroup: null` = anyone the provider lets through).
- `adminGroup`: with it set, being an admin follows the group at every SSO login (added or
  removed), and `adminsOnlyWithSso: true` makes `/uwu/v1/admin/**` accept only tokens from an SSO
  login (`amr` contains `"sso"`).
- `rolesClaim`: after UwUAuth pairing, `"roles"`: role `admin` and `user` replace the two groups.

### 19.2 The login — [BW] requests, UwULock's handling

1. **[BW]** `POST /api/organizations/domain/sso/verified` — auth `none`, `{ "email" }` → with SSO
   on: `{ "object": "list", "data": [{ "object": "verifiedOrganizationDomainSsoDetails", "organizationIdentifier": "<identifier>", "organizationName": "<branding name>", "domainName": "<the address's domain>" }], "continuationToken": null }`;
   off: an empty list. (Server `OrganizationDomainController.cs`; the older `…/sso/details` is gone
   from current clients.)
2. **[BW]** `GET /identity/sso/prevalidate?domainHint=<any>` → `{ "token": "<JWT, 2 minutes, issuer suffix |sso>" }`;
   SSO off: 400 "SSO is not enabled on this server."
3. **[BW]** `GET /identity/connect/authorize?client_id=…&redirect_uri=…&response_type=code&scope=api%20offline_access&state=…&code_challenge=…&code_challenge_method=S256&response_mode=query&domain_hint=…&ssoToken=…`.
   The server:
   - checks `ssoToken`, `code_challenge_method=S256`, and `redirect_uri` against the client:
     `web`, `browser`: `<public>/sso-connector.html`; `mobile`: `bitwarden://sso-callback`;
     `desktop`: `bitwarden://sso-callback` or a loopback URL (UwULock desktop keeps
     `client_id=desktop` and uses loopback, since `bitwarden://` belongs to Bitwarden's app);
     `cli`, `uwussh`, `uwurdp`, `uwumail`, `uwusuite`: `http://localhost:<port>/…`
     or `http://127.0.0.1:<port>/…`; `uwulock-extension`: `https://<32 letters a–p>.chromiumapp.org/…`
     or `https://<40 hex>.extensions.allizom.org/…` (the extensions' `identity` redirect URLs).
     Anything else: 400.
   - stores `{ sha256(state) → client_id, redirect_uri, client state, client code_challenge,
     nonce, own PKCE verifier, sha256(binding), expires in 10 minutes }`, sets
     `__Host-uwu-sso=<binding>; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`, and answers
     302 to the provider's `authorization_endpoint` with `response_type=code`, `client_id`,
     `redirect_uri=<public>/identity/connect/oidc-signin`, `scope`, `state` (its own, random),
     `nonce`, and its own `code_challenge` (S256) when `pkce`.
4. `GET /identity/connect/oidc-signin?code=…&state=…` (or `error=…`) — the provider's callback,
   auth: state and binding cookie. The server exchanges the code (`client_secret_basic`, PKCE
   verifier), validates the ID token (JWKS signature, `iss` = issuer, `aud` contains `clientId`,
   `exp`, `nonce`), reads userinfo if the ID token lacks `email`, decides the account (§19.3), makes
   a one-time code (32 random bytes, 5 minutes, stored hashed, bound to the client's
   `code_challenge`, `client_id`, `redirect_uri`), and answers 302 to
   `<client redirect_uri>?code=<one-time code>&state=<client state>`. A provider error or refused
   account: 302 to `<client redirect_uri>?error=access_denied&error_description=<message>&state=<client state>`.
   The web vault's `sso-connector.html` (UwULock's web vault must ship it, as Bitwarden's does)
   hands code and state to the page or extension that started the login.
5. **[BW]** `POST /identity/connect/token`, form `grant_type=authorization_code`, `code`,
   `code_verifier` (checked against the stored `code_challenge`), `redirect_uri`, `client_id`
   (both equal to the stored), `scope`, `deviceType`, `deviceIdentifier`, `deviceName` (and the
   two-step fields). Then as a password login: the server's own two-step login still applies, then
   the token answer. The access token's `amr` gets `"sso"` beside `"Application"`. The token's
   scope follows the `client_id`: the suite apps' ids (§6.5) get `uwu.suite`, all others `api`.
   - Account with a master password: the usual answer (`Key`, `PrivateKey`, `AccountKeys`,
     `UserDecryptionOptions.HasMasterPassword: true` with `MasterPasswordUnlock`).
   - New account from SSO (no keys yet): no `Key`, no `PrivateKey`, no `AccountKeys`,
     `UserDecryptionOptions: { "HasMasterPassword": false, "Object": "userDecryptionOptions" }`
     — the official clients then go to "set initial password" (clients
     `libs/auth/src/common/login-strategies/sso-login.strategy.ts`).
6. **[BW]** `POST /api/accounts/set-password` (server `SetInitialPasswordRequestModel.cs`) — auth
   `user` (the token from step 5). Both shapes: the legacy one the clients still send
   `{ "masterPasswordHash", "key", "masterPasswordHint", "orgIdentifier", "keys": { "publicKey", "encryptedPrivateKey" }, "kdf", "kdfIterations", "kdfMemory", "kdfParallelism" }`
   and the new one `{ "masterPasswordAuthentication": { "kdf": {…}, "masterPasswordAuthenticationHash", "salt" }, "masterPasswordUnlock": { "kdf": {…}, "masterKeyWrappedUserKey", "salt" }, "accountKeys": {…} }`.
   Only for an account without keys (else 400); the KDF must meet §20 (400). `orgIdentifier` is
   ignored. Answer 200. The security stamp stays, as with Vaultwarden (the account had no password
   that could have leaked, and a new stamp would log out the client that is setting it up); the
   client goes on with its session.
7. **[BW]** `GET /api/organizations/{identifier}/auto-enroll-status` →
   `{ "object": "organizationAutoEnrollStatus", "id": "<UUIDv5 of the identifier>", "resetPasswordEnabled": false }`
   for the SSO identifier (there is no organization behind it; the client then skips account
   recovery enrolment); for a real organization's identifier, that organization's values.

`/api/config`: `environment.sso` stays as Vaultwarden 1.34+ answers it (the implementer checks
`src/api/core/mod.rs::config` there and copies it).

### 19.3 Which account

Kept in `sso_identities (user_id, issuer, subject, created, last_login)`, unique on
`(issuer, subject)` and on `(user_id, issuer)`:

1. `(issuer, sub)` known → that account (disabled: refused).
2. Else by the ID token's `email` (normalized): only if `email_verified` is `true` (or
   `trustUnverifiedEmail`). An account with that address and no identity of this issuer → linked
   now (notice `ssoLinked`, mailed). An account already linked to another subject → refused.
3. Else, by `signups`: a new account **without keys** (the address from the token, verified),
   which then sets its master password (§19.2 step 6); refused otherwise ("Ask for an
   invitation.").

Group and role checks (`userGroup`, `adminGroup`, `roles`) read the ID token's (or userinfo's)
`groupsClaim` / `rolesClaim`. The admin networks (§21.4) apply to admin rights gained this way.

### 19.4 SCIM — auth: bearer token from pairing or made in the admin portal

UwUAuth (or another provider) disables or removes accounts. SCIM 2.0 (RFC 7643/7644), JSON
`application/scim+json`, under `/scim/v2`:

- `GET /scim/v2/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` — static (patch yes, bulk
  no, filter yes with `maxResults` 200, no sort, no etag, auth `oauthbearertoken`).
- `GET /scim/v2/Users?filter=userName eq "a@example.com"` (also `externalId eq "…"`),
  `GET /scim/v2/Users/{id}`. A user resource: `id` (the account id, or the id of a provisioned
  entry), `userName` (address), `externalId` (the provider's subject), `active`, `displayName`,
  `emails[{ value, primary: true }]`, `meta`.
- `POST /scim/v2/Users` — no account for the address: a provisioned entry that lets this address
  sign up through SSO even with `signups: invitation`; an account exists: 409 `uniqueness` (the
  provider then finds it by filter).
- `PATCH /scim/v2/Users/{id}` — `replace` of `active` (false: account disabled, all devices
  logged out, notify `LogOut`; true: enabled), `displayName` (the account's name), `externalId`.
  A change of `userName`/`emails` is 400 `mutability` (the address is the KDF salt; the person
  changes it in the vault).
- `PUT /scim/v2/Users/{id}` — the same fields, whole.
- `DELETE /scim/v2/Users/{id}` — admin setting `scim.onDelete`: `disable` (default) or `delete`
  (the account and its vault are deleted, as an admin would).
- `/scim/v2/Groups` (`GET`, `POST`, `PATCH` members, `DELETE`) — kept only to know membership in
  `adminGroup`/`userGroup` between logins; removal from `adminGroup` takes the admin right at once.

Errors as RFC 7644 `{ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": "409", "scimType": "uniqueness", "detail": "…" }`.
The token is compared in constant time against its stored SHA-256.

### 19.5 Pairing with UwUAuth (UwUAuth's Stufe 4)

Instead of copying issuer, client id, secret and redirect URIs by hand, the admin pairs the two
servers with a one-time code. Afterwards it is plain OIDC (§19.2) and SCIM (§19.4). This is the
protocol both sides implement; UwUAuth builds its half from this section.

**UwUAuth side (built in UwUAuth-Server):**

- Admin portal *Apps → Pair a UwUSuite app*: the admin picks the groups that may use the app
  (default: everyone) and, optionally, which groups get which of the app's roles (after pairing,
  when the app has told its roles, also on the app's page). `POST /uwu/v1/pairing-codes` (UwUAuth
  admin API) `{ "allowedGroups": [], "roleGroups": { "admin": ["vault-admins"] } }` →
  `{ "code": "7KQ4-M2XD-9HFT", "expires": "…", "qr": "<SVG>" }`. The code: 12 Crockford base32
  characters in three groups (60 bits), one use, 15 minutes. The QR code holds
  `<UwUAuth URL>#pair=<code>`; app input fields accept that whole string too.
- `GET /uwu/v1/server` (exists) additionally says `"pairing": 1` and `"scim": true`.
- `POST /uwu/v1/pair` — auth: the code. Rate-limited per IP (10 tries per 15 minutes) and globally
  (60 per 15 minutes); an unknown, used or expired code is always 400 `{ "error": "invalid_code" }`.
  Body:

  ```json
  {
    "code": "7KQ4-M2XD-9HFT",
    "app": {
      "product": "UwULock",
      "version": "0.6.0",
      "name": "UwULock (lock.example.com)",
      "url": "https://lock.example.com",
      "icon": "data:image/png;base64,…",
      "redirectUris": ["https://lock.example.com/identity/connect/oidc-signin"],
      "postLogoutRedirectUris": ["https://lock.example.com/"],
      "scopes": ["openid", "email", "profile", "groups", "roles"],
      "roles": [
        { "id": "admin", "name": "Administrator", "description": "Uses the admin portal" },
        { "id": "user", "name": "User", "description": "May create a vault without an invitation" }
      ],
      "scim": { "baseUrl": "https://lock.example.com/scim/v2", "resources": ["User", "Group"] }
    }
  }
  ```

  `icon` at most 64 KiB, PNG. UwUAuth checks every URI is `https` on the host of `app.url` (or a
  loopback address), then creates an app as `NewApp` does today: `public: false`,
  `tokenAuthMethod: client_secret_basic`, `requirePkce: true`, `consent: false` (a first-party
  suite app), `allowedGroups` and roles from the code, `grantTypes: ["authorization_code", "refresh_token"]`,
  template `uwusuite`. It makes a SCIM bearer token (32 random bytes, base64url) and starts pushing
  users and groups of the allowed groups to `scim.baseUrl`. Answer 200:

  ```json
  {
    "issuer": "https://auth.example.com",
    "clientId": "…",
    "clientSecret": "…",
    "tokenEndpointAuthMethod": "client_secret_basic",
    "scopes": ["openid", "email", "profile", "groups", "roles"],
    "groupsClaim": "groups",
    "rolesClaim": "roles",
    "scimToken": "…",
    "appId": "…",
    "manageUrl": "https://auth.example.com/apps/…"
  }
  ```

  The code is used up with the first answer; the app, its secret and the SCIM token stay
  manageable (and deletable) on the app's page in UwUAuth.

**UwULock side:** admin portal *Settings → Login → Pair with UwUAuth*, address and code:

1. `POST /uwu/v1/admin/sso/pair` — auth `admin` — `{ "url": "https://auth.example.com", "code": "7KQ4-M2XD-9HFT" }`
   (or the QR string). `https` only (a loopback address for tests).
2. The server calls `GET <url>/uwu/v1/server`: `product` must be `UwUAuth` and `pairing` ≥ 1, else
   400 `not_uwuauth`.
3. It calls `POST <url>/uwu/v1/pair` with the body above; no redirects followed; the answer's
   `issuer` must be what `/uwu/v1/server` said, and its discovery document must be readable.
4. It stores issuer, client id, client secret (encrypted like §13.2's tokens), `rolesClaim`,
   `groupsClaim`, the SHA-256 of `scimToken`, and `paired: { "url", "appId", "manageUrl", "date" }`;
   switches `enabled` on (not `only`), `signups: "group"` with `rolesClaim` deciding (`user` role =
   may sign up, `admin` role = admin).
5. Answer: the §19.1 settings. The page offers "Test login".

`DELETE /uwu/v1/admin/sso/pairing` forgets it here (and switches SSO off, and the SCIM token); the
app on the UwUAuth side is deleted there.

### 19.6 Implementation notes (UwULock Server, Stufe 4b)

- `GET|PUT /uwu/v1/admin/sso` also answer `redirectUri` (`<public>/identity/connect/oidc-signin`),
  `scimUrl`, `scimTokenSet` and `scimOnDelete` (read-only here; `scim.onDelete` is saved with
  §21.1). `PUT` refuses `adminsOnlyWithSso: true` from a session without SSO (400
  `would_lock_out`) and reads the discovery document when SSO is switched on or the issuer
  changes. Pairing errors: 400 `invalid_code`, 400 `not_uwuauth`, 429, 502 `upstream`.
- `/uwu/v1/admin/**` with `adminsOnlyWithSso`: 403 with code `sso_required` for a session without
  SSO. Whether a session came through SSO survives refreshes (kept with the device).
- `GET /uwu/v1/account` additionally says `hasMasterPassword` (false until §19.2 step 6), `sso`
  (this session came through SSO) and `adminNeedsSso`.
- `GET /api/organizations/{id}/policies/master-password` — auth `user` — for the id of step 7:
  Bitwarden's policy object (`type: 1`) with the §20 master password rules, which the clients'
  "set initial password" asks for. Any other id: 404.
- The web vault serves `#/sso?clientId=…&redirectUri=…&state=…&codeChallenge=…` (the login of
  Bitwarden's extension, desktop app and CLI, passed on to step 3 at once) and `#/sso?code=…&state=…`
  (its own, and the admin portal's at `/admin#/sso`). Its own logins use `client_id=web` with a
  state ending in `:clientId=web` (`:admin:clientId=web` for the admin portal), which the connector
  page reads to know where to go; states with `:clientId=browser` are posted to the page as
  `{ command: "authResult", code, state }` for Bitwarden's extension, `:clientId=desktop` go to
  `bitwarden://sso-callback`.
- The one-time code of step 4 stays valid (5 minutes) until a token request with it succeeds, so
  the client can send it again with the second step of two-step login.
- Refused SSO logins are written to the event log as `login-failed` (detail `SSO: …`); SSO sign-ups
  as `register` (detail `through SSO`); step 6 as `password-set`; SCIM changes as `scim`; the admin
  right given or taken by SSO as `admin`. SCIM refuses to disable or delete the last admin (409
  `mutability`), and neither SSO nor SCIM takes the admin right from the last admin.
- Wrong SCIM tokens: 30 per address, then one every 30 seconds (429 before that).
- The client secret is sealed (AES-256-GCM) under `secret.key` in the data directory (§13.2);
  a value set on the command line unsealed is taken as it is.

Other suite apps pair the same way with their own `app` values (UwUMail, UwUSync for
UwUSSH/UwURDP).

**Clients:** official clients and all of ours (§19.2), web vault (connector page, set password),
admin portal (§19.1, §19.5), UwUAuth (§19.4, §19.5).

---

## 20. Server policies the clients see

Server-wide rules for every account, set in the admin portal (§21.1 `policies`). Organization
policies (Stufe 5) are Bitwarden's and separate.

```json
{
  "requireTwoFactor": { "enabled": false, "deadline": null },
  "minimumKdf": { "pbkdf2Iterations": 600000, "argon2Memory": 64, "argon2Iterations": 3, "argon2Parallelism": 4 },
  "masterPassword": { "minLength": 12, "minComplexity": 3, "enforceOnLogin": false }
}
```

**Two-step login required.** Before `deadline`: the web vault shows a banner, the account gets
`policy.twoFactorRequired: true` and the deadline in `/uwu/v1/account`. After it, an account
without an enabled provider:

- gets a token only for `client_id=web` (UwULock's web vault), which then shows nothing but the
  two-step setup until one is enabled;
- from every other client (official or ours), `POST /identity/connect/token` — every grant that
  logs in an account: password, `refresh_token`, `client_credentials`, `webauthn` — answers 400
  `{ "error": "invalid_grant", "error_description": "two_factor_required", "ErrorModel": { "Message": "This server requires two-step login. Set it up in the web vault at https://lock.example.com, then log in again.", "Object": "error" } }`
  — the official clients show `ErrorModel.Message`.

**Minimum KDF.** The server refuses weaker KDF settings (400, the message names the minimum, `code`
`kdf_too_weak`) in registration, `POST /api/accounts/kdf`, set-password (§19.2) and emergency
takeover when the contact sends a KDF of its own. `POST /api/accounts/password` and key rotation
cannot change the KDF at all (they refuse any other than the account's), so there is nothing to
check there. Existing accounts below it (e.g. PBKDF2 from Vaultwarden)
keep working and get `policy.kdfBelowMinimum: true` in `/uwu/v1/account`, a security notice
`kdfBelowMinimum` (once), and a button in the web vault that calls **[BW]** `POST /api/accounts/kdf`.

**Master password strength** is checked only by clients (the server never sees the password):
the web vault and UwULock desktop at registration and change (`minComplexity` = zxcvbn score 0–4).
The official clients honour it too: the server fills Bitwarden's `MasterPasswordPolicy` in the
token response (today an empty object) with
`{ "MinComplexity": 3, "MinLength": 12, "RequireUpper": false, "RequireLower": false, "RequireNumbers": false, "RequireSpecial": false, "EnforceOnLogin": false, "Object": "masterPasswordPolicy" }`;
with `EnforceOnLogin: true` they make the person change a weaker password after login (clients
`libs/auth/src/common/login-strategies/password-login.strategy.ts`, which evaluates the policy from
the identity response). This answers the plan's open question: yes, through the token response.
The same values are in `/uwu/v1/info` as `policies.masterPassword` for the registration page.

---

## 21. Admin API additions

All auth `admin` (§1.2, including the admin networks). Every change is written to the admin event
log as today (`admin.rs::record`). Secrets never come back: responses say `…Set: true` instead,
and a secret left out on save keeps the stored one only when the target (host, account) is the
same, as the SMTP password today.

### 21.1 Settings

`GET|PUT /uwu/v1/admin/settings` keeps its shape; new keys (camelCase, all optional on `PUT`,
defaults in brackets):

| Key | Contents |
| --- | --- |
| `versions` | `{ perItem [20], days [365] }` (§8); `perItem` 0–100, `days` 0–3650 |
| `icons` | `{ automatic [true], library [true], sources [["selfhst"]] }` (§7) |
| `fileRequests` | `{ enabled [true], perUser [50], maxDays [90], maxFiles [20] }` (§11) |
| `families` / `organizations` | `{ whoMayCreate, maxMembers, perUser }` (§16.4) |
| `secretsManager` | `{ enabled [true] }` (§17) |
| `suite` | `{ enabled [true], maxRecords [50000], maxMb [256] }` (§6) |
| `securityNotices` | `{ mailOff [[]] }` — kinds not mailed (§12) |
| `policies` | §20 |
| `adminNetworks` | `["192.0.2.0/24", "2001:db8::/32"]` [[] = everywhere] (§21.4) |
| `masked` | `{ servers: [{ url, name }] }` [[]] (§13) |
| `metrics` | `{ enabled [false], tokenSet, listen [null] }` (§22); `token` write-only |
| `loki` | `{ enabled [false], url, tenant, username, passwordSet, labels [{"job":"uwulock"}] }` (§21.7) |
| `scim` | `{ onDelete ["disable"], tokenSet }` (§19.4) |
| `storagePerUserMb` | [null = no limit] counts attachments, Send files, file requests, versions, icons, suite; what would go past it is refused with 422 `quota` (announcing an attachment of an own item, a Send file, a file-request submission for its owner) |

`metrics` is stored with `tokenHash` (hex SHA-256), which `GET` replaces by `tokenSet`; on `PUT`,
`token` left out or `null` keeps it, `""` removes it, otherwise it needs 16 characters. `loki`
takes `password` on `PUT` (left out, `null` or `""`: kept for the same `url` and `username`).
`uwulock-server settings list|get|set <key> <json>` reads and writes the same object on the
command line, with dotted keys (`policies.requireTwoFactor.enabled`) and the same checks.

`sso` (§19.1), branding (§14.4), send domains (§14.1), off-site backups (§21.2) and notification
channels (§21.3) have their own endpoints because of their secrets and actions.

### 21.2 Off-site backups

As UwUMail Server's (its `docs/backups.md` and `routes/backups.rs`; reuse the design): SFTP, S3 or
a mounted folder; deduplicated; encrypted by default with a recovery key shown once; retention
7 days / 4 weeks / 6 months. Contents: the database (an online SQLite backup, or `pg_dump` on
PostgreSQL), the attachment, Send, file-request and icon directories, and the server's secret
files (token key, the secret of §13.2). (As built: own icons are in the database; the `icons/`
directory holds only what the server fetched from websites and the library, which it fetches
again — and which would say which websites the accounts use — so it is left out.)

- `GET /uwu/v1/admin/backups/offsite` →
  `{ "object": "offsiteBackups", "enabled", "hour", "minute", "retention": { "days": 7, "weeks": 4, "months": 6 }, "encrypted", "target", "status": { "lastSuccess", "lastError", "lastDuration", "bytes" }, "running", "warnAfterHours": 48 }`.
  Also in `status`: `lastAttempt`, `uploaded` (bytes the last run sent) and `snapshot` (its
  name); beside it `stale` (the last success is older than `warnAfterHours`). Times are the
  store's format; `lastDuration` is seconds, `bytes` what the last snapshot holds. `hour` and
  `minute` are UTC (default 02:30). `target` is `null` until one is set.
  `target` as UwUMail's view: `{ "kind": "sftp", "host", "port", "user", "path", "method": "key" | "password", "publicKey", "passwordSet", "hostKey" }`,
  `{ "kind": "s3", "endpoint", "region", "bucket", "prefix", "accessKey", "secretKeySet", "pathStyle" }`,
  or `{ "kind": "folder", "path" }`.
- `PUT /uwu/v1/admin/backups/offsite` — `{ enabled, hour, minute, retention, encrypted, warnAfterHours, target: { kind, …, password?, secretKey? } }`;
  the first save with `encrypted: true` answers `recoveryKey` once (the `GET` body plus
  `recoveryKey`; `null` on every later save). `encrypted` is fixed once there are backups (400):
  once a backup succeeded and the target is still the same place. `encrypted` left out means
  `true`. `enabled` needs a target. For SFTP, `method: "key"` makes the server's own Ed25519 key
  on the first save and keeps it whatever the target; the view shows its `publicKey` line for
  `authorized_keys`. The host key is kept while host and port stay the same. A folder must be an
  absolute path outside the data directory (400).
- `POST …/offsite/test` → `{ "kind", "hostKey": "…" | null, "known": true }` (SFTP: first contact
  shows and remembers the host key); `POST …/offsite/forget-host-key` → the `GET` body. The test
  writes a small file there, reads it back and removes it.
- `POST …/offsite/run` → 202; progress in `GET`. 409 `conflict` while one runs.
- `GET …/offsite/snapshots` → list `{ id, date, bytes, version }`, newest first, each also with
  `hostname` (the public host of the server that made it) and `uploaded`.
- Errors of the target itself (unreachable, login refused, host key changed, damaged backup)
  are 502 `upstream` with the reason; settings that cannot work are 400.
- `POST …/offsite/restore` — `{ "snapshot", "masterPasswordHash" }`: like the local restore (a
  local backup first, only backups of this server, into the running server); bumps the server
  epoch (§4.3). Answer `{ "restored", "before", "files" }` (`before`: the local backup of how it
  was; `files`: how many files came back). The off-site settings and status stay those from
  before the restore; so they do when a local backup goes back.
- `POST …/offsite/recovery-key` — `{ "masterPasswordHash" }` → `{ "recoveryKey" }`.
- Command line (not HTTP): `uwulock-server backup restore --sftp … | --s3 … | --folder … --into /data`
  for a new machine, keys from the environment (`UWULOCK_BACKUP_KEY`,
  `UWULOCK_BACKUP_SFTP_PASSWORD`, `UWULOCK_BACKUP_S3_ACCESS_KEY`, `UWULOCK_BACKUP_S3_SECRET_KEY`);
  `--list`, `--snapshot`, `--host-key`, `--ssh-key`, `--endpoint`, `--region`, `--path-style`. It
  switches the off-site backups off in the restored database. `uwulock-server backup offsite`
  and `backup list` back up and list with the portal's settings ([backups.md](backups.md)).
- Too old (`warnAfterHours`): an alert (§21.3), a warning on the overview, the metric of §22.

### 21.3 Notification channels

- `GET /uwu/v1/admin/notifications` →
  `{ "object": "notificationChannels", "channels": [channel…], "events": ["backupFailed", "backupStale", "certificateExpiring", "updateAvailable", "manyFailedLogins", "diskLow", "pushRelayFailing", "mailFailing"] }`.
- A channel: `{ "id", "kind": "mail" | "ntfy" | "gotify" | "matrix", "name", "enabled", "events": [], "config": {} }` with
  `mail` `{}` (all admins), `ntfy` `{ "url": "https://ntfy.example.com", "topic", "tokenSet", "priority": 3 }`,
  `gotify` `{ "url", "tokenSet", "priority": 5 }`,
  `matrix` `{ "homeserver": "https://matrix.example.org", "roomId": "!abc:example.org", "accessTokenSet" }`.
- `POST /uwu/v1/admin/notifications` (new; secrets as `token` / `accessToken`),
  `PUT /uwu/v1/admin/notifications/{id}`, `DELETE /uwu/v1/admin/notifications/{id}`,
  `POST /uwu/v1/admin/notifications/{id}/test` → 200 or 502 `upstream` with the reason.
- Every channel also has `status: { lastSuccess, lastError, lastErrorDate, queued }`; the test
  answers `{ "object": "notificationTest", "ok": true }`. A new server has one `mail` channel.
- Sending: admin-configured hosts may be private (an ntfy in the LAN); no redirects; 10 s timeout;
  a failing channel is retried with backoff (1, 2, 4 … 60 minutes, given up after a day) and shown
  on the overview. Messages name no account data beyond counts. An event is sent when it starts —
  at most once an hour per channel however often it comes and goes — and once when it is over.
  ntfy gets the JSON publish (`POST <url>` with `topic`, `title`, `message`, `priority`, `tags`),
  Gotify `POST <url>/message` with `X-Gotify-Key`, Matrix `PUT
  <homeserver>/_matrix/client/v3/rooms/<room>/send/m.room.message/<txn>` with an `m.text`.

### 21.4 Admin networks

`adminNetworks` (§21.1): CIDRs. Empty: everywhere. Otherwise `/admin`, `/admin/**` and
`/uwu/v1/admin/**` answer 404 `Not found.` to any client IP outside them (the real client IP,
`ClientIp`, also behind a proxy with `trust_forwarded`), and an SSO login outside them does not
grant the admin right (§19.1). Vault, Sends and the command line are not affected. A `PUT` that
would shut out the IP making it is 400 `would_lock_out`. Escape hatch:
`uwulock-server settings set adminNetworks '[]'`.

### 21.5 Diagnosis

- `POST /uwu/v1/admin/diagnosis` → runs the checks (at most 30 s) and answers the result;
  `GET /uwu/v1/admin/diagnosis` → the last result (the server also runs it after every start with
  a new version).

  ```json
  {
    "object": "diagnosis",
    "date": "…",
    "version": "0.6.0",
    "checks": [
      { "id": "certificate", "status": "ok", "summary": "Valid until 2026-12-20", "detail": null, "fix": null },
      { "id": "proxy.websocket", "status": "error", "summary": "WebSockets do not get through", "detail": "…",
        "fix": { "text": "Pass the Upgrade headers on.", "caddy": "reverse_proxy …", "nginx": "proxy_set_header Upgrade $http_upgrade; …" } }
    ]
  }
  ```

  `status`: `ok`, `warning`, `error`, `skipped`. Check ids: `certificate` (and each send domain's),
  `clock` (offset from the `Date` of the push relay's and GitHub's answers — `UWULOCK_TIME_SOURCE`
names others or `off`, GitHub only while the update check is on; warning over 30 s, error over
2 min; `skipped` when none answers),
  `mail` (connect, EHLO, auth; nothing sent), `pushRelay`, `backup` (local and off-site age),
  `disk`, `proxy.clientIp` (a proxy peer without `X-Forwarded-For`, or `trust_forwarded` off
  behind a private peer; shows the IP it sees), `proxy.publicUrl` (the request's `Host`/`Origin`
  vs the configured public address), `proxy.websocket`, `proxy.uploadLimit`.
- The last two need the browser: the page opens `GET /uwu/v1/admin/diagnosis/websocket` (a
  WebSocket that echoes one message) and sends `POST /uwu/v1/admin/diagnosis/upload` (a body of
  16 MiB by default, or the largest allowed file on the "test the full size" button; the server
  counts and discards it, no body limit but the file limit, answers `{ "bytes": … }`), then
  `POST /uwu/v1/admin/diagnosis/client` `{ "websocket": { "ok": true, "error": null }, "upload": { "ok": false, "status": 413, "bytes": 16777216 } }`
  which is merged into the stored result. `proxy.clientIp` and `proxy.publicUrl` come from the
  admin's `POST`; in the run after an update they, like the browser checks, are `skipped` until
  the portal runs it. Texts come in the admin's language. The upload answers 413 `too_large` past
  the largest allowed file (plus 1 MiB). The WebSocket takes the token as `?access_token=`, like
  the hub, since a browser cannot set a header on one.

### 21.6 Overview additions

`GET /uwu/v1/admin/overview` gains `"alerts": [{ "kind": "backupStale", "severity": "warning", "since": "…", "detail": "…" }]`
(the events of §21.3 that are going on; `severity` `info`, `warning` or `error`; `detail` in the
admin's language) and `"storage": { "databaseBytes", "filesBytes": { "attachments", "sends", "fileRequests", "icons" } }`
(each kind once it exists). Also `"failingChannels": [{ "id", "name", "kind", "error" }]`,
`"loki": { "enabled", "queued", "sent", "dropped", "lastSuccess", "error" }` and
`"diagnosis": null | { "date", "errors", "warnings" }`.

### 21.7 Logs to Loki

`loki` (§21.1): the same JSON lines as `log.format = json`, pushed to `<url>/loki/api/v1/push`
with `labels` (never user data), `X-Scope-OrgID: <tenant>` when set, basic auth when set; batched
(1 s or 1 MiB), dropped with a counter when Loki is away for long (10,000 lines wait). The line is
tracing-subscriber's JSON format, `{ "timestamp", "level", "fields": { "message", … }, "target" }`,
which `UWULOCK_LOG_FORMAT=json` writes too; the server adds the label `level` (lower case).
`POST /uwu/v1/admin/settings/test-loki` — body: the `loki` object as typed, or none for the
saved one — → 200 or 502.

### 21.8 Allowed UwUMail servers

`masked.servers` (§21.1). `POST /uwu/v1/admin/masked/check` — `{ "url" }` →
`{ "discovery": true, "maskedScope": true, "registration": true, "error": null }`.

### 21.9 SSO

`GET|PUT /uwu/v1/admin/sso` — §19.1 (`clientSecret` write-only), `POST /uwu/v1/admin/sso/test`
(reads the discovery document and JWKS) → `{ "ok", "error" }`, `POST /uwu/v1/admin/sso/pair` and
`DELETE /uwu/v1/admin/sso/pairing` (§19.5), `POST /uwu/v1/admin/scim/token` → `{ "token" }` once
(for providers other than UwUAuth; replaces the old one).

### 21.10 Icons

`DELETE /uwu/v1/admin/icons/cache` (automatic icons), `POST /uwu/v1/admin/icons/library/refresh`
→ 202. `GET /uwu/v1/admin/icons` → `{ "object": "iconStatus", "cached", "cacheBytes", "ownBytes",
"libraryUpdated", "libraryIcons" }` for the portal (added).

### 21.11 Families and organizations

`GET /uwu/v1/admin/organizations` → list `{ "id", "name", "kind": "family" | "organization", "members", "owners": ["a@example.com"], "secretsManager", "creationDate" }`;
`DELETE /uwu/v1/admin/organizations/{id}` — `{ "masterPasswordHash" }` (the admin's). Admins see
no vault content.

---

## 22. Metrics

`GET /metrics` — Prometheus text format (`text/plain; version=0.0.4`). Off by default. With
`metrics.token`: `Authorization: Bearer <token>` (constant-time compare against its SHA-256), else
401. With `metrics.listen` (e.g. `127.0.0.1:9100`): served only on that extra listener, without a
token, and 404 on the public one. As UwUMail Server's `docs/metrics.md`. Labels never carry
addresses, names, hosts of icons, IPs or ids.

| Metric | Type | Labels |
| --- | --- | --- |
| `uwulock_build_info` | gauge (1) | `version` |
| `uwulock_http_requests_total` | counter | `route` (the route template, e.g. `/api/ciphers/{id}`), `method`, `status` |
| `uwulock_http_request_duration_seconds` | histogram | `route`, `method` |
| `uwulock_logins_total` | counter | `grant` (`password`, `refresh_token`, `client_credentials`, `webauthn`, `authorization_code`, `send_access`), `result` (`success`, `failure`, `two_factor`) |
| `uwulock_sync_duration_seconds` | histogram | `kind` (`bitwarden`, `full`, `delta`) |
| `uwulock_live_connections` | gauge | `channel` (`signalr`, `anonymous`, `realtime`) |
| `uwulock_push_relay_errors_total`, `uwulock_mail_errors_total`, `uwulock_mail_sent_total` | counter | – |
| `uwulock_database_bytes` | gauge | – |
| `uwulock_files_bytes` | gauge | `kind` (`attachments`, `sends`, `file_requests`, `icons`) |
| `uwulock_accounts`, `uwulock_items` | gauge | – |
| `uwulock_backup_last_success_timestamp_seconds` | gauge | `target` (`local`, `offsite`) |
| `uwulock_certificate_expiry_timestamp_seconds` | gauge | `domain` (`main` or the send domain's id) |
| `uwulock_icon_fetches_total` | counter | `result` (`found`, `none`, `refused`, `error`) |
| `uwulock_loki_dropped_total` | counter | – |

Plus the process collector (`process_*`). What does not exist yet is left out rather than
reported as 0: `kind` `file_requests`/`icons`, `channel` `realtime`, `target` `offsite`, the send
domains' certificates and `uwulock_icon_fetches_total` come with their features. `route` is
`other` for the web vault's files and unknown paths. `docs/metrics.md` ships example alert rules (backup
older than 2 days, certificate under 14 days, error rate, failed logins spike).

---

## 23. Browser extension

UwULock's own MV3 extension (Chromium and Firefox), `uwulock-core` as WebAssembly, talking to the
server directly. It asks for the host permission of the one server origin at setup
(`permissions.request({ origins: ["https://lock.example.com/*"] })`), so it needs no CORS.
Identity: `client_id=uwulock-extension`, `deviceType` Bitwarden's numbers (2 Chrome, 3 Firefox,
5 Edge, 19 Vivaldi, 20 Safari; others 2), `deviceName` e.g. "UwULock Chrome",
`deviceIdentifier` a UUID kept in `storage.local`.

| Purpose | Endpoints |
| --- | --- |
| Setup | `GET /uwu/v1/info`, **[BW]** `GET /api/config` |
| Log in | **[BW]** `POST /identity/accounts/prelogin`, `POST /identity/connect/token` (`password`, two-step, `refresh_token`), `POST /api/two-factor/send-email-login`; WebAuthn as second factor through the server's connector pages (`/webauthn-connector.html`, `/webauthn-fallback-connector.html`) as Bitwarden's extension does; SSO (§19.2) with `identity.launchWebAuthFlow` and the redirect URLs of §19.2 step 3; log in with a device: **[BW]** `POST /api/auth-requests`, then `GET /api/auth-requests/{id}/response?code=…` every 2 s (no SignalR in the extension) |
| Unlock | local (master password, PIN or the browser's platform authenticator, all local) |
| Sync | `GET /uwu/v1/sync` (full, then delta), `GET /uwu/v1/realtime` from the service worker; a `chrome.alarms` delta sync every 5 min when the worker slept; **[BW]** `GET /api/accounts/revision-date` is not needed |
| Items | **[BW]** `POST /api/ciphers` (personal), `POST /api/ciphers/create` (organization), `PUT /api/ciphers/{id}`, `PUT /api/ciphers/{id}/partial`, `PUT /api/ciphers/{id}/delete`, `POST /api/folders`; save/update prompts after a form submit use the same |
| Passkeys (provider) | **[BW]** the cipher's `login.fido2Credentials` (all fields EncStrings except `creationDate`: `credentialId`, `keyType` `public-key`, `keyAlgorithm` `ECDSA`, `keyCurve` `P-256`, `keyValue` (PKCS#8), `rpId`, `rpName`, `userHandle`, `userName`, `userDisplayName`, `counter`, `discoverable`) written with `PUT /api/ciphers/{id}` on registration and on each assertion (counter) |
| TOTP, generator | local |
| Masked address in the generator and at an item | `POST /uwu/v1/masked/addresses` (with the session, `forDomain` = the tab's origin), `GET /uwu/v1/masked/connection` |
| Icons | `GET /icons/{host}/icon.png` (fetched by the worker, shown as blob URLs, since the popup's CSP names no server), `POST /uwu/v1/icons/own/get` |
| Leaked-password check | `GET /uwu/v1/hibp/{prefix}` (optional) |
| Badges | `uwu.unseen` from the sync; opens the web vault for file requests and notices |
| Log out | drop tokens; **[BW]** `PUT /api/devices/identifier/{id}/clear-token` not needed (no push token) |

Travel mode, versions, reminders, file requests, Sends and account settings are not in the
extension; it links to the web vault.

---

## 24. Who uses what

| Area | Server | Web vault | UwULock desktop | Extension | Official clients | UwUSSH / UwURDP | UwUMail | UwUAuth |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| §2 info | ✓ | ✓ | ✓ | ✓ | | ✓ | | |
| §3 extras key, rotation | ✓ | ✓ | ✓ | ✓ (open only) | rotation side effects | ✓ (open, re-wrap) | | |
| §4 delta sync | ✓ | optional | ✓ | ✓ | | ✓ (`suite`) | | |
| §5 realtime | ✓ | optional | ✓ | ✓ | | ✓ | | |
| §6 suite | ✓ | list/delete | list/delete | | | ✓ | reserved space | |
| §7 icons | ✓ | ✓ | ✓ | ✓ | §7.1 | | | |
| §8 versions | ✓ | ✓ | ✓ | | | | | |
| §9 travel | ✓ | ✓ | ✓ | state only | effect only | | | |
| §10 reminders | ✓ | ✓ | ✓ | | | | | |
| §11 file requests | ✓ | ✓ (+ public page) | ✓ | badge | | | | |
| §12 notices | ✓ | ✓ | badge, report | report | event 1007 | | | |
| §13 masked | ✓ | ✓ | ✓ | ✓ | §13.4/§13.5 | | `maskedemail` scope | |
| §14 Sends | ✓ | ✓ | ✓ | | §14.3 | | | |
| §15 reports | ✓ | ✓ | optional | | | | | |
| §16 family | ✓ | ✓ (management) | read, share | read, share | read, share | | | |
| §17 Secrets Manager | ✓ | ✓ | | | `bws`, SDKs | | | |
| §18 Directory Connector | ✓ | API key | | | Directory Connector | | | |
| §19 SSO | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | pairing, SCIM |
| §20 policies | ✓ | ✓ | ✓ | ✓ | token response | | | |
| §21 admin | ✓ | admin portal | | | | | | |
| §22 metrics | ✓ | | | | | | | |

### Storage notes for the server (not contract, but decided)

- New columns: `seq` on every synced table (with indexes `(user_id, seq)` / `(organization_id, seq)`),
  `users.seq`, `users.sync_epoch`, `organizations.seq`, `devices.client_id`, `sends.domain_id`,
  `sends.emails`, `sends.auth_type`, `organizations.kind`, `organizations.secrets_manager`.
- New tables: `tombstones`, `extras_keys`, `suite_spaces`, `suite_records`, `own_icons`,
  `cipher_versions`, `travel` (+ folder flags), `reminders`, `file_requests`,
  `file_request_submissions`, `file_request_files`, `security_notices`, `masked_connections`,
  `masked_links`, `masked_api_keys`, `send_domains`, `send_otps` (or in memory), `sso_identities`,
  `sso_states`, `scim_provisioned`, `org_api_keys`, `sm_projects`, `sm_secrets`,
  `sm_service_accounts`, `sm_access_tokens`, `sm_access_policies`, `notification_channels`,
  `health_reports`, `branding` (images).
- Each in the SQLite migrations and the PostgreSQL ones (Stufe 5), behind `Store`.
- As built in Stufe 4c (migration 0010): `sends.emails` only — `authType` is derived (addresses →
  0, a password hash → 1, else 2), no `auth_type` column; the codes (`send_otps`) live in memory
  (`send_codes.rs`), a restart only means asking again; `branding` is keyed by `scope` (`""` the
  server, a send domain's id) with the pictures as PNG blobs; `health_reports`.
