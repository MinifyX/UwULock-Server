# Security review, September 2026

Before 0.4.0-beta.1, everything new since 0.1.0-beta.2 was reviewed in five parts, each by reading
the code paths end to end:

- logging in and identity;
- files and Sends;
- who may do what;
- the import, live updates, push and the password check;
- the web vault and the new crypto in `uwulock-core`.

Every finding was checked again before it was counted. There was nothing critical. The high and
medium findings are fixed in 0.4.0-beta.1, each with a test. The low ones are listed here, to be
fixed later.

## Fixed

| | Finding | Fix |
|---|---|---|
| High | An upload's parts next to the file were read whole before their size was checked. The upload routes have no body limit, so one logged-in request could fill the memory. | Every part is read in pieces and refused past 10 KB. An upload has at most 8 parts. |
| Medium | Uploads had no bound at all but the file size, so an account could fill the disk and take the database down with it. (There is still no quota per account, as decided.) | An upload is refused when it would leave less free space than a backup leaves (a twentieth of the disk, at least 256 MiB). |
| Medium | Rate limits for a Send's password, the master password of a session, and the second step of a login were checked first and only charged after a wrong try. Many tries sent at once all got through. | A try is taken first and given back when it was right. |
| Medium | "Log in with a device" told an anonymous caller whether an address has an account: the answer for an unknown address had fewer fields, and the limit per account only hit real ones. | Requests for unknown addresses are kept in memory like real ones and answered the same way. The limit counts per address before the lookup. |
| Medium | An emergency takeover left the grantor in their organisations, so the contact also got what other people shared with them. | A takeover takes the grantor out of every organisation they do not own, as Bitwarden does. |
| Medium | The anonymous notification hub took any token, messages of up to 64 MiB, and counted IPv6 addresses one by one, with no ceiling. A client that never said hello stayed connected. | The token has to be a waiting request. Messages are at most 16 KiB. An IPv6 address counts by its /64, and there are at most 1000 anonymous connections. The handshake has to come within 10 seconds. |
| Medium | Running `import-vaultwarden` a second time wrote over the files of the first import, then deleted them when it found the accounts were there already. | Existing accounts stop the import before anything is touched, the dry run included. No file is written over, and a stopped import only removes files it wrote itself. |
| Medium | When the vault got new keys, the web vault wrapped the new user key for the emergency contacts' public keys as the server handed them out, without the fingerprint check done when the contacts were confirmed. | The dialog shows every contact's fingerprint phrase to compare first, and wraps for exactly the keys it showed. |

## Low: open

Logging in:

- A stolen access token (valid for an hour) can approve its own "log in with a device" request
  and so get a device that stays logged in. That device still cannot decrypt anything, and the
  mail for a new device goes out (it is on by default). Bitwarden works the same way. Idea: always
  send a mail when a request is approved.
- Requests of type "unlock only" can also be used to log in. Bitwarden only allows this for
  "authenticate and unlock".
- The WebAuthn challenges waiting in memory are only cleaned out past 10,000 entries, and then
  only expired ones.
- Accounts moved in from Vaultwarden that have not logged in since are slower to check (PBKDF2
  with Vaultwarden's rounds). This lets somebody tell them apart by timing.
- Refresh tokens moved in from Vaultwarden also work without Vaultwarden's signature, and on that
  path they are not replaced. Whoever has the old Vaultwarden database keeps those devices logged
  in. After moving in, destroy the old data.
- Key rotation is refused for a passkey that can do PRF but is not set up for unlocking.
- Rotation also refuses accounts enrolled in an organisation's account recovery (imported only).

Files and Sends:

- An upload that stalls has no deadline of its own, so it holds a file descriptor for as long as
  the connection lives.
- A Send with a maximum number of openings counts one too many for the newest clients, so the
  last opening fails. One counted opening also allows file links for two minutes.
- Two uploads to the same attachment at the same time share one partial file. A Send upload
  writes back the Send as it was when the upload began.
- Attachment and Send download tokens share one issuer, which is safe only because the server
  makes every id.
- A Send's download link, once issued, keeps working for its five minutes after the Send is
  disabled.

Who may do what:

- Emergency access changes write the whole row back, so two at the same moment can undo each
  other or bring back a deleted contact.
- Inviting an emergency contact tells a logged-in user whether an address has an account, and
  so does inviting somebody to the server (for those allowed to).
- Users who may invite get the signup link back, so they could register the address themselves.
  Without a mail server, an emergency invitation to an existing account is accepted at once.
- The number of invitations per user can be passed with requests sent at the same time.
- `manage` on a collection is not checked: edit rights are enough to delete, as in Vaultwarden.
  The comment in the store says otherwise.

Import, live updates and the password check:

- Connections to the hub are not checked again after they are opened. After a password change or
  a logout they keep getting ids and times (no contents) until they close.
- Access tokens in the hub's address can end up in a reverse proxy's access log.
- The shared cache for Have I Been Pwned lets one user notice whether somebody on the server
  checked a password with the same hash prefix in the last day.
- The import builds file paths from the Vaultwarden database without checking them. This only
  matters for a crafted database.
- Two-step login by Duo, YubiKey OTP or U2F does not come over, and the affected users are not
  told (only the admin, in the summary).

Web vault:

- Rotation sends the account's public key as the server had it, instead of deriving it from the
  private key.
- The connector pages can be framed by any browser extension and by `file:`.
- The length decoder of the live connection can run for a long time on a malformed frame from
  the server.
- The server sees the first five characters of each password's SHA-1 hash in the password check.
- Emergency takeover uses the KDF settings the server hands out, which may be weak ones.

Also known:

- Restoring an older backup brings back the sessions and tokens that were valid then.
- Organisation policies from Vaultwarden are shown to the clients but not enforced by the server.
