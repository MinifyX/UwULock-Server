# Security review, September 2026

Before 0.4.0-beta.1, everything new since 0.1.0-beta.2 was reviewed in five parts, each by reading
the code paths end to end:

- logging in and identity;
- files and Sends;
- who may do what;
- the import, live updates, push and the password check;
- the web vault and the new crypto in `uwulock-core`.

Every finding was checked again before it was counted. There was nothing critical. The high and
medium findings are fixed in 0.4.0-beta.1, each with a test; the low ones in 0.4.0-beta.2.

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

## Low: fixed in 0.4.0-beta.2

Logging in:

- A login by another device's approval always sends the mail about a new login, whatever the
  setting, and every approval is in the event log. (A stolen access token could approve its own
  request and so get a device that stays logged in.)
- Requests of type "unlock only" no longer log in.
- The WebAuthn challenges waiting in memory have a hard ceiling; the oldest go first.
- While password hashes from Vaultwarden are left, every login does the work of both kinds of
  hash, so its time says nothing about the account.
- Refresh tokens from Vaultwarden are kept apart from this server's and replaced at their first
  use, bare or signed; the docs say to destroy the old Vaultwarden data.
- Key rotation leaves out passkeys that cannot unlock, and takes account recovery enrolments
  along (an enrolment left out ends).

Files and Sends:

- Uploads give up after a minute without a byte, and an account runs at most four at once.
- Every upload has a file name of its own while it arrives, a file that is there is never
  written over, and an attachment or a Send's file is marked uploaded once. A Send upload
  changes nothing else of the Send.
- The newest clients' way of opening a Send counts a text once and every file download link, so
  the last allowed opening works.
- Download links are signed for an attachment or for a Send's file, never both, and a Send's
  link stops working with the Send.

Who may do what:

- Emergency access is written back only when it did not change in between.
- Inviting an emergency contact answers the same whether the address has an account, and is
  limited per grantor. It is never accepted by itself any more, not even without mail: the
  contact accepts in their settings, where invitations now wait.
- Users who invite learn nothing about accounts, get the signup link only when the server cannot
  mail it, and cannot pass their quota with requests sent at once.
- The comment in the store says what edit rights allow; `manage` matters from Stufe 5 on.

Import, live updates and the password check:

- Connections to the hub are checked again at every ping (15 seconds) and end with their
  session: a password change, a logout, a disabled account, a token that ran out.
- The docs show how to keep the access token in the hub's address out of Caddy's and nginx's
  logs.
- The cache for Have I Been Pwned is per account. The web vault says what the server sees.
- The import checks every id before it becomes a path.
- Whoever loses their only second step in the import gets a mail (or is named for the admin to
  tell).

Web vault:

- Rotation refuses to go on when the public key the server has is not the one that belongs to
  the account's private key.
- The connector pages may be framed only by Bitwarden's extension in Chrome and Edge (by its id),
  and by Firefox and Safari extensions; not by any other extension, and not by `file:`.
- The length decoder of the live connection reads at most five bytes and stops at a length that
  does not fit.
- An emergency takeover gives the new password today's key derivation when the grantor's is
  weaker.

Also:

- Putting a backup back ends every session, in the portal and on the command line.

## Stays as it is

- The server sees the first five characters of a password's SHA-1 hash while it asks Have I
  Been Pwned; it writes them nowhere. That is the price of the browser never talking to anybody
  but its own server, as decided.
- The clients carry the access token in the hub's address, as Bitwarden's do. It works for an
  hour; keep it out of access logs (see above).
- Organisation policies from Vaultwarden are shown to the clients, which follow them, but not
  enforced by the server before Stufe 5.
