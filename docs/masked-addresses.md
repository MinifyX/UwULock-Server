# Masked addresses

A mail address of its own for every website, from your UwUMail server: mail to it lands in your
mailbox, and an address that gets spam or was sold is simply switched off. UwULock makes them for
you — in the web vault, in the UwULock app, and in the official Bitwarden apps' generator — through
UwUMail's JMAP `MaskedEmail`, with an OAuth grant you give once.

## For the admin

*Admin portal → Vault & features → Masked addresses.* List the UwUMail servers accounts may
connect to, with the name people see (`https://mail.example.com`, "UwUMail"). *Check* tells
whether the server answers OAuth discovery, offers the `maskedemail` scope and lets apps register.
The Lock server talks to these servers and no others; they may be in the local network, since only
an admin can list them. Nothing listed: no masked addresses, and the web vault does not offer them.

UwUMail needs the `maskedemail` scope (UwUMail Server with the masked-only scope), JMAP switched on
for the account, and a domain its masked-address policy allows for that person.

## Connecting

*Web vault → Settings → Masked addresses → Connect UwUMail.* The browser goes to UwUMail, you log
in there and agree that "UwULock (lock.example.com)" may create and manage your masked addresses.
It cannot read or send your mail with that. Then you are back in the web vault and unlock it once
more. The page shows the mailbox, its domains and which one new addresses get by default.

What happens underneath:

- The Lock server registers itself at UwUMail as an OAuth client (a public one, no secret) and
  keeps the client id; when UwUMail forgot it (unused for seven days), it registers again.
- The code flow uses PKCE (S256), a single-use `state` and a cookie that ties the answer to the
  browser that asked; the answer must name the UwUMail server as its issuer.
- The access and refresh token are kept encrypted (AES-256-GCM) under `secret.key` in the data
  directory, not in the vault — so the official apps can make addresses too. Backups take the file
  along. Tokens are never logged.
- UwUMail hands out a new refresh token with every refresh and ends the whole grant when an old
  one comes back. So the server refreshes one at a time per account and stores the new token
  before it uses the new access token.

The connection is listed at UwUMail under *My account → Security → Apps signed in with OAuth*, and
can be ended there or here (*Disconnect …*). Disconnecting ends the grant at UwUMail; the addresses
stay there and keep getting mail. Connecting and disconnecting are security notices of the account.
Deleting the account ends the grant too.

**State**: *connected*; *not reachable* (the last call to UwUMail failed — it tries again next
time); *ended* (UwUMail ended the grant, for example because it was signed out there — connect
again).

## Making addresses

- **Settings → Masked addresses → New address …**: for which website, a description, the domain.
- **The generator**: *Masked address (UwUMail)* makes one for the item being edited.
- **At an item**: next to the username, *Create a masked address* puts one there; the item then
  shows it has one, and UwUMail keeps a link back to the item (`#/vault?itemId=…`).

New addresses are *enabled* straight away (not *pending*: an address in a password manager must
not vanish because no mail came in a day). Each item has at most one masked address.

The list shows every address with its state, the last mail and its item; switch it off, on, or
delete it. Deleting is for good: UwUMail refuses mail to it and never hands it out again. When you
delete an item for good, the web vault asks whether to switch its address off (yes by default).

Limits: 30 new addresses a minute and 500 a day per account; UwUMail allows 5000 per mailbox.

## In the official Bitwarden apps

The Bitwarden generator can make forwarding addresses through addy.io or SimpleLogin; UwULock
speaks both, with keys of its own.

1. *Settings → Masked addresses → For the Bitwarden apps → Create a key* (asks for the master
   password). The key (`uwulock_ma_…`) is shown once; up to ten per account, one per app.
2. In the app: *Generator → Username → Forwarded email alias*, service **addy.io**,
   *Self-host server URL* `https://lock.example.com/uwu/v1/masked/addy`, *API access token* the
   key, *Domain name* one of your UwUMail domains (anything else gets UwUMail's default).
   Or service **SimpleLogin**, *Self-host server URL*
   `https://lock.example.com/uwu/v1/masked/simplelogin`, *API key* the key.

The web vault shows both addresses to copy. The website comes from the app's description
("Website: shop.example.com …"). A key only makes masked addresses; it is no login anywhere.
Deleting it stops the app that has it. Wrong keys count like wrong logins.

The API is in [uwu-api.md](uwu-api.md) §13.
