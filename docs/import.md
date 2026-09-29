# Moving in from another password manager

*Web vault → Settings → Import & Export → Import* reads the export of another password manager
and brings its items into your vault: logins, secure notes, cards and identities, folders, TOTP
secrets, favourites and custom fields.

1. Export from the old app (see below for each). Most exports are **not encrypted**: every
   password is in the file in plain text. Delete it once the import is done.
2. Choose the app under *Import from*, or leave it at *Detect automatically*, and pick the file.
3. A KeePass database asks for its password, and its key file if it has one.
4. The preview shows how many logins, notes, cards and identities are in the file, which folders
   will be created, every item with its user name, folder and a TOTP mark, and anything you
   should know (fields without a place of their own, attachments that can't come along, items
   left out). Nothing is in the vault yet.
5. *Import N items* — they are encrypted in the browser and sent to the server, and the vault
   syncs.

## Everything happens in the browser

The file never goes to the server. The web vault reads it, turns it into Bitwarden's unencrypted
JSON export format in memory, shows the preview, and hands it to the same import that reads
Bitwarden's own exports: that encrypts each item with your vault's key and sends only the
encrypted items. What the file held is dropped from memory after the import or the cancel.

Folders are created by name, as a Bitwarden export creates them; a folder path like `Private/Banks`
shows as *Banks* inside *Private*. If you already have a folder of the same name, you get a second
one — merge them by moving the items.

## Apps and what comes along

In every format, a value that has no field of its own in UwULock becomes a **custom field** —
hidden, when the source marked it secret or its name sounds like one (PIN, password, token, key,
secret, …) — or goes into the **notes** when it is long or has several lines. Nothing is dropped
silently; the preview says how many items got such fields. A card or note that came with a user
name, password or address keeps them the same way.

| App | Export to use | Logins | Notes | Cards | Identities | Folders | TOTP | Favourites |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Bitwarden, Vaultwarden, UwULock | JSON (unencrypted) or CSV | ✓ | ✓ | JSON | JSON | ✓ | ✓ | ✓ |
| KeePass, KeePassXC | the `.kdbx` database itself, KeePass XML, or CSV | ✓ | ✓ | | | groups | ✓ | |
| 1Password | `.1pux` (1Password 8), or CSV | ✓ | ✓ | ✓ | ✓ | vaults | ✓ | ✓ |
| Chrome, Edge (Chromium) | *Password Manager → Settings → Export passwords* (CSV) | ✓ | | | | | | |
| Firefox | *about:logins → ⋯ → Export passwords* (CSV) | ✓ | | | | | | |
| Apple Passwords (Safari) | *Passwords app → File → Export All Passwords* (CSV) | ✓ | | | | | ✓ | |
| Proton Pass | *Settings → Export*, unencrypted: JSON (zip) or CSV | ✓ | ✓ | ✓ | ✓ | vaults | ✓ | pinned |
| LastPass | *Advanced options → Export* (CSV) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### KeePass and KeePassXC

The database file (`.kdbx`) is opened directly — no export needed:

- **KDBX 4.0 and 4.1** (KeePassXC and KeePass 2.35 and newer), and **KDBX 3.1** (older files,
  and what KeePass 2 still writes with AES-KDF).
- Encryption **AES-256** or **ChaCha20**. Twofish isn't supported: switch the database to
  AES-256 or ChaCha20 in the app's database settings, save, and import again.
- Key derivation **Argon2d**, **Argon2id** or **AES-KDF**, with any parameters the browser has
  memory for (up to 2 GiB for Argon2). The derivation runs in the page; with the defaults of
  KeePassXC that takes a second or two, with very large settings longer.
- A **key file**: KeePass's XML key files (version 1.0 and 2.0), 32-byte binary files, 64 hex
  digits, or any other file (its SHA-256 is the key, as KeePass does it). A password, a key
  file, or both. Challenge-response (YubiKey) and Windows user accounts can't be used; remove
  them in the app first, or export to CSV.
- KeePass 1 files (`.kdb`) aren't read: open them in KeePassXC or KeePass 2 and save as KDBX.

What comes along: groups as folders by path (without the root group; the recycle bin and the
template group are left out), *Title*, *User name*, *Password*, *URL* and *Notes*, additional
URLs (`KP2A_URL`, `KP2A_URL_1`, …), every other field as a custom field (protected ones hidden),
tags and the expiry date as custom fields, and up to five older passwords from an entry's
history. TOTP from KeePassXC's `otp` field (an `otpauth://` address, or the older
`key=…&step=…&size=…`), from KeePass 2.47's *TimeOtp-\** fields and from KeeTrayTOTP's *TOTP
Seed* and *TOTP Settings*; Steam codes as `steam://`. Attachments, icons and auto-type don't
come along.

KeePass's XML export and the CSV exports of KeePassXC (`"Group","Title","Username",…`) and
KeePass 2 (`"Account","Login Name",…`) work too, with fewer details.

### 1Password

The `.1pux` export (*File → Export* in 1Password 8, "1PUX") has everything: categories become
logins (also passwords, databases, servers, routers, API credentials), cards, identities (also
driver's licences, passports, memberships, reward programmes, social security numbers),
secure notes (also software licences, bank accounts, email accounts, medical records, documents)
and SSH keys. Section fields go to the matching place by their id, TOTP fields to the login,
everything else becomes a custom field. When the export holds several vaults, each becomes a
folder. Tags become a custom field; archived items come in as ordinary items. Documents and file
attachments don't come along.

The CSV export (1Password 8's `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes`,
and older ones with other columns) has logins only, plus cards and identities from older exports
that name their type.

### Browsers

Chrome and Edge (`name,url,username,password,note`), Firefox (`url,username,password,httpRealm,…`;
the name comes from the address) and Apple Passwords (`Title,URL,Username,Password,Notes,OTPAuth`)
have logins only. Passwords of Android apps from Chrome come as `androidapp://` addresses.
Firefox's own account (`chrome://FirefoxAccounts`) is left out.

### Proton Pass

The unencrypted JSON export — the zip Proton Pass writes (`Proton Pass/data.json`), or the JSON
taken out of it — has everything: logins (the email as a field when there is also a user name),
aliases (as logins with the alias address), notes, cards (the PIN as a hidden field), identities,
SSH keys and custom items, each with its extra fields. When there are several vaults, each
becomes a folder. Items in the trash are left out. Passkeys don't come along.

A PGP-encrypted export can't be read: export again without encryption. The CSV export works
too, with logins, notes and aliases only.

### LastPass

The CSV export: sites as logins (grouping as folder, `\` as separator), secure notes as notes,
and LastPass's forms — *Credit Card*, *Address*, *Passport*, *Driver's License*, *Social
Security* — as cards and identities. The fields of other forms (bank accounts, Wi-Fi, …) become
custom fields of a note. Form-fill profiles in older exports become cards and identities.

## What doesn't come along

- **Attachments and documents**: the import goes through Bitwarden's JSON format, which has
  none. The preview counts them; save them from the old app and attach them again.
- **Passkeys** from Proton Pass: their format differs; set them up again.
- Icons, auto-type rules, and the old app's timestamps.

## Where the mapping comes from

The field mapping follows Bitwarden's importers ([bitwarden/clients](https://github.com/bitwarden/clients),
`libs/importer/src/importers/`, GPL-3.0): the KeePass XML and KeePassX CSV importers, the
1Password 1PUX and CSV importers, the Chrome, Firefox and Safari CSV importers, the Proton Pass
JSON importer, the LastPass CSV importer and the shared base importer. Differences: several
vaults become folders (Bitwarden makes a folder of the first tag in 1Password, and of every
Proton Pass vault), bank accounts from 1Password become notes rather than cards, and KeePass
files are opened directly. The code is in `web/src/lib/import/`.
