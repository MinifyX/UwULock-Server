# The suite vault: UwUSSH and UwURDP on UwULock

UwUSSH and UwURDP can keep their hosts, keys, snippets and connections on a UwULock Server
instead of a UwUSync server: one account, one master password, one place for backups. The
records stay what they were on UwUSync — sealed by the apps under a key the server never sees,
merged by the apps with their clocks — only the transport, the login and the key's home change.
For developers: [uwu-api.md](uwu-api.md) §6.

They are **not** items of the vault: Bitwarden's apps would stumble over types they do not know,
so the records live beside the vault, in one *space* per app (`ssh` for UwUSSH, `rdp` for UwURDP;
`mail` and `generic` are kept free for other UwU apps).

## Using it

In UwUSSH or UwURDP: *Settings → Sync → UwULock*, then the server's address, the account's email
and master password (and the second step of the login, if the account has one — authenticator,
a code by mail, a YubiKey; "remember this device" works too).

- The app logs in **as an app of its own** (`client_id` `uwussh` or `uwurdp`, scope `uwu.suite`).
  Its session can do nothing but its space: not read the vault, not change the account, not
  reach the other app's space. The web vault lists it under *Settings → Devices* with the app's
  name, where it can be removed like any device.
- Every such login is a **security notice** (*Settings → Security*, and in the notice mail): the
  app got at its data.
- The first UwU app of an account makes the account's **extras key** (the web vault or UwULock
  may have made it already), and the first device of an app makes its space and the space's key.
  Every other device takes them. The space key is kept under the extras key, the extras key under
  the account's keys: the server holds nothing that opens any of it.
- The devices keep each other up to date through the **realtime channel**
  ([sync.md](sync.md)): a change on one device reaches the others within a moment.

**Moving from UwUSync** is one button in the apps' sync settings: the app logs in to UwULock,
copies every record from UwUSync, sealed again for the UwULock space, reads the copy back and
compares it, and only then switches. Running it again, or on a second device, merges and copies
nothing twice. UwULock Server does not read UwUSync's database itself — the records there are
sealed with keys only the apps have.

**When a device is lost**, remove it in the web vault (*Settings → Devices*): its session ends at
once, and its refresh token is gone. The server can also give a space a new key and id, with
every record sealed again (`POST /uwu/v1/suite/spaces/{space}/rekey`), after which every other
device has to log in again; the apps offer that once they have it.

## What the server keeps and checks

- A record is at most 256 KiB sealed; a push brings at most 500 records and 8 MiB; a pull pages
  through 500 at a time.
- Per account and across its spaces: at most **50,000 records** and **256 MiB** by default
  (*Admin portal → Vault & features → Storage & limits*, `suite.maxRecords` / `suite.maxMb`). The suite counts
  towards the account's storage limit as well. Over it, the push is refused as a whole.
- Deleted records stay as tombstones for 90 days, so that every device hears of the deletion.
- The suite vault is a feature switch (*Admin portal → Vault & features → Features*, [features.md](features.md)).
  Off, suite logins are refused and the spaces answer 404 `feature_off` (their data stays).
- Deleting a space is for the account itself — in the web vault, with the master password —
  never for an app. Starting the extras key over (*Settings → Security*) deletes every space with
  it.

## Where the space shows in the web vault

*Settings → Devices* shows the apps' devices with the app's name, and below them, under *Suite
vault*, the spaces with the number of records, their size and the last change; a space can be
deleted there (with the master password). What is in them the web vault cannot show — only the
apps can open the records.
