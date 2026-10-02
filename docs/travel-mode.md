# Travel mode, versions and reminders

## Travel mode

Crossing a border with a laptop or a phone that somebody may ask you to unlock? Travel mode takes
folders you choose off every device — the web vault, UwULock, and the Bitwarden apps and
extensions too, at their next sync — until you switch it off again.

1. Put what should not travel into one or more folders.
2. *Web vault → Settings → Travel mode*: tick the folders under *Hide while travelling*.
3. *Switch travel mode on* — from any device. Every device syncs at once (the ones that are
   online); the marked folders and their items, attachments, versions, own icons and reminders
   are gone from them.

Switching it off needs the **master password and the second step of your login** (authenticator
app, a code by mail, or a security key; not the recovery code). So travel mode needs two-step
login. Five wrong tries, and the next one waits a few minutes; every wrong try is listed under
*Settings → Security* and mailed to you.

While travel mode is on, two-step login stays exactly as it is: it cannot be switched off,
replaced or set up anew, the authenticator key and the recovery code are not shown, and the
recovery code does not work at login. Otherwise whoever holds your unlocked device and your master
password could take the second step away and switch travel mode off. Lost the phone with the
authenticator on the way? An admin can reset your two-step login (*Admin portal → Users &
invitations → Accounts*); after that, and after an emergency contact took the account over, the
master password alone switches travel mode off. Keep the recovery code at home — it is for the day travel mode is off.

While it is on:

- The server leaves the hidden items out of everything the account asks for — the sync, single
  items, attachments (also download links made before), versions, icons, reminders, and what an
  emergency contact sees. For the account it is as if they were not there.
- You can mark more folders (they disappear at once), but none can come back.
- Emptying the vault and giving the vault new keys wait until it is off.
- The server knows the folders only by their ids, never their names.

An organisation's items that you filed into a marked folder are hidden for you; the organisation
and its other members still see them.

## Earlier versions of items

Whenever an item changes — its name, a password, a note, a field — the server keeps the state it
had before, encrypted as it was. *Web vault → an item → Earlier versions* lists them; *Show* opens
one in your browser, *Bring back* makes it the item's content again (and what the item held
becomes a version itself). Attachments, the folder and the favourite star are not versioned.

The admin decides how many versions an item keeps (20 by default, 0 for none) and for how many
days (365). Versions count toward the storage of the account (of the organisation, for its
items). An item deleted for good takes its versions along.

When you give the vault new keys in the web vault (*Settings → Account → Re-encrypt*) or in
UwULock, the versions are encrypted again with them. The Bitwarden apps do not know versions:
when one of them rotates the keys, the server deletes the versions of your own items, since they
could not be opened any more.

## Reminders to renew a password

*Web vault → an item → Edit → Remind me to renew* (a switch, off by default): after a number of
months (counted from the last change of the password, or from when the item was made) or on a
day. Only while it is on does the item's page show a *Reminder to renew* card with the next date;
switching it off in the editor removes the reminder. When it is due, the
item gets a bell in the list, the vault a *Due* section, and you a mail — "An item in your vault is
due for a new password" — that names no item and links to the list. The server keeps only the
item's id and the day. A new password moves a repeating reminder on; a reminder for a day that has
passed ends with it.
