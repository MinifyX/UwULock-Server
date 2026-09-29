# Families

A family shares items between a few people: passwords for the streaming service, the router, the
insurance. It is Bitwarden's "Families" organisation — collections with read or write access per
member — made and managed in UwULock's web vault, and seen by every client: the official
Bitwarden apps, extension and CLI, and the UwULock app. (Stufe 5's organisations for companies
build on the same ground: groups, policies, account recovery and the event log come with them.)

## How it is encrypted

A family has a key of its own. Everything in it — the items, their attachments, the collections'
names — is encrypted under that key by the client that saves it; the server keeps only what it
cannot read.

Each member holds the family key wrapped for their account's public key. The server hands it
out, but it never had it in the clear, and it cannot make one: when an owner confirms a member,
**the owner's browser** wraps the key for the member's public key. That public key comes from the
server, so the owner compares its **fingerprint phrase** with the member first — five words,
shown in the confirm dialog and in the member's own settings under *Account → Fingerprint*.
Only when they are the same does the key go to the right person. Compare them in person or on the
phone, not by mail.

## For everybody

**Making one.** In the web vault, *Families* in the sidebar, **+**: a name and the first
collection. You are its owner. The admin decides who may make a family, how many members one has
at most (invited people count) and how many one account may own.

**Inviting.** On the family's page (*Members & collections*), **Invite**: addresses, member or
owner, and for a member which collections they read or also change.

- Somebody with an account here gets a mail with a link; logged in with that address, they also
  find the invitation in the sidebar of their vault and accept it there (without mail, that is
  the way).
- Somebody without one: if you may invite people to the server (the admin's invitation rules,
  within your quota), the same link lets them create their account, and that accepts the
  invitation too. Otherwise the mail tells them to ask whoever runs the server for an invitation
  first. You never learn which addresses have an account.

**Confirming.** A member who accepted waits for an owner: *Confirm …* shows the phrase to
compare. Owners get a mail when somebody waits. After confirming, the member sees what the
family shares on every device after its next sync (live updates make that at once).

**Roles.** *Owners* manage members and collections and see every item of the family, also those
in no collection. *Members* see the collections they are given — read only, or read and change
(put items in, change them, delete them). A family always keeps a confirmed owner: to hand it
over, make somebody else an owner, then leave or become a member.

**Collections.** Owners make, rename and delete them, and set who reaches each. Deleting a
collection leaves its items in the family (visible to owners only) until they go into another.

**Sharing an item.** In an item's details, the house button moves it into a family and its
collections: the item is encrypted anew under the family's key and leaves your own vault. The
grid button changes the collections of a family's item. The official apps do the same with
*Move to organisation* / *Collections*, the CLI with `bw move` and `bw edit item-collections`, and
`bw create item` with `organizationId` and `collectionIds`.

**Leaving, removing, deleting.** Anybody but the last owner may leave. An owner removes members
and deletes the family (with the master password) — its items go with it, for everybody. What a
removed member's devices had synced may stay there until they sync again: change passwords that
matter.

**Security notices.** Being confirmed into a family, removed from one (or it was deleted) and a
changed role show up under *Settings → Security*, and are mailed like the other notices.

An account that is the only owner of a family with other people in it cannot be deleted: make
somebody else an owner, or delete the family, first.

## For admins

*Settings → Families* in the admin portal:

| Setting | Default | |
| --- | --- | --- |
| Who may make a family | everyone | `everyone`, `admins` or `nobody` |
| Members per family | 6 | 2–50, invited people count |
| Families per account | 1 | 0–10 |

*Families* in the portal lists every family with its owners and how many are in it — nothing of
what it shares — and deletes one (with your master password), for example when its only owner is
gone.

Organisations moved over from Vaultwarden are families when they have only owners and members and
no groups or policies; then they are managed here like any family. Others work as before (their
members save items where their collections let them) and are managed with Stufe 5.

## For developers

The endpoints are Bitwarden's (`/api/organizations/…`, `…/users`, `…/collections`); what UwULock
adds is small: `GET /uwu/v1/organizations/invitations` and accepting without the link's token when
logged in with the invited address. The exact shapes are in [uwu-api.md §16](uwu-api.md).
