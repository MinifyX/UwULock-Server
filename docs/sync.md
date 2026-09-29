# Delta sync and the realtime channel

Bitwarden's apps fetch the whole vault at every sync (`/api/sync`) and hear of changes through
Bitwarden's SignalR hub. That stays as it is. UwULock's own clients — the desktop app, the browser
extension, UwUSSH and UwURDP — use two lighter things instead, described for developers in
[uwu-api.md](uwu-api.md) §4 and §5:

- **Delta sync** (`GET /uwu/v1/sync`): the first sync gets everything, as `/api/sync` would, plus
  UwULock's own (the extras key, own icons, reminders, travel mode, the unseen counts) and the
  suite vault if asked for. It comes with a cursor; the next sync hands the cursor back and gets
  only what changed since, deletions included.
- **Realtime channel** (`/uwu/v1/realtime`): one WebSocket per device that says *that* something
  changed — never what — so the device asks for a delta at once. It carries no secrets and may
  lose a message: the delta sync is the truth.

## How the server keeps track

Every account and every organisation counts its changes. Each write to something an account sees
— an item, a folder, a Send, the profile, a reminder, an own icon, the extras key, a suite record
— takes the next number of that counter, in the same transaction, from database triggers, so no
way of writing (an import, a rotation, a member removed) can forget one. A change to a shared item
is counted once for the organisation, not once per member. What is deleted for good leaves a
*tombstone* with its number; items in the trash are ordinary changes.

Some changes cannot be said as a delta; after them the next sync of the account is a full one
again (`reset: true`):

- new keys (a rotation by any client), a new master password or KDF, "log out everywhere";
- joining, leaving or being removed from a family, a change of the collections or rights one has
  there, a family deleted;
- travel mode switched on or off, or a hidden folder added while it is on;
- the whole vault emptied, an import of more than 1000 items;
- the extras key lost or started over; a suite space deleted or given a new key;
- a **backup put back** (from the admin portal or with `uwulock-server restore`): every cursor
  of every account starts over. So do cursors that were made for other areas (`include`) than the
  one they are used with.

Tombstones are kept **90 days**; the nightly maintenance removes older ones (and deleted suite
records). A device that did not sync for longer gets a full sync — nothing is lost, it only takes
a little longer.

A long delta comes in pages (`limit`, 500 changes by default, at most 1000; `hasMore: true` means
"ask again at once"). Pages are cut between change numbers, so a page never holds half of one.

## The realtime channel

The client opens `wss://<server>/uwu/v1/realtime` with the subprotocol `uwu.realtime.v1` and sends
its access token in the first message (never in the address, so it does not end up in a proxy's
log). The server answers `ready` with the time the token runs out; before that the client sends a
fresh token on the same connection. It then hears:

| Message | When |
| --- | --- |
| `changed` (`vault`, `uwu`, `suite` with the space) | something of the account changed on another device |
| `logout` | the session ended: new password or keys, "log out everywhere", the device removed, the account disabled |
| `authRequest` | a "log in with a device" request waits for approval |
| `notice` | a new security notice, something arrived for a file request, a reminder became due |
| `info` | the admin changed a setting (the client fetches `/uwu/v1/info` again) |

The server pings every 25 seconds and checks the session at every ping, like the SignalR hub. An
account may keep 20 connections open; a client may send about one message a second. Every change
that goes to the SignalR hub goes to the realtime channel as well, from the same place in the
server, so both always tell the same story.

A suite app's connection hears only changes in its own space, the end of its session and `info`.

**Behind a reverse proxy**, `/uwu/v1/realtime` is a WebSocket like `/notifications/hub`: the
proxy configurations in [deployment.md](deployment.md) pass both. Caddy does it without anything
extra.

## Numbers

Measured and noted in [performance.md](performance.md). The admin sees them live in the metrics
([metrics.md](metrics.md)): `uwulock_sync_duration_seconds{kind="full"|"delta"}` and
`uwulock_live_connections{channel="realtime"}`.
