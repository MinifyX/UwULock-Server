-- The suite vault (Stufe 6; docs/uwu-api.md §6): the records of UwUSSH, UwURDP and the other UwU
-- apps, in UwUSync's record model, sealed by the apps under a space key the server never sees.

-- One app's data in one account. `id` is the space's id the apps seal into every record; `key`
-- the space key under the account's extras key. `epoch` is the account's change number when the
-- space got its key: a pull from before that starts over.
CREATE TABLE suite_spaces (
    user_id  TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    space    TEXT NOT NULL,
    id       TEXT NOT NULL UNIQUE,
    key      TEXT NOT NULL,
    seq      INTEGER NOT NULL,
    epoch    INTEGER NOT NULL DEFAULT 0,
    created  TEXT NOT NULL,
    revision TEXT NOT NULL,
    PRIMARY KEY (user_id, space)
) STRICT, WITHOUT ROWID;

-- A record as the app sealed it, with its clock, and the account's change number of its last
-- write. A deleted record stays as a tombstone (with a sealed empty payload) for 90 days after
-- its last write (`updated`, Unix seconds).
CREATE TABLE suite_records (
    id       TEXT PRIMARY KEY NOT NULL,
    user_id  TEXT NOT NULL,
    space    TEXT NOT NULL,
    kind     TEXT NOT NULL,
    wall_ms  INTEGER NOT NULL,
    counter  INTEGER NOT NULL,
    device   INTEGER NOT NULL,
    deleted  INTEGER NOT NULL,
    nonce    BLOB NOT NULL,
    blob     BLOB NOT NULL,
    seq      INTEGER NOT NULL,
    updated  INTEGER NOT NULL,
    FOREIGN KEY (user_id, space) REFERENCES suite_spaces (user_id, space) ON DELETE CASCADE
) STRICT;

CREATE INDEX suite_records_by_space ON suite_records (user_id, space, seq);
CREATE INDEX suite_records_by_deletion ON suite_records (updated) WHERE deleted;

-- Which app a device logged in as: `uwussh`, `uwurdp`, … for a suite app, else the client id it
-- said (`web`, `browser`, `desktop`, …).
ALTER TABLE devices ADD COLUMN client_id TEXT;

-- A space that goes, or gets a new key, is something a delta cannot say.
CREATE TRIGGER suite_spaces_epoch AFTER DELETE ON suite_spaces BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id = OLD.user_id;
END;
