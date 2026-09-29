-- Own icons, entry versions, travel mode and renewal reminders (Stufe 4c; docs/uwu-api.md §7.3,
-- §8, §9 and §10).

-- An icon the person chose for an item: a PNG, encrypted by the client under the extras key (a
-- personal item) or the organisation's key. Goes with its item.
CREATE TABLE own_icons (
    cipher_id TEXT PRIMARY KEY NOT NULL REFERENCES ciphers (id) ON DELETE CASCADE,
    -- `extras` or `organization`: which key it is under.
    key_type  TEXT NOT NULL,
    data      TEXT NOT NULL,
    revision  TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- The states an item had before it was changed, as the clients encrypted them. `user_id` is the
-- owner of a personal item, `organization_id` the organisation of an organisation's: the one the
-- version counts for, and what a key rotation re-encrypts (personal ones only).
CREATE TABLE cipher_versions (
    id              TEXT PRIMARY KEY NOT NULL,
    cipher_id       TEXT NOT NULL REFERENCES ciphers (id) ON DELETE CASCADE,
    user_id         TEXT REFERENCES users (id) ON DELETE CASCADE,
    organization_id TEXT,
    -- JSON: type, name, notes, key, data, fields, passwordHistory and reprompt.
    content         TEXT NOT NULL,
    -- The revision date that state had, and when it was replaced.
    revision        TEXT NOT NULL,
    replaced        TEXT NOT NULL,
    size            INTEGER NOT NULL
) STRICT;

CREATE INDEX cipher_versions_by_cipher ON cipher_versions (cipher_id, replaced);
CREATE INDEX cipher_versions_by_user ON cipher_versions (user_id);
CREATE INDEX cipher_versions_by_replaced ON cipher_versions (replaced);

-- Travel mode: folders marked "hide while travelling", and whether it is on (a row here).
ALTER TABLE folders ADD COLUMN travel INTEGER NOT NULL DEFAULT 0;

CREATE TABLE travel (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    enabled TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- "Renew this password": per account and item, only the day it is due. `mailed` is the day the
-- mail for this due date went out.
CREATE TABLE reminders (
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    cipher_id    TEXT NOT NULL REFERENCES ciphers (id) ON DELETE CASCADE,
    due          TEXT NOT NULL,
    every_months INTEGER,
    mailed       TEXT,
    PRIMARY KEY (user_id, cipher_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX reminders_by_cipher ON reminders (cipher_id);
CREATE INDEX reminders_by_due ON reminders (due);
