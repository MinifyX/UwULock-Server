-- Accounts and their vaults: what 0.1 needs for one person with the official clients, the web
-- vault and the admin portal. Every time is text in one format, `2026-09-25T12:00:00.000000Z`
-- (UTC, microseconds), the way the clients get it — so it sorts the way it reads, and goes out
-- without being converted.

CREATE TABLE users (
    id                 TEXT PRIMARY KEY NOT NULL,
    -- Trimmed and in lower case. It is also the salt of the master key, so it only changes
    -- together with the key the client derives from it.
    email              TEXT NOT NULL UNIQUE,
    name               TEXT,
    -- Argon2id over the master password hash the client sends. The master password never
    -- comes here, only that hash of it.
    password_hash      TEXT NOT NULL,
    password_hint      TEXT,
    -- The user key, wrapped under the master key by the client. The server cannot open it.
    user_key           TEXT NOT NULL,
    private_key        TEXT,
    public_key         TEXT,
    kdf_type           INTEGER NOT NULL,
    kdf_iterations     INTEGER NOT NULL,
    kdf_memory         INTEGER,
    kdf_parallelism    INTEGER,
    -- Changes whenever every session has to end: a new password, new keys, "log out everywhere".
    security_stamp     TEXT NOT NULL,
    -- For mails: de or en.
    language           TEXT NOT NULL,
    avatar_color       TEXT,
    equivalent_domains TEXT NOT NULL DEFAULT '[]',
    excluded_globals   TEXT NOT NULL DEFAULT '[]',
    -- Turns off two-step login once, when the phone is gone. Shown to the user on request.
    recovery_code      TEXT,
    admin              INTEGER NOT NULL DEFAULT 0,
    disabled           INTEGER NOT NULL DEFAULT 0,
    created            TEXT NOT NULL,
    updated            TEXT NOT NULL,
    -- The last change to anything the clients sync. They ask for it all the time.
    revision           TEXT NOT NULL,
    last_login         TEXT
) STRICT;

-- A browser extension, an app, a CLI, a web vault tab: each logs in as a device of its own.
CREATE TABLE devices (
    user_id          TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The identifier the client made for itself.
    id               TEXT NOT NULL,
    name             TEXT NOT NULL,
    type             INTEGER NOT NULL,
    created          TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    last_ip          TEXT,
    -- SHA-256 of the refresh token; none once the device logged out.
    refresh_hash     BLOB,
    refresh_expires  TEXT,
    -- SHA-256 of the token that skips two-step login on this device.
    remember_hash    BLOB,
    remember_expires TEXT,
    push_token       TEXT,
    PRIMARY KEY (user_id, id)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX devices_by_refresh ON devices (refresh_hash) WHERE refresh_hash IS NOT NULL;

-- Nobody registers without one.
CREATE TABLE invitations (
    email      TEXT PRIMARY KEY NOT NULL,
    token_hash BLOB NOT NULL UNIQUE,
    admin      INTEGER NOT NULL DEFAULT 0,
    -- A user, or none for the command line.
    invited_by TEXT REFERENCES users (id) ON DELETE SET NULL,
    language   TEXT NOT NULL,
    created    TEXT NOT NULL,
    expires    TEXT NOT NULL
) STRICT;

CREATE TABLE folders (
    id       TEXT PRIMARY KEY NOT NULL,
    user_id  TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name     TEXT NOT NULL,
    created  TEXT NOT NULL,
    revision TEXT NOT NULL
) STRICT;

CREATE INDEX folders_by_user ON folders (user_id);

-- An item, as the client encrypted it. What belongs to its type — the login, card, identity,
-- note or SSH key object — is kept as the JSON the client sent, so fields a newer client adds
-- come back to it unchanged.
CREATE TABLE ciphers (
    id               TEXT PRIMARY KEY NOT NULL,
    user_id          TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    folder_id        TEXT REFERENCES folders (id) ON DELETE SET NULL,
    type             INTEGER NOT NULL,
    name             TEXT NOT NULL,
    notes            TEXT,
    key              TEXT,
    data             TEXT NOT NULL,
    fields           TEXT,
    password_history TEXT,
    favorite         INTEGER NOT NULL DEFAULT 0,
    reprompt         INTEGER NOT NULL DEFAULT 0,
    created          TEXT NOT NULL,
    revision         TEXT NOT NULL,
    deleted          TEXT,
    archived         TEXT
) STRICT;

CREATE INDEX ciphers_by_user ON ciphers (user_id);
CREATE INDEX ciphers_by_folder ON ciphers (folder_id) WHERE folder_id IS NOT NULL;

-- Two-step login: 0 an authenticator app, 1 codes by mail.
CREATE TABLE two_factor (
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type      INTEGER NOT NULL,
    enabled   INTEGER NOT NULL,
    data      TEXT NOT NULL,
    -- The last time step an authenticator code was taken for, so none is taken twice.
    last_used INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, type)
) STRICT, WITHOUT ROWID;

-- Codes sent by mail, one per purpose and user: logging in, setting up mail codes, a new address.
CREATE TABLE codes (
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose   TEXT NOT NULL,
    code_hash BLOB NOT NULL,
    data      TEXT,
    attempts  INTEGER NOT NULL DEFAULT 0,
    expires   TEXT NOT NULL,
    PRIMARY KEY (user_id, purpose)
) STRICT, WITHOUT ROWID;

-- What the admin portal shows: logins, failed ones, and what admins did. Kept for 90 days.
CREATE TABLE events (
    id          INTEGER PRIMARY KEY,
    time        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    user_id     TEXT,
    email       TEXT,
    ip          TEXT,
    device_type INTEGER,
    detail      TEXT
) STRICT;

CREATE INDEX events_by_time ON events (time);
