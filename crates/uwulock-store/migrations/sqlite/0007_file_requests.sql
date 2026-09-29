-- The extras key and file requests (Stufe 4b; docs/uwu-api.md §3 and §11).

-- What UwULock encrypts beyond Bitwarden's own objects is under one extras key per account, kept
-- wrapped twice: under the user key, and for the account's public key. An official client that
-- rotates the user key leaves the second one working. `public_key` is the account's public key
-- it was wrapped for: when the account's changes, neither wrap opens any more.
CREATE TABLE extras_keys (
    user_id            TEXT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    user_key_wrapped   TEXT,
    public_key_wrapped TEXT NOT NULL,
    public_key         TEXT NOT NULL,
    revision           TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- Sends the other way round: a link somebody without an account uploads files and text to,
-- encrypted in their browser for the owner. The server keeps only ciphertext.
CREATE TABLE file_requests (
    id               TEXT PRIMARY KEY NOT NULL,
    user_id          TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The owner's label and the link's secret, under the extras key; gone when it was reset.
    name             TEXT,
    link_secret      TEXT,
    -- Title, note and the public key to encrypt for, under the link's key.
    public_info      TEXT NOT NULL,
    -- Argon2id of what the uploader's page makes of the password.
    password_hash    TEXT,
    expiration       TEXT NOT NULL,
    deletion         TEXT NOT NULL,
    max_submissions  INTEGER,
    submission_count INTEGER NOT NULL DEFAULT 0,
    max_files        INTEGER NOT NULL,
    max_file_bytes   INTEGER NOT NULL,
    text_allowed     INTEGER NOT NULL,
    send_domain_id   TEXT,
    disabled         INTEGER NOT NULL DEFAULT 0,
    -- When the owner was last mailed about it: at most one mail a quarter of an hour.
    mailed           TEXT,
    created          TEXT NOT NULL,
    revision         TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX file_requests_by_user ON file_requests (user_id);
CREATE INDEX file_requests_by_deletion ON file_requests (deletion);

-- What one uploader sent: the key for the owner, the message and who they said they are. Only
-- `completed` ones reach the owner; the others go after a day.
CREATE TABLE file_request_submissions (
    id          TEXT PRIMARY KEY NOT NULL,
    request_id  TEXT NOT NULL REFERENCES file_requests (id) ON DELETE CASCADE,
    wrapped_key TEXT NOT NULL,
    sender      TEXT,
    text        TEXT,
    created     TEXT NOT NULL,
    completed   TEXT,
    seen        INTEGER NOT NULL DEFAULT 0
) STRICT, WITHOUT ROWID;

CREATE INDEX file_request_submissions_by_request ON file_request_submissions (request_id);

-- The files of a submission, at file-requests/<request>/<id> in the data directory, in the order
-- the uploader gave them (by rowid).
CREATE TABLE file_request_files (
    id            TEXT PRIMARY KEY NOT NULL,
    submission_id TEXT NOT NULL REFERENCES file_request_submissions (id) ON DELETE CASCADE,
    file_name     TEXT NOT NULL,
    key           TEXT NOT NULL,
    size          INTEGER NOT NULL,
    uploaded      INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX file_request_files_by_submission ON file_request_files (submission_id);
