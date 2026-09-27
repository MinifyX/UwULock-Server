-- The admin portal's numbers over time: one row a day, written by the maintenance job while the
-- day lasts. Logins are counted from the event log, which is only kept 90 days; the rows stay.
CREATE TABLE daily_stats (
    -- YYYY-MM-DD, UTC.
    day           TEXT PRIMARY KEY NOT NULL,
    users         INTEGER NOT NULL,
    devices       INTEGER NOT NULL,
    ciphers       INTEGER NOT NULL,
    sends         INTEGER NOT NULL,
    -- Attachments and the files of Sends, in bytes.
    file_bytes    INTEGER NOT NULL,
    logins        INTEGER NOT NULL,
    failed_logins INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- Who brought an account in, for the invitations a user may make.
ALTER TABLE users ADD COLUMN invited_by TEXT REFERENCES users (id) ON DELETE SET NULL;
