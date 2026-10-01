-- The breach sources of the password check (docs/uwu-api.md §15).

-- What an account chose not to be shown again in the password check: per item and per kind of
-- problem, a JSON list encrypted under the extras key by the client, like the health report.
CREATE TABLE health_ignores (
    user_id  TEXT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    data     TEXT NOT NULL,
    revision TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- Accounts that agreed to have their addresses checked at XposedOrNot by the server.
CREATE TABLE breach_email_opt_ins (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    since   TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- XposedOrNot's answers for addresses, kept a week. Keyed by a salted SHA-256 of the address
-- (the salt sealed with the server secret, outside the database), never by the address, and
-- never next to an account.
CREATE TABLE breach_email_cache (
    address_hash BLOB PRIMARY KEY NOT NULL,
    breaches     TEXT NOT NULL,
    checked      INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
