-- Sends only for given addresses, the server's own look and the stored health report (Stufe 4c;
-- docs/uwu-api.md §14.3, §14.4 and §15).

-- Who may open a Send, when only given addresses may: plain text, lower case, comma-separated.
-- The server mails them their codes, so it has to read them. NULL: a password or nobody.
ALTER TABLE sends ADD COLUMN emails TEXT;

-- Name, accent colour, logos and favicon. `scope` is '' for the server; a send domain's id for
-- that domain's own (Stufe 6). The images are PNG, re-encoded by the server when they came in.
CREATE TABLE branding (
    scope      TEXT PRIMARY KEY NOT NULL,
    name       TEXT,
    color      TEXT,
    logo_light BLOB,
    logo_dark  BLOB,
    favicon    BLOB,
    revision   TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- The last password-health report of an account, as its client encrypted it under the extras key
-- (§15). The server cannot read it.
CREATE TABLE health_reports (
    user_id  TEXT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    data     TEXT NOT NULL,
    revision TEXT NOT NULL
) STRICT, WITHOUT ROWID;
