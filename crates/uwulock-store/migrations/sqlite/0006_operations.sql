-- Running the server and keeping it safe (Stufe 4b).

-- What happened on an account, for its owner: failed logins, changed credentials, new devices,
-- exports. Listed in the web vault and mailed in bundles. Kept 180 days. The Stufe 5 event log
-- builds on this table.
CREATE TABLE security_notices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- `failedLogins`, `newDevice`, `passwordChanged`, … (docs/uwu-api.md §12.1)
    kind        TEXT NOT NULL,
    time        TEXT NOT NULL,
    ip          TEXT,
    device_type INTEGER,
    device_name TEXT,
    -- The client: `web`, `browser`, `desktop`, `cli`, …
    app         TEXT,
    -- A JSON object, per kind.
    detail      TEXT NOT NULL DEFAULT '{}',
    -- 0: no mail for it, 1: waits for the next bundle, 2: mailed.
    mail        INTEGER NOT NULL DEFAULT 0,
    mailed      TEXT,
    seen        INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX security_notices_by_user ON security_notices (user_id, id);
CREATE INDEX security_notices_waiting ON security_notices (mail) WHERE mail = 1;
CREATE INDEX security_notices_by_time ON security_notices (time);

-- Where the admins hear of trouble: mail to all admins, ntfy, Gotify, Matrix. `config` holds
-- the channel's address and secrets; the admin portal never gets the secrets back.
CREATE TABLE notification_channels (
    id      TEXT PRIMARY KEY NOT NULL,
    kind    TEXT NOT NULL,
    name    TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    -- A JSON list of event names.
    events  TEXT NOT NULL,
    config  TEXT NOT NULL,
    created TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- Every server starts with mail to its admins, for what needs someone to act.
INSERT INTO notification_channels (id, kind, name, enabled, events, config, created) VALUES (
    lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))), 2)
        || '-' || substr('89ab', 1 + abs(random()) % 4, 1) || substr(lower(hex(randomblob(2))), 2) || '-'
        || lower(hex(randomblob(6))),
    'mail',
    'Mail',
    1,
    '["backupFailed","backupStale","certificateExpiring","manyFailedLogins","diskLow","pushRelayFailing"]',
    '{}',
    strftime('%Y-%m-%dT%H:%M:%S', 'now') || '.000000Z'
);
