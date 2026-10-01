-- Failed logins in the admin portal (docs/failed-logins.md): what the client said about itself,
-- why a login was refused, and addresses that may not log in for a while.

-- What the client said about itself at a login, refused or not. `client_name` and
-- `client_version` come from Bitwarden's `Bitwarden-Client-Name`/`-Version` headers (or the
-- token request's `client_id`), `device_name` from the token request. Older events have none.
ALTER TABLE events ADD COLUMN user_agent TEXT;
ALTER TABLE events ADD COLUMN client_name TEXT;
ALTER TABLE events ADD COLUMN client_version TEXT;
ALTER TABLE events ADD COLUMN device_name TEXT;
-- Why a login was refused: `password` (an account, the wrong password), `unknown-account`,
-- `disabled`, `api-key`, `two-factor`. NULL for everything else.
ALTER TABLE events ADD COLUMN reason TEXT;

UPDATE events SET reason = CASE
    WHEN kind = 'two-factor-failed' THEN 'two-factor'
    WHEN detail = 'account disabled' THEN 'disabled'
    WHEN detail = 'wrong API key' THEN 'api-key'
    WHEN user_id IS NULL THEN 'unknown-account'
    ELSE 'password'
END
WHERE kind IN ('login-failed', 'two-factor-failed');

-- The failed-logins page asks by kind and time, and the history of one address.
CREATE INDEX events_by_kind ON events (kind, time);
CREATE INDEX events_by_ip ON events (ip, time);

-- Addresses (or networks, as CIDR) refused at every login endpoint until `expires` (none: until
-- an admin lifts it). Expired rows are swept away by the daily maintenance.
CREATE TABLE ip_blocks (
    id         INTEGER PRIMARY KEY,
    -- `203.0.113.7` or `2001:db8::/64`, written the way the server parses it.
    network    TEXT NOT NULL UNIQUE,
    reason     TEXT NOT NULL DEFAULT '',
    created    TEXT NOT NULL,
    expires    TEXT,
    -- The admin who blocked it; their address stays after the account is gone.
    created_by TEXT
) STRICT;
