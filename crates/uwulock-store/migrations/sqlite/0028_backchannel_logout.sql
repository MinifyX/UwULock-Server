-- OpenID Connect back-channel logout: the provider names a session it ended by its `sid`, and maybe
-- not by the person's `sub`. So each SSO login keeps the provider's session id until its refresh
-- token could have run out at the latest, and which logout tokens were taken, for as long as
-- they hold (each works once).
CREATE TABLE sso_sessions (
    issuer  TEXT NOT NULL,
    sid     TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created TEXT NOT NULL,
    PRIMARY KEY (issuer, sid)
) STRICT, WITHOUT ROWID;
CREATE INDEX sso_sessions_user ON sso_sessions (user_id);

CREATE TABLE sso_logout_tokens (
    jti_hash BLOB NOT NULL PRIMARY KEY,
    expires  TEXT NOT NULL
) STRICT, WITHOUT ROWID;
