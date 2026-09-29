-- Logging in through an OpenID Connect provider, and SCIM from it (Stufe 4b; docs/uwu-api.md §19).

-- Which login at which provider is which account. One login per provider and account, and one
-- account per login.
CREATE TABLE sso_identities (
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    issuer     TEXT NOT NULL,
    subject    TEXT NOT NULL,
    created    TEXT NOT NULL,
    last_login TEXT,
    PRIMARY KEY (issuer, subject),
    UNIQUE (user_id, issuer)
) STRICT, WITHOUT ROWID;

-- A login on its way to the provider and back: the client's side of it (where to send the code,
-- its state and PKCE challenge) and the server's own (nonce, PKCE verifier, the cookie that binds
-- it to the browser). Kept by the SHA-256 of the state the provider gets; ten minutes.
CREATE TABLE sso_states (
    state_hash     BLOB PRIMARY KEY NOT NULL,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    client_state   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    nonce          TEXT NOT NULL,
    verifier       TEXT,
    binding_hash   BLOB NOT NULL,
    expires        TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- The one-time code the client trades for its tokens, by its SHA-256; five minutes. It stays
-- until the login is through, so the client can send it again with the second step.
CREATE TABLE sso_codes (
    code_hash      BLOB PRIMARY KEY NOT NULL,
    user_id        TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    expires        TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- People the provider pushed over SCIM. Without an account yet: an address that may sign up
-- through SSO. With one (`user_id`): the id the provider knows the account by, and its
-- `externalId`.
CREATE TABLE scim_provisioned (
    id           TEXT PRIMARY KEY NOT NULL,
    email        TEXT NOT NULL,
    user_id      TEXT UNIQUE REFERENCES users (id) ON DELETE CASCADE,
    external_id  TEXT,
    display_name TEXT,
    active       INTEGER NOT NULL DEFAULT 1,
    created      TEXT NOT NULL,
    updated      TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX scim_provisioned_by_email ON scim_provisioned (email) WHERE user_id IS NULL;

-- Groups as the provider pushes them, only to know who is in the admin and user groups between
-- logins. `members`: a JSON list of SCIM user ids.
CREATE TABLE scim_groups (
    id           TEXT PRIMARY KEY NOT NULL,
    display_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    external_id  TEXT,
    members      TEXT NOT NULL DEFAULT '[]',
    created      TEXT NOT NULL,
    updated      TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- Whether the device's login came through SSO: its access tokens say so (`amr`), also after a
-- refresh, for `adminsOnlyWithSso`.
ALTER TABLE devices ADD COLUMN sso INTEGER NOT NULL DEFAULT 0;
