-- Masked addresses from UwUMail (Stufe 6; docs/uwu-api.md §13): the OAuth client this server
-- registered at each UwUMail server, each account's connection, the links between masked
-- addresses and items, and the API keys for the official clients' generators.

-- One registration per UwUMail server (its address as the admin listed it). UwUMail forgets a
-- client that has no grant and was not used for seven days; then it is registered again.
-- `used`: seconds since 1970 of the last call UwUMail took from it.
CREATE TABLE masked_clients (
    server       TEXT PRIMARY KEY NOT NULL,
    client_id    TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    used         INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- An account's grant at one UwUMail server. The tokens are sealed with the server secret in the
-- data directory (`secret.key`), with the account and the server as associated data.
-- `status`: 'ok', 'revoked' (UwUMail ended the grant), 'unreachable' (the last call failed).
CREATE TABLE masked_connections (
    user_id        TEXT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    server         TEXT NOT NULL,
    issuer         TEXT NOT NULL,
    client_id      TEXT NOT NULL,
    token_endpoint TEXT NOT NULL,
    revocation_endpoint TEXT,
    api_url        TEXT NOT NULL,
    account_id     TEXT NOT NULL,
    username       TEXT NOT NULL,
    -- JSON array of the domains the account may use, and the one UwUMail picks without a choice.
    domains        TEXT NOT NULL,
    default_domain TEXT,
    access_token   TEXT,
    -- Seconds since 1970 when the access token runs out.
    access_expires INTEGER NOT NULL DEFAULT 0,
    refresh_token  TEXT NOT NULL,
    status         TEXT NOT NULL,
    connected      TEXT NOT NULL,
    last_used      TEXT
) STRICT, WITHOUT ROWID;

-- Which item a masked address belongs to: at most one address per item and one item per address.
-- The address and its last known state are kept so clients can show them without asking UwUMail.
CREATE TABLE masked_links (
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    masked_id TEXT NOT NULL,
    cipher_id TEXT NOT NULL REFERENCES ciphers (id) ON DELETE CASCADE,
    email     TEXT NOT NULL,
    state     TEXT,
    revision  TEXT NOT NULL,
    PRIMARY KEY (user_id, masked_id),
    UNIQUE (user_id, cipher_id)
) STRICT, WITHOUT ROWID;

-- Keys for the addy.io- and SimpleLogin-compatible endpoints, kept as SHA-256 of the secret part.
CREATE TABLE masked_api_keys (
    id        TEXT PRIMARY KEY NOT NULL,
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    hash      BLOB NOT NULL,
    hint      TEXT NOT NULL,
    created   TEXT NOT NULL,
    last_used TEXT
) STRICT;
CREATE INDEX masked_api_keys_user ON masked_api_keys (user_id);
