-- What 0.4 adds for one person: files on items, Sends, emergency access, logging in with
-- another device, passkeys and an API key. Files themselves live on disk, next to the
-- database; these tables say what they are and whose.

-- A file on an item. The file is `files/attachments/<cipher>/<id>`, encrypted by the client
-- with a key of its own, which is here wrapped under the item's key.
CREATE TABLE attachments (
    id        TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL REFERENCES ciphers (id) ON DELETE CASCADE,
    -- Encrypted by the client.
    file_name TEXT NOT NULL,
    key       TEXT,
    -- In bytes, of the encrypted file.
    size      INTEGER NOT NULL,
    -- Whether the file arrived. An attachment is announced first and uploaded after.
    uploaded  INTEGER NOT NULL DEFAULT 0,
    created   TEXT NOT NULL
) STRICT;

CREATE INDEX attachments_by_cipher ON attachments (cipher_id);

-- A Send: a text or a file for somebody without an account, behind a link that carries the
-- key. What the link opens the server cannot read either.
CREATE TABLE sends (
    id               TEXT PRIMARY KEY NOT NULL,
    user_id          TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- 0 text, 1 file.
    type             INTEGER NOT NULL,
    name             TEXT NOT NULL,
    notes            TEXT,
    -- JSON: the text object, or the file object with its id, name and size.
    data             TEXT NOT NULL,
    -- The Send's key, wrapped under the user key.
    key              TEXT NOT NULL,
    -- Argon2id over the hash of the password the client sends; none without a password.
    password_hash    TEXT,
    max_access_count INTEGER,
    access_count     INTEGER NOT NULL DEFAULT 0,
    created          TEXT NOT NULL,
    revision         TEXT NOT NULL,
    expiration       TEXT,
    deletion         TEXT NOT NULL,
    disabled         INTEGER NOT NULL DEFAULT 0,
    hide_email       INTEGER NOT NULL DEFAULT 0,
    -- For a file Send, whether the file arrived.
    uploaded         INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX sends_by_user ON sends (user_id);
CREATE INDEX sends_by_deletion ON sends (deletion);

-- Somebody the grantor trusts to see (0) or take over (1) the vault, after asking and a wait.
-- Status: 0 invited, 1 accepted, 2 confirmed, 3 recovery asked for, 4 recovery approved.
CREATE TABLE emergency_access (
    id                TEXT PRIMARY KEY NOT NULL,
    grantor_id        TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    grantee_id        TEXT REFERENCES users (id) ON DELETE CASCADE,
    -- The address the invitation went to, until it is accepted.
    email             TEXT NOT NULL,
    -- The grantor's user key, wrapped for the grantee's public key.
    key_encrypted     TEXT,
    type              INTEGER NOT NULL,
    status            INTEGER NOT NULL,
    wait_days         INTEGER NOT NULL,
    -- SHA-256 of the token in the invitation mail.
    token_hash        BLOB,
    recovery_asked    TEXT,
    last_notification TEXT,
    created           TEXT NOT NULL,
    revision          TEXT NOT NULL
) STRICT;

CREATE INDEX emergency_by_grantor ON emergency_access (grantor_id);
CREATE INDEX emergency_by_grantee ON emergency_access (grantee_id) WHERE grantee_id IS NOT NULL;

-- "Log in with a device": a new device asks, a logged-in one answers with the user key
-- wrapped for the new device's public key.
CREATE TABLE auth_requests (
    id                 TEXT PRIMARY KEY NOT NULL,
    user_id            TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- 0 log in and unlock, 1 unlock only.
    type               INTEGER NOT NULL,
    device_id          TEXT NOT NULL,
    device_type        INTEGER NOT NULL,
    ip                 TEXT NOT NULL,
    public_key         TEXT NOT NULL,
    -- SHA-256 of the code the new device made; it logs in with it once approved.
    access_code_hash   BLOB NOT NULL,
    key                TEXT,
    master_password_hash TEXT,
    -- None while nobody answered.
    approved           INTEGER,
    response_device_id TEXT,
    created            TEXT NOT NULL,
    responded          TEXT,
    -- When the new device logged in with it; it works once.
    used               TEXT
) STRICT;

CREATE INDEX auth_requests_by_user ON auth_requests (user_id);

-- Passkeys that log in to the web vault, and with the PRF extension unlock it too: the user key
-- wrapped for a key pair whose private key only the passkey's PRF output opens.
CREATE TABLE passkeys (
    -- The credential id, base64url.
    id                    TEXT PRIMARY KEY NOT NULL,
    user_id               TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    -- COSE, base64url.
    public_key            TEXT NOT NULL,
    counter               INTEGER NOT NULL DEFAULT 0,
    supports_prf          INTEGER NOT NULL DEFAULT 0,
    encrypted_user_key    TEXT,
    encrypted_public_key  TEXT,
    encrypted_private_key TEXT,
    created               TEXT NOT NULL,
    last_used             TEXT
) STRICT;

CREATE INDEX passkeys_by_user ON passkeys (user_id);

-- The CLI logs in with this instead of the master password: `client_id` is `user.<id>`.
CREATE TABLE api_keys (
    user_id  TEXT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    secret   TEXT NOT NULL,
    revision TEXT NOT NULL
) STRICT;
