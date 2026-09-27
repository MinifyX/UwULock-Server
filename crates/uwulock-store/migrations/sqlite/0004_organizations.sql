-- What a vault moved over from Vaultwarden brings along: organisations, their collections,
-- groups and policies, and items that belong to an organisation rather than to a person. Also
-- the push relay's id for each phone.
--
-- An item now belongs to a user or to an organisation, so `ciphers` is built again with
-- `user_id` optional — SQLite changes no column in place. The migration runs with foreign keys
-- off for that, and checks them afterwards.

CREATE TABLE organizations (
    id          TEXT PRIMARY KEY NOT NULL,
    -- Not encrypted: Bitwarden's organisation names are not either.
    name        TEXT NOT NULL,
    billing_email TEXT NOT NULL DEFAULT '',
    -- The organisation's own key pair: the private key under the organisation key.
    public_key  TEXT,
    private_key TEXT,
    created     TEXT NOT NULL,
    revision    TEXT NOT NULL
) STRICT;

-- A person in an organisation. Status: -1 revoked, 0 invited, 1 accepted, 2 confirmed. Type:
-- 0 owner, 1 admin, 2 user, 3 manager, 4 custom.
CREATE TABLE org_members (
    id          TEXT PRIMARY KEY NOT NULL,
    org_id      TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id     TEXT REFERENCES users (id) ON DELETE CASCADE,
    email       TEXT,
    -- The organisation key, wrapped for the member's public key; none until confirmed.
    key         TEXT,
    status      INTEGER NOT NULL,
    type        INTEGER NOT NULL,
    access_all  INTEGER NOT NULL DEFAULT 0,
    -- JSON: a custom member's permissions.
    permissions TEXT NOT NULL DEFAULT '{}',
    external_id TEXT,
    reset_password_key TEXT,
    created     TEXT NOT NULL,
    revision    TEXT NOT NULL
) STRICT;

CREATE INDEX org_members_by_user ON org_members (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX org_members_by_org ON org_members (org_id);

CREATE TABLE collections (
    id          TEXT PRIMARY KEY NOT NULL,
    org_id      TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- Encrypted under the organisation key.
    name        TEXT NOT NULL,
    external_id TEXT,
    created     TEXT NOT NULL,
    revision    TEXT NOT NULL
) STRICT;

CREATE INDEX collections_by_org ON collections (org_id);

CREATE TABLE groups (
    id          TEXT PRIMARY KEY NOT NULL,
    org_id      TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    access_all  INTEGER NOT NULL DEFAULT 0,
    external_id TEXT,
    created     TEXT NOT NULL,
    revision    TEXT NOT NULL
) STRICT;

CREATE TABLE group_members (
    group_id  TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    member_id TEXT NOT NULL REFERENCES org_members (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, member_id)
) STRICT, WITHOUT ROWID;

-- Who may do what with a collection: members directly, or by a group.
CREATE TABLE collection_members (
    collection_id  TEXT NOT NULL REFERENCES collections (id) ON DELETE CASCADE,
    member_id      TEXT NOT NULL REFERENCES org_members (id) ON DELETE CASCADE,
    read_only      INTEGER NOT NULL DEFAULT 0,
    hide_passwords INTEGER NOT NULL DEFAULT 0,
    manage         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (collection_id, member_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE collection_groups (
    collection_id  TEXT NOT NULL REFERENCES collections (id) ON DELETE CASCADE,
    group_id       TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    read_only      INTEGER NOT NULL DEFAULT 0,
    hide_passwords INTEGER NOT NULL DEFAULT 0,
    manage         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (collection_id, group_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE policies (
    id      TEXT PRIMARY KEY NOT NULL,
    org_id  TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    type    INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    -- JSON, as the organisation's admin set it.
    data    TEXT,
    revision TEXT NOT NULL
) STRICT;

CREATE INDEX policies_by_org ON policies (org_id);

-- Items, again: owned by a user or by an organisation.
CREATE TABLE ciphers_new (
    id               TEXT PRIMARY KEY NOT NULL,
    user_id          TEXT REFERENCES users (id) ON DELETE CASCADE,
    organization_id  TEXT REFERENCES organizations (id) ON DELETE CASCADE,
    folder_id        TEXT REFERENCES folders (id) ON DELETE SET NULL,
    type             INTEGER NOT NULL,
    name             TEXT NOT NULL,
    notes            TEXT,
    key              TEXT,
    data             TEXT NOT NULL,
    fields           TEXT,
    password_history TEXT,
    favorite         INTEGER NOT NULL DEFAULT 0,
    reprompt         INTEGER NOT NULL DEFAULT 0,
    created          TEXT NOT NULL,
    revision         TEXT NOT NULL,
    deleted          TEXT,
    archived         TEXT,
    CHECK ((user_id IS NULL) <> (organization_id IS NULL))
) STRICT;

INSERT INTO ciphers_new (id, user_id, organization_id, folder_id, type, name, notes, key, data, fields,
    password_history, favorite, reprompt, created, revision, deleted, archived)
SELECT id, user_id, NULL, folder_id, type, name, notes, key, data, fields, password_history, favorite, reprompt,
    created, revision, deleted, archived
FROM ciphers;

DROP TABLE ciphers;
ALTER TABLE ciphers_new RENAME TO ciphers;

CREATE INDEX ciphers_by_user ON ciphers (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX ciphers_by_org ON ciphers (organization_id) WHERE organization_id IS NOT NULL;
CREATE INDEX ciphers_by_folder ON ciphers (folder_id) WHERE folder_id IS NOT NULL;

CREATE TABLE collection_ciphers (
    collection_id TEXT NOT NULL REFERENCES collections (id) ON DELETE CASCADE,
    cipher_id     TEXT NOT NULL REFERENCES ciphers (id) ON DELETE CASCADE,
    PRIMARY KEY (collection_id, cipher_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX collection_ciphers_by_cipher ON collection_ciphers (cipher_id);

-- What each member makes of an organisation's item for themselves: its folder, its star.
CREATE TABLE cipher_preferences (
    cipher_id TEXT NOT NULL REFERENCES ciphers (id) ON DELETE CASCADE,
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    folder_id TEXT REFERENCES folders (id) ON DELETE SET NULL,
    favorite  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cipher_id, user_id)
) STRICT, WITHOUT ROWID;

-- The push relay's id for a phone of the account, once it is registered there.
ALTER TABLE devices ADD COLUMN push_id TEXT;
