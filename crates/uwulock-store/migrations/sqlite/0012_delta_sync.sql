-- Delta sync (Stufe 6; docs/uwu-api.md §4): change numbers, tombstones and epochs.
--
-- Every account and every organisation counts its changes (`seq`). A row the account sees in a
-- sync carries the number of its last change, so "what changed since n" is one indexed query per
-- table; what is deleted for good leaves a tombstone with its number. What a delta cannot say —
-- a new key, a membership, travel mode — moves the account's `sync_epoch` on, and a cursor of an
-- older epoch gets everything again.
--
-- The numbers are handed out by triggers, in the transaction of the change itself, so no way of
-- writing (an import, a rotation, a member removed, a cascade) can forget one. A trigger's own
-- update of its table does not fire it again (SQLite's recursive triggers are off). A later step
-- that builds one of these tables again has to make its triggers again, too.

ALTER TABLE users ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
-- The number of the last change to what the profile, the domains and the key options show.
ALTER TABLE users ADD COLUMN profile_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN sync_epoch INTEGER NOT NULL DEFAULT 0;
-- Tombstones up to this number are gone: an older cursor cannot be served a delta.
ALTER TABLE users ADD COLUMN pruned_seq INTEGER NOT NULL DEFAULT 0;

ALTER TABLE organizations ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN policies_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN pruned_seq INTEGER NOT NULL DEFAULT 0;

ALTER TABLE ciphers ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE folders ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sends ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE collections ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cipher_preferences ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE reminders ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE extras_keys ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
-- An own icon counts for the owner of its item: a user or an organisation.
ALTER TABLE own_icons ADD COLUMN owner TEXT;
ALTER TABLE own_icons ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;

CREATE INDEX ciphers_by_user_seq ON ciphers (user_id, seq) WHERE user_id IS NOT NULL;
CREATE INDEX ciphers_by_org_seq ON ciphers (organization_id, seq) WHERE organization_id IS NOT NULL;
CREATE INDEX folders_by_user_seq ON folders (user_id, seq);
CREATE INDEX sends_by_user_seq ON sends (user_id, seq);
CREATE INDEX collections_by_org_seq ON collections (org_id, seq);
CREATE INDEX cipher_preferences_by_user_seq ON cipher_preferences (user_id, seq);
CREATE INDEX reminders_by_user_seq ON reminders (user_id, seq);
CREATE INDEX own_icons_by_owner_seq ON own_icons (owner, seq);

UPDATE own_icons SET owner = (SELECT coalesce(c.user_id, c.organization_id) FROM ciphers c WHERE c.id = own_icons.cipher_id);

-- What is gone for good: `owner` is a user's or an organisation's id (both are UUIDs), `kind`
-- one of cipher, folder, send, collection, icon, reminder. `time` in Unix seconds; kept 90 days.
-- No foreign key: a tombstone outlives what it names, and an owner that is deleted takes its
-- tombstones along by the maintenance.
CREATE TABLE tombstones (
    owner     TEXT NOT NULL,
    kind      TEXT NOT NULL,
    object_id TEXT NOT NULL,
    seq       INTEGER NOT NULL,
    time      INTEGER NOT NULL
) STRICT;

CREATE INDEX tombstones_by_owner ON tombstones (owner, seq);
CREATE INDEX tombstones_by_time ON tombstones (time);

-- The server's epoch: a new random value whenever a backup is put back, so every cursor from
-- before starts over.
INSERT INTO server (key, value) VALUES ('sync_epoch', lower(hex(randomblob(8))));

-- ── Items ─────────────────────────────────────────────────

CREATE TRIGGER ciphers_seq_insert AFTER INSERT ON ciphers BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE organizations SET seq = seq + 1 WHERE id = NEW.organization_id;
    UPDATE ciphers SET seq = coalesce((SELECT seq FROM users WHERE id = NEW.user_id),
        (SELECT seq FROM organizations WHERE id = NEW.organization_id), 0) WHERE id = NEW.id;
END;

CREATE TRIGGER ciphers_seq_update AFTER UPDATE ON ciphers BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE organizations SET seq = seq + 1 WHERE id = NEW.organization_id;
    UPDATE ciphers SET seq = coalesce((SELECT seq FROM users WHERE id = NEW.user_id),
        (SELECT seq FROM organizations WHERE id = NEW.organization_id), 0) WHERE id = NEW.id;
END;

-- Given to an organisation: gone from the person's own items.
CREATE TRIGGER ciphers_moved AFTER UPDATE OF user_id ON ciphers
WHEN OLD.user_id IS NOT NULL AND NEW.user_id IS NOT OLD.user_id BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = OLD.user_id;
    INSERT INTO tombstones (owner, kind, object_id, seq, time)
    SELECT id, 'cipher', OLD.id, seq, unixepoch() FROM users WHERE id = OLD.user_id;
END;

CREATE TRIGGER ciphers_tombstone AFTER DELETE ON ciphers BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = OLD.user_id;
    UPDATE organizations SET seq = seq + 1 WHERE id = OLD.organization_id;
    INSERT INTO tombstones (owner, kind, object_id, seq, time)
    SELECT id, 'cipher', OLD.id, seq, unixepoch() FROM users WHERE id = OLD.user_id
    UNION ALL
    SELECT id, 'cipher', OLD.id, seq, unixepoch() FROM organizations WHERE id = OLD.organization_id;
END;

-- What an item shows beside itself: its attachments, its collections. Setting `seq` fires the
-- item's own trigger, which gives it its number.
CREATE TRIGGER attachments_seq_insert AFTER INSERT ON attachments BEGIN
    UPDATE ciphers SET seq = 0 WHERE id = NEW.cipher_id;
END;
CREATE TRIGGER attachments_seq_update AFTER UPDATE ON attachments BEGIN
    UPDATE ciphers SET seq = 0 WHERE id = NEW.cipher_id;
END;
CREATE TRIGGER attachments_seq_delete AFTER DELETE ON attachments BEGIN
    UPDATE ciphers SET seq = 0 WHERE id = OLD.cipher_id;
END;
CREATE TRIGGER collection_ciphers_seq_insert AFTER INSERT ON collection_ciphers BEGIN
    UPDATE ciphers SET seq = 0 WHERE id = NEW.cipher_id;
END;
CREATE TRIGGER collection_ciphers_seq_delete AFTER DELETE ON collection_ciphers BEGIN
    UPDATE ciphers SET seq = 0 WHERE id = OLD.cipher_id;
END;

-- A member's own folder and star for an organisation's item.
CREATE TRIGGER cipher_preferences_seq_insert AFTER INSERT ON cipher_preferences BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE cipher_preferences SET seq = (SELECT seq FROM users WHERE id = NEW.user_id)
    WHERE cipher_id = NEW.cipher_id AND user_id = NEW.user_id;
END;
CREATE TRIGGER cipher_preferences_seq_update AFTER UPDATE ON cipher_preferences BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE cipher_preferences SET seq = (SELECT seq FROM users WHERE id = NEW.user_id)
    WHERE cipher_id = NEW.cipher_id AND user_id = NEW.user_id;
END;

-- ── Folders and Sends ─────────────────────────────────────

CREATE TRIGGER folders_seq_insert AFTER INSERT ON folders BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE folders SET seq = (SELECT seq FROM users WHERE id = NEW.user_id) WHERE id = NEW.id;
END;
CREATE TRIGGER folders_seq_update AFTER UPDATE ON folders BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE folders SET seq = (SELECT seq FROM users WHERE id = NEW.user_id) WHERE id = NEW.id;
END;
CREATE TRIGGER folders_tombstone AFTER DELETE ON folders BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = OLD.user_id;
    INSERT INTO tombstones (owner, kind, object_id, seq, time)
    SELECT id, 'folder', OLD.id, seq, unixepoch() FROM users WHERE id = OLD.user_id;
END;
-- Hidden or shown while travelling: what the account sees changes wholesale.
CREATE TRIGGER folders_travel AFTER UPDATE OF travel ON folders
WHEN OLD.travel IS NOT NEW.travel AND EXISTS (SELECT 1 FROM travel WHERE user_id = NEW.user_id) BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id = NEW.user_id;
END;

CREATE TRIGGER sends_seq_insert AFTER INSERT ON sends BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE sends SET seq = (SELECT seq FROM users WHERE id = NEW.user_id) WHERE id = NEW.id;
END;
CREATE TRIGGER sends_seq_update AFTER UPDATE ON sends BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE sends SET seq = (SELECT seq FROM users WHERE id = NEW.user_id) WHERE id = NEW.id;
END;
CREATE TRIGGER sends_tombstone AFTER DELETE ON sends BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = OLD.user_id;
    INSERT INTO tombstones (owner, kind, object_id, seq, time)
    SELECT id, 'send', OLD.id, seq, unixepoch() FROM users WHERE id = OLD.user_id;
END;

-- ── The account itself ────────────────────────────────────

-- What the profile, the equivalent domains and the unlock options show.
CREATE TRIGGER users_profile AFTER UPDATE ON users
WHEN OLD.name IS NOT NEW.name OR OLD.email IS NOT NEW.email OR OLD.language IS NOT NEW.language
    OR OLD.user_key IS NOT NEW.user_key OR OLD.user_key_id IS NOT NEW.user_key_id
    OR OLD.private_key IS NOT NEW.private_key OR OLD.public_key IS NOT NEW.public_key
    OR OLD.kdf_type IS NOT NEW.kdf_type OR OLD.kdf_iterations IS NOT NEW.kdf_iterations
    OR OLD.kdf_memory IS NOT NEW.kdf_memory OR OLD.kdf_parallelism IS NOT NEW.kdf_parallelism
    OR OLD.security_stamp IS NOT NEW.security_stamp OR OLD.avatar_color IS NOT NEW.avatar_color
    OR OLD.equivalent_domains IS NOT NEW.equivalent_domains OR OLD.excluded_globals IS NOT NEW.excluded_globals
BEGIN
    UPDATE users SET seq = seq + 1, profile_seq = seq + 1 WHERE id = NEW.id;
END;

-- A new key or stamp (a rotation, a new password or KDF, "log out everywhere"): everything again.
CREATE TRIGGER users_epoch AFTER UPDATE ON users
WHEN OLD.security_stamp IS NOT NEW.security_stamp OR OLD.user_key IS NOT NEW.user_key BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id = NEW.id;
END;

-- Two-step login on or off shows in the profile.
CREATE TRIGGER two_factor_profile_insert AFTER INSERT ON two_factor BEGIN
    UPDATE users SET seq = seq + 1, profile_seq = seq + 1 WHERE id = NEW.user_id;
END;
CREATE TRIGGER two_factor_profile_update AFTER UPDATE OF enabled ON two_factor WHEN OLD.enabled IS NOT NEW.enabled BEGIN
    UPDATE users SET seq = seq + 1, profile_seq = seq + 1 WHERE id = NEW.user_id;
END;
CREATE TRIGGER two_factor_profile_delete AFTER DELETE ON two_factor BEGIN
    UPDATE users SET seq = seq + 1, profile_seq = seq + 1 WHERE id = OLD.user_id;
END;

-- ── Organisations ─────────────────────────────────────────

-- Its name and keys are in every member's profile.
CREATE TRIGGER organizations_profile AFTER UPDATE ON organizations
WHEN OLD.name IS NOT NEW.name OR OLD.public_key IS NOT NEW.public_key OR OLD.private_key IS NOT NEW.private_key
    OR OLD.plan_type IS NOT NEW.plan_type OR OLD.billing_email IS NOT NEW.billing_email
BEGIN
    UPDATE users SET seq = seq + 1, profile_seq = seq + 1
    WHERE id IN (SELECT user_id FROM org_members WHERE org_id = NEW.id AND user_id IS NOT NULL);
END;

-- Who is in it, and with what: what the member sees changes wholesale.
CREATE TRIGGER org_members_epoch_insert AFTER INSERT ON org_members WHEN NEW.user_id IS NOT NULL BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id = NEW.user_id;
END;
CREATE TRIGGER org_members_epoch_update AFTER UPDATE ON org_members
WHEN OLD.user_id IS NOT NEW.user_id OR OLD.status IS NOT NEW.status OR OLD.type IS NOT NEW.type
    OR OLD.access_all IS NOT NEW.access_all OR OLD.permissions IS NOT NEW.permissions OR OLD.key IS NOT NEW.key
    OR OLD.reset_password_key IS NOT NEW.reset_password_key
BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id IN (OLD.user_id, NEW.user_id);
END;
CREATE TRIGGER org_members_epoch_delete AFTER DELETE ON org_members WHEN OLD.user_id IS NOT NULL BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id = OLD.user_id;
END;

CREATE TRIGGER collection_members_epoch_insert AFTER INSERT ON collection_members BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1
    WHERE id = (SELECT user_id FROM org_members WHERE id = NEW.member_id);
END;
CREATE TRIGGER collection_members_epoch_update AFTER UPDATE ON collection_members BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1
    WHERE id IN (SELECT user_id FROM org_members WHERE id IN (OLD.member_id, NEW.member_id));
END;
CREATE TRIGGER collection_members_epoch_delete AFTER DELETE ON collection_members BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1
    WHERE id = (SELECT user_id FROM org_members WHERE id = OLD.member_id);
END;

CREATE TRIGGER collection_groups_epoch_insert AFTER INSERT ON collection_groups BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id IN (SELECT m.user_id FROM group_members gm
        JOIN org_members m ON m.id = gm.member_id WHERE gm.group_id = NEW.group_id);
END;
CREATE TRIGGER collection_groups_epoch_update AFTER UPDATE ON collection_groups BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id IN (SELECT m.user_id FROM group_members gm
        JOIN org_members m ON m.id = gm.member_id WHERE gm.group_id IN (OLD.group_id, NEW.group_id));
END;
CREATE TRIGGER collection_groups_epoch_delete AFTER DELETE ON collection_groups BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id IN (SELECT m.user_id FROM group_members gm
        JOIN org_members m ON m.id = gm.member_id WHERE gm.group_id = OLD.group_id);
END;

CREATE TRIGGER group_members_epoch_insert AFTER INSERT ON group_members BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1
    WHERE id = (SELECT user_id FROM org_members WHERE id = NEW.member_id);
END;
CREATE TRIGGER group_members_epoch_delete AFTER DELETE ON group_members BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1
    WHERE id = (SELECT user_id FROM org_members WHERE id = OLD.member_id);
END;
CREATE TRIGGER groups_epoch AFTER UPDATE OF access_all ON groups WHEN OLD.access_all IS NOT NEW.access_all BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id IN (SELECT m.user_id FROM group_members gm
        JOIN org_members m ON m.id = gm.member_id WHERE gm.group_id = NEW.id);
END;

CREATE TRIGGER collections_seq_insert AFTER INSERT ON collections BEGIN
    UPDATE organizations SET seq = seq + 1 WHERE id = NEW.org_id;
    UPDATE collections SET seq = (SELECT seq FROM organizations WHERE id = NEW.org_id) WHERE id = NEW.id;
END;
CREATE TRIGGER collections_seq_update AFTER UPDATE ON collections BEGIN
    UPDATE organizations SET seq = seq + 1 WHERE id = NEW.org_id;
    UPDATE collections SET seq = (SELECT seq FROM organizations WHERE id = NEW.org_id) WHERE id = NEW.id;
END;
CREATE TRIGGER collections_tombstone AFTER DELETE ON collections BEGIN
    UPDATE organizations SET seq = seq + 1 WHERE id = OLD.org_id;
    INSERT INTO tombstones (owner, kind, object_id, seq, time)
    SELECT id, 'collection', OLD.id, seq, unixepoch() FROM organizations WHERE id = OLD.org_id;
END;

CREATE TRIGGER policies_seq_insert AFTER INSERT ON policies BEGIN
    UPDATE organizations SET seq = seq + 1, policies_seq = seq + 1 WHERE id = NEW.org_id;
END;
CREATE TRIGGER policies_seq_update AFTER UPDATE ON policies BEGIN
    UPDATE organizations SET seq = seq + 1, policies_seq = seq + 1 WHERE id = NEW.org_id;
END;
CREATE TRIGGER policies_seq_delete AFTER DELETE ON policies BEGIN
    UPDATE organizations SET seq = seq + 1, policies_seq = seq + 1 WHERE id = OLD.org_id;
END;

-- ── UwULock's own ─────────────────────────────────────────

CREATE TRIGGER own_icons_seq_insert AFTER INSERT ON own_icons BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = (SELECT user_id FROM ciphers WHERE id = NEW.cipher_id);
    UPDATE organizations SET seq = seq + 1 WHERE id = (SELECT organization_id FROM ciphers WHERE id = NEW.cipher_id);
    UPDATE own_icons SET owner = (SELECT coalesce(user_id, organization_id) FROM ciphers WHERE id = NEW.cipher_id),
        seq = coalesce((SELECT u.seq FROM ciphers c JOIN users u ON u.id = c.user_id WHERE c.id = NEW.cipher_id),
            (SELECT o.seq FROM ciphers c JOIN organizations o ON o.id = c.organization_id WHERE c.id = NEW.cipher_id), 0)
    WHERE cipher_id = NEW.cipher_id;
END;
CREATE TRIGGER own_icons_seq_update AFTER UPDATE ON own_icons BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = (SELECT user_id FROM ciphers WHERE id = NEW.cipher_id);
    UPDATE organizations SET seq = seq + 1 WHERE id = (SELECT organization_id FROM ciphers WHERE id = NEW.cipher_id);
    UPDATE own_icons SET owner = (SELECT coalesce(user_id, organization_id) FROM ciphers WHERE id = NEW.cipher_id),
        seq = coalesce((SELECT u.seq FROM ciphers c JOIN users u ON u.id = c.user_id WHERE c.id = NEW.cipher_id),
            (SELECT o.seq FROM ciphers c JOIN organizations o ON o.id = c.organization_id WHERE c.id = NEW.cipher_id), 0)
    WHERE cipher_id = NEW.cipher_id;
END;
-- Gone with its item, the item's tombstone says enough; taken off on its own, it needs one.
CREATE TRIGGER own_icons_tombstone AFTER DELETE ON own_icons BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = OLD.owner;
    UPDATE organizations SET seq = seq + 1 WHERE id = OLD.owner;
    INSERT INTO tombstones (owner, kind, object_id, seq, time)
    SELECT id, 'icon', OLD.cipher_id, seq, unixepoch() FROM users WHERE id = OLD.owner
    UNION ALL
    SELECT id, 'icon', OLD.cipher_id, seq, unixepoch() FROM organizations WHERE id = OLD.owner;
END;

CREATE TRIGGER reminders_seq_insert AFTER INSERT ON reminders BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE reminders SET seq = (SELECT seq FROM users WHERE id = NEW.user_id)
    WHERE user_id = NEW.user_id AND cipher_id = NEW.cipher_id;
END;
CREATE TRIGGER reminders_seq_update AFTER UPDATE OF due, every_months ON reminders
WHEN OLD.due IS NOT NEW.due OR OLD.every_months IS NOT NEW.every_months BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE reminders SET seq = (SELECT seq FROM users WHERE id = NEW.user_id)
    WHERE user_id = NEW.user_id AND cipher_id = NEW.cipher_id;
END;
CREATE TRIGGER reminders_tombstone AFTER DELETE ON reminders BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = OLD.user_id;
    INSERT INTO tombstones (owner, kind, object_id, seq, time)
    SELECT id, 'reminder', OLD.cipher_id, seq, unixepoch() FROM users WHERE id = OLD.user_id;
END;

CREATE TRIGGER extras_keys_seq_insert AFTER INSERT ON extras_keys BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE extras_keys SET seq = (SELECT seq FROM users WHERE id = NEW.user_id) WHERE user_id = NEW.user_id;
END;
CREATE TRIGGER extras_keys_seq_update AFTER UPDATE ON extras_keys BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = NEW.user_id;
    UPDATE extras_keys SET seq = (SELECT seq FROM users WHERE id = NEW.user_id) WHERE user_id = NEW.user_id;
END;
CREATE TRIGGER extras_keys_epoch AFTER DELETE ON extras_keys BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id = OLD.user_id;
END;

-- Travel mode on or off.
CREATE TRIGGER travel_epoch_insert AFTER INSERT ON travel BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id = NEW.user_id;
END;
CREATE TRIGGER travel_epoch_delete AFTER DELETE ON travel BEGIN
    UPDATE users SET sync_epoch = sync_epoch + 1 WHERE id = OLD.user_id;
END;
