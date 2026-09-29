-- Fixes of the 0.6 review's low findings (docs/security-review-0.6.md).

-- SV-L2: the accounts SCIM disabled. SCIM enables only these again; an account an admin disabled
-- stays disabled whatever the provider says. Enabling an account in any way forgets the mark.
CREATE TABLE scim_disabled (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TRIGGER scim_disabled_forget AFTER UPDATE OF disabled ON users
WHEN OLD.disabled AND NOT NEW.disabled
BEGIN
    DELETE FROM scim_disabled WHERE user_id = NEW.id;
END;

-- SV-L7: a delta hands an organisation's deletions only to members who could see the item. The
-- item's collections are kept with its tombstone (a JSON array; NULL for a person's own item and
-- for tombstones from before). They are read before the item goes: the collection links go with
-- it.
ALTER TABLE tombstones ADD COLUMN collections TEXT;

DROP TRIGGER ciphers_tombstone;
CREATE TRIGGER ciphers_tombstone BEFORE DELETE ON ciphers BEGIN
    UPDATE users SET seq = seq + 1 WHERE id = OLD.user_id;
    UPDATE organizations SET seq = seq + 1 WHERE id = OLD.organization_id;
    INSERT INTO tombstones (owner, kind, object_id, seq, time)
    SELECT id, 'cipher', OLD.id, seq, unixepoch() FROM users WHERE id = OLD.user_id;
    INSERT INTO tombstones (owner, kind, object_id, seq, time, collections)
    SELECT id, 'cipher', OLD.id, seq, unixepoch(),
        (SELECT json_group_array(collection_id) FROM collection_ciphers WHERE cipher_id = OLD.id)
    FROM organizations WHERE id = OLD.organization_id;
END;

-- Every cursor starts over once, so no client needs a tombstone from before.
UPDATE server SET value = lower(hex(randomblob(8))) WHERE key = 'sync_epoch';

-- SV-L9: reminders and masked links of an organisation's items go with the membership: when a
-- member is removed or revoked, and for those left from before.
CREATE TRIGGER org_members_gone_extras AFTER DELETE ON org_members WHEN OLD.user_id IS NOT NULL BEGIN
    DELETE FROM reminders WHERE user_id = OLD.user_id
        AND cipher_id IN (SELECT id FROM ciphers WHERE organization_id = OLD.org_id);
    DELETE FROM masked_links WHERE user_id = OLD.user_id
        AND cipher_id IN (SELECT id FROM ciphers WHERE organization_id = OLD.org_id);
END;

CREATE TRIGGER org_members_revoked_extras AFTER UPDATE OF status ON org_members
WHEN NEW.user_id IS NOT NULL AND NEW.status = -1 AND OLD.status IS NOT -1 BEGIN
    DELETE FROM reminders WHERE user_id = NEW.user_id
        AND cipher_id IN (SELECT id FROM ciphers WHERE organization_id = NEW.org_id);
    DELETE FROM masked_links WHERE user_id = NEW.user_id
        AND cipher_id IN (SELECT id FROM ciphers WHERE organization_id = NEW.org_id);
END;

DELETE FROM reminders WHERE EXISTS (
    SELECT 1 FROM ciphers c WHERE c.id = reminders.cipher_id AND c.organization_id IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM org_members m WHERE m.org_id = c.organization_id
            AND m.user_id = reminders.user_id AND m.status = 2));
DELETE FROM masked_links WHERE EXISTS (
    SELECT 1 FROM ciphers c WHERE c.id = masked_links.cipher_id AND c.organization_id IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM org_members m WHERE m.org_id = c.organization_id
            AND m.user_id = masked_links.user_id AND m.status = 2));
