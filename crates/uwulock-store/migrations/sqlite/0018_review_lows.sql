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
