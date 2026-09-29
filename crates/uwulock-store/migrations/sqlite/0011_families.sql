-- Families (Stufe 4d; docs/uwu-api.md §16): organisations made and managed on this server.
--
-- An organisation now says what it is, in Bitwarden's plan numbers: 22 a family (owners and
-- members only, no groups, no policies), 20 an organisation of Stufe 5. What came from
-- Vaultwarden is a family when it needs no more than a family has.

ALTER TABLE organizations ADD COLUMN plan_type INTEGER NOT NULL DEFAULT 20;

UPDATE organizations SET plan_type = 22
WHERE NOT EXISTS (SELECT 1 FROM org_members m WHERE m.org_id = organizations.id AND m.type NOT IN (0, 2))
  AND NOT EXISTS (SELECT 1 FROM groups g WHERE g.org_id = organizations.id)
  AND NOT EXISTS (SELECT 1 FROM policies p WHERE p.org_id = organizations.id);

-- Invitations are found by address.
CREATE INDEX org_members_by_email ON org_members (email) WHERE email IS NOT NULL;
