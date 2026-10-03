-- An API key belongs to the security stamp it was made under (R1-5): a password change, "log
-- out everywhere", a key rotation, an emergency takeover or an admin's log-out change the stamp,
-- and the key stops working with it. The next fetch makes a new one. Keys there are now keep
-- working until the stamp changes.
ALTER TABLE api_keys ADD COLUMN stamp TEXT NOT NULL DEFAULT '';
UPDATE api_keys SET stamp = coalesce((SELECT security_stamp FROM users WHERE users.id = api_keys.user_id), '');
