-- The extras key's second wrap is under a key derived from the account's private key
-- (docs/uwu-api.md §3), not an RSA wrap for its public key: the server knows the public key and
-- could make such a wrap for a key of its own. Keys from before get the new wrap from the next
-- client that opens them with the user key; one that has only the old wrap left opens nowhere
-- any more and counts as lost (no wrap at all).
ALTER TABLE extras_keys ADD COLUMN private_key_wrapped TEXT;
ALTER TABLE extras_keys DROP COLUMN public_key_wrapped;

-- Every client hears of it with its next sync.
UPDATE extras_keys SET revision = revision;
