-- Send domains (Stufe 6; docs/uwu-api.md §14.1, §14.2): extra hosts that serve only Sends and
-- file requests, and which of them a Send's link and page use.

-- `host` in lower case, without scheme or port. `tls`: 'acme' (the server's own certificate from
-- Let's Encrypt) or 'proxy' (a proxy in front terminates TLS). The certificate itself lives in the
-- ACME cache on disk like the main host's; its state is the running server's.
CREATE TABLE send_domains (
    id      TEXT PRIMARY KEY NOT NULL,
    host    TEXT NOT NULL UNIQUE,
    tls     TEXT NOT NULL,
    created TEXT NOT NULL
) STRICT;

-- The domain a Send's link and page use; NULL for the main host. A Send is reachable on every
-- host all the same, so a domain that goes only changes which link the clients show.
ALTER TABLE sends ADD COLUMN domain_id TEXT REFERENCES send_domains (id) ON DELETE SET NULL;

-- The account's default for new Sends, which is also what a Send made by an official client gets.
ALTER TABLE users ADD COLUMN send_domain_id TEXT REFERENCES send_domains (id) ON DELETE SET NULL;
