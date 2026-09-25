-- What the server knows about itself: when this database was made, and later its settings.
CREATE TABLE server (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;

INSERT INTO server (key, value) VALUES ('created', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
