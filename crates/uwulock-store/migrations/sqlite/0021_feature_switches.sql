-- Feature switches (docs/features.md): the extras an admin turns on or off, kept as JSON under
-- `features` in `server`. A new server has no accounts yet when this runs and gets nothing here:
-- it starts with UWULOCK_FEATURES, by default none of the extras. A server that was running
-- before keeps each extra on that is in use — something is kept for it, or it is set up — and
-- has the others off. An extra an admin had switched off already (file requests, the suite
-- vault, the icon library) stays off.
INSERT INTO server (key, value)
SELECT 'features', json_object(
    'families', json(CASE WHEN EXISTS (SELECT 1 FROM organizations) THEN 'true' ELSE 'false' END),
    'file-requests', json(CASE WHEN EXISTS (SELECT 1 FROM file_requests)
        AND coalesce((SELECT json_extract(value, '$.fileRequests.enabled') FROM server WHERE key = 'settings'), 1)
        THEN 'true' ELSE 'false' END),
    'send-domains', json(CASE WHEN EXISTS (SELECT 1 FROM send_domains) THEN 'true' ELSE 'false' END),
    'masked-addresses', json(CASE WHEN EXISTS (SELECT 1 FROM masked_connections)
        OR EXISTS (SELECT 1 FROM masked_links)
        OR EXISTS (SELECT 1 FROM masked_api_keys)
        OR coalesce((SELECT json_array_length(value, '$.masked.servers') FROM server WHERE key = 'settings'), 0) > 0
        THEN 'true' ELSE 'false' END),
    'versions', json(CASE WHEN EXISTS (SELECT 1 FROM cipher_versions) THEN 'true' ELSE 'false' END),
    'reminders', json(CASE WHEN EXISTS (SELECT 1 FROM reminders) THEN 'true' ELSE 'false' END),
    'travel-mode', json(CASE WHEN EXISTS (SELECT 1 FROM travel) OR EXISTS (SELECT 1 FROM folders WHERE travel)
        THEN 'true' ELSE 'false' END),
    -- Made in the browser, nothing of it is kept.
    'emergency-sheet', json('false'),
    'own-icons', json(CASE WHEN EXISTS (SELECT 1 FROM own_icons) THEN 'true' ELSE 'false' END),
    -- A library icon is kept as an own icon.
    'icon-library', json(CASE WHEN EXISTS (SELECT 1 FROM own_icons)
        AND coalesce((SELECT json_extract(value, '$.icons.library') FROM server WHERE key = 'settings'), 1)
        THEN 'true' ELSE 'false' END),
    -- The list is fetched for the password check, whose report is kept.
    'twofa-directory', json(CASE WHEN EXISTS (SELECT 1 FROM health_reports) THEN 'true' ELSE 'false' END),
    'sso', json(CASE WHEN EXISTS (SELECT 1 FROM sso_identities)
        OR coalesce((SELECT json_extract(value, '$.sso.enabled') FROM server WHERE key = 'settings'), 0)
        OR coalesce((SELECT trim(json_extract(value, '$.sso.issuer')) FROM server WHERE key = 'settings'), '') <> ''
        THEN 'true' ELSE 'false' END),
    'scim', json(CASE WHEN EXISTS (SELECT 1 FROM scim_provisioned)
        OR EXISTS (SELECT 1 FROM scim_groups)
        OR (SELECT json_extract(value, '$.scim.tokenHash') FROM server WHERE key = 'settings') IS NOT NULL
        THEN 'true' ELSE 'false' END),
    'offsite-backups', json(CASE
        WHEN (SELECT json_extract(value, '$.target') FROM server WHERE key = 'offsite.settings') IS NOT NULL
        THEN 'true' ELSE 'false' END),
    -- Mail to the admins is always there; the switch is for ntfy, Gotify and Matrix.
    'admin-notifications', json(CASE WHEN EXISTS (SELECT 1 FROM notification_channels WHERE kind <> 'mail')
        THEN 'true' ELSE 'false' END),
    'suite', json(CASE WHEN EXISTS (SELECT 1 FROM suite_spaces)
        AND coalesce((SELECT json_extract(value, '$.suite.enabled') FROM server WHERE key = 'settings'), 1)
        THEN 'true' ELSE 'false' END)
)
WHERE EXISTS (SELECT 1 FROM users)
ON CONFLICT (key) DO NOTHING;
