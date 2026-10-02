-- Bitwarden's push relay is gone (docs/plan.md, Planänderung 0.8): its settings with the
-- installation id and key, the phones' push tokens and the relay's ids for them, and the
-- notification event about the relay failing. Bitwarden's apps sync when they are opened; live
-- updates go over the server's own WebSocket.

UPDATE server SET value = json_remove(value, '$.push') WHERE key = 'settings' AND json_valid(value);

ALTER TABLE devices DROP COLUMN push_id;
ALTER TABLE devices DROP COLUMN push_token;

UPDATE notification_channels
SET events = (
    SELECT json_group_array(event.value) FROM json_each(notification_channels.events) AS event
    WHERE event.value <> 'pushRelayFailing'
)
WHERE json_valid(events) AND events LIKE '%pushRelayFailing%';
