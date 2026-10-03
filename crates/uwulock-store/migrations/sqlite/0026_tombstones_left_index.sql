-- R5 I-3: a delta looks for an item's `cipher-left` tombstones by organisation, item and number
-- once per changed item out of the member's reach. With only `tombstones_by_owner (owner, seq)`
-- that read every tombstone of the organisation in the window; this finds the item's own.
CREATE INDEX tombstones_left ON tombstones (owner, object_id, seq) WHERE kind = 'cipher-left';
