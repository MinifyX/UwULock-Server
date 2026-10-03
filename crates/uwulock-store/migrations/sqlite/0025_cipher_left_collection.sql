-- R1-7: a delta tells a member of an organisation's item that is out of their reach only when
-- they could have had it: when it left a collection they see. So leaving a collection is written
-- down, with the collection, as a tombstone of its own kind (`cipher-left`) — never handed out
-- itself, only looked at beside the item. Its number is one past the organisation's, whichever
-- trigger of the change runs first, so it is never below the window it belongs to.
CREATE TRIGGER collection_ciphers_left AFTER DELETE ON collection_ciphers BEGIN
    INSERT INTO tombstones (owner, kind, object_id, seq, time, collections)
    SELECT o.id, 'cipher-left', OLD.cipher_id, o.seq + 1, unixepoch(), json_array(OLD.collection_id)
    FROM ciphers c JOIN organizations o ON o.id = c.organization_id WHERE c.id = OLD.cipher_id;
END;
