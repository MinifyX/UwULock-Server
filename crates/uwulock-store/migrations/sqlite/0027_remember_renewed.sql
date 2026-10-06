-- "Remember this device" lasts as long as the admin sets (30, 90, 365 days or without end), counted
-- from the last login with the remembered device. So a device keeps when that was, not when it
-- runs out: a shorter setting then holds for devices remembered before, too. What was remembered
-- before ran 30 days from its login, so that login was 30 days before its end.
ALTER TABLE devices RENAME COLUMN remember_expires TO remember_renewed;
UPDATE devices
SET remember_renewed = strftime('%Y-%m-%dT%H:%M:%S', remember_renewed, '-30 days') || substr(remember_renewed, 20)
WHERE remember_renewed IS NOT NULL;
UPDATE devices SET remember_renewed = NULL WHERE remember_hash IS NULL;
