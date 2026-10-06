//! The schema, one numbered step at a time.
//!
//! Each step is a file under `migrations/sqlite`, applied once, in order, inside a transaction.
//! How far a database has come is its `user_version`. A step is never changed once it is
//! released: a database that went through it already would not go through it again.

use crate::{Result, StoreError};
use rusqlite::Connection;

const STEPS: &[&str] = &[
    include_str!("../migrations/sqlite/0001_server.sql"),
    include_str!("../migrations/sqlite/0002_accounts.sql"),
    include_str!("../migrations/sqlite/0003_features.sql"),
    include_str!("../migrations/sqlite/0004_organizations.sql"),
    include_str!("../migrations/sqlite/0005_admin.sql"),
    include_str!("../migrations/sqlite/0006_operations.sql"),
    include_str!("../migrations/sqlite/0007_file_requests.sql"),
    include_str!("../migrations/sqlite/0008_sso.sql"),
    include_str!("../migrations/sqlite/0009_vault_comfort.sql"),
    include_str!("../migrations/sqlite/0010_sends_branding_reports.sql"),
    include_str!("../migrations/sqlite/0011_families.sql"),
    include_str!("../migrations/sqlite/0012_delta_sync.sql"),
    include_str!("../migrations/sqlite/0013_suite.sql"),
    include_str!("../migrations/sqlite/0014_send_domains.sql"),
    include_str!("../migrations/sqlite/0015_masked.sql"),
    include_str!("../migrations/sqlite/0016_extras_private_wrap.sql"),
    include_str!("../migrations/sqlite/0017_feature_switches.sql"),
    include_str!("../migrations/sqlite/0018_review_lows.sql"),
    include_str!("../migrations/sqlite/0019_failed_logins.sql"),
    include_str!("../migrations/sqlite/0022_breach_sources.sql"),
    include_str!("../migrations/sqlite/0023_drop_push_relay.sql"),
    include_str!("../migrations/sqlite/0024_api_key_stamp.sql"),
    include_str!("../migrations/sqlite/0025_cipher_left_collection.sql"),
    include_str!("../migrations/sqlite/0026_tombstones_left_index.sql"),
    include_str!("../migrations/sqlite/0027_remember_renewed.sql"),
];

/// The schema this build writes.
pub const SCHEMA_VERSION: i64 = STEPS.len() as i64;

pub(crate) fn run(conn: &mut Connection) -> Result<()> {
    let found: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::TooNew { found, known: SCHEMA_VERSION });
    }
    if found == SCHEMA_VERSION {
        return Ok(());
    }
    // A step may build a table again (SQLite changes no column in place), which with foreign
    // keys on would take everything that points at the old table with it. So they are off while
    // the steps run — outside the transactions, the only place SQLite lets that change — and
    // checked before they are on again.
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    let result = (|| -> Result<()> {
        for (index, step) in STEPS.iter().enumerate().skip(found as usize) {
            let version = index as i64 + 1;
            let tx = conn.transaction()?;
            tx.execute_batch(step)?;
            let broken: i64 = tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| row.get(0))?;
            if broken > 0 {
                return Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY),
                    Some(format!("schema step {version} left {broken} broken references")),
                )));
            }
            tx.pragma_update(None, "user_version", version)?;
            tx.commit()?;
            tracing::info!(version, "database schema updated");
        }
        Ok(())
    })();
    conn.pragma_update(None, "foreign_keys", "ON")?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database from 0.1 with an item and an attachment on it goes through the step that builds
    /// `ciphers` again — and keeps both, the attachment still pointing at its item.
    #[test]
    fn an_older_database_keeps_its_items_and_their_attachments() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        for step in &STEPS[..3] {
            conn.execute_batch(step).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO users (id, email, password_hash, user_key, kdf_type, kdf_iterations, security_stamp, language, \
             created, updated, revision) VALUES ('u', 'nyu@example.com', 'h', 'k', 0, 600000, 's', 'de', 't', 't', 't');
             INSERT INTO ciphers (id, user_id, type, name, data, created, revision) VALUES ('c', 'u', 1, 'n', '{}', 't', 't');
             INSERT INTO attachments (id, cipher_id, file_name, size, uploaded, created) VALUES ('a', 'c', 'f', 1, 1, 't');",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 3).unwrap();
        run(&mut conn).unwrap();
        let (user, org): (Option<String>, Option<String>) = conn
            .query_row("SELECT user_id, organization_id FROM ciphers WHERE id = 'c'", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!((user.as_deref(), org), (Some("u"), None));
        let attachments: i64 = conn.query_row("SELECT count(*) FROM attachments", [], |row| row.get(0)).unwrap();
        assert_eq!(attachments, 1);
        let on: i64 = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0)).unwrap();
        assert_eq!(on, 1, "foreign keys are on again");
        conn.execute("DELETE FROM ciphers WHERE id = 'c'", []).unwrap();
        let left: i64 = conn.query_row("SELECT count(*) FROM attachments", [], |row| row.get(0)).unwrap();
        assert_eq!(left, 0, "and the attachment still goes with its item");
    }

    /// A device remembered for 30 days before 0027 keeps the login that remembered it, 30 days
    /// before its end, to the microsecond; one not remembered keeps nothing.
    #[test]
    fn a_remembered_device_keeps_when_it_was_remembered() {
        let mut conn = Connection::open_in_memory().unwrap();
        let step = STEPS.iter().position(|step| step.contains("RENAME COLUMN remember_expires")).unwrap();
        for step in &STEPS[..step] {
            conn.execute_batch(step).unwrap();
        }
        conn.pragma_update(None, "user_version", step as i64).unwrap();
        conn.execute_batch(
            "INSERT INTO users (id, email, password_hash, user_key, kdf_type, kdf_iterations, security_stamp, language, \
             created, updated, revision) VALUES ('u', 'nyu@example.com', 'h', 'k', 0, 600000, 's', 'de', 't', 't', 't');
             INSERT INTO devices (user_id, id, name, type, created, last_seen, remember_hash, remember_expires) VALUES
               ('u', 'd1', 'n', 8, 't', 't', x'01', '2026-03-31T12:34:56.123456Z'),
               ('u', 'd2', 'n', 8, 't', 't', NULL, '2026-03-31T12:34:56.123456Z');",
        )
        .unwrap();
        run(&mut conn).unwrap();
        let renewed = |id: &str| -> Option<String> {
            conn.query_row("SELECT remember_renewed FROM devices WHERE id = ?1", [id], |row| row.get(0)).unwrap()
        };
        assert_eq!(renewed("d1").as_deref(), Some("2026-03-01T12:34:56.123456Z"));
        assert_eq!(renewed("d2"), None);
    }

    /// The schema up to the step before the feature switches.
    fn before_switches() -> (Connection, usize) {
        let conn = Connection::open_in_memory().unwrap();
        let step = STEPS.iter().position(|step| step.starts_with("-- Feature switches")).unwrap();
        for step in &STEPS[..step] {
            conn.execute_batch(step).unwrap();
        }
        conn.pragma_update(None, "user_version", step as i64).unwrap();
        (conn, step)
    }

    fn switches(conn: &Connection) -> Option<serde_json::Value> {
        use rusqlite::OptionalExtension;
        conn.query_row("SELECT value FROM server WHERE key = 'features'", [], |row| row.get::<_, String>(0))
            .optional()
            .unwrap()
            .map(|json| serde_json::from_str(&json).unwrap())
    }

    /// A new server gets no switches from the step: it starts with its configuration's.
    #[test]
    fn a_new_server_gets_no_switches() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        assert_eq!(switches(&conn), None);
    }

    /// A server that was running keeps what is in use, set up or asked for, and nothing else.
    #[test]
    fn an_updated_server_keeps_on_what_is_in_use() {
        let (mut conn, _) = before_switches();
        conn.execute_batch(
            "INSERT INTO users (id, email, password_hash, user_key, kdf_type, kdf_iterations, security_stamp, language, \
             created, updated, revision) VALUES ('u', 'nyu@example.com', 'h', 'k', 0, 600000, 's', 'de', 't', 't', 't');
             INSERT INTO organizations (id, name, created, revision) VALUES ('o', 'Vaultwarden', 't', 't');
             INSERT INTO suite_spaces (user_id, space, id, key, seq, created, revision) VALUES ('u', 'ssh', 's', 'k', 0, 't', 't');
             INSERT INTO folders (id, user_id, name, created, revision, travel) VALUES ('f', 'u', 'n', 't', 't', 1);
             INSERT INTO server (key, value) VALUES ('settings',
                 '{\"masked\":{\"servers\":[{\"url\":\"https://mail.example.com\",\"name\":\"Mail\"}]},\"suite\":{\"enabled\":false}}');
             INSERT INTO server (key, value) VALUES ('offsite.settings', '{\"enabled\":false,\"target\":{\"kind\":\"folder\"}}');",
        )
        .unwrap();
        run(&mut conn).unwrap();
        let on = switches(&conn).unwrap();
        let expected = serde_json::json!({
            // An organisation, even one moved in from Vaultwarden.
            "families": true,
            // A UwUMail server listed.
            "masked-addresses": true,
            // A folder marked for travel.
            "travel-mode": true,
            // A target set up.
            "offsite-backups": true,
            // In use, but the admin had it switched off.
            "suite": false,
            // Nothing of these; mail to the admins does not count.
            "file-requests": false, "send-domains": false, "versions": false, "reminders": false,
            "emergency-sheet": false, "own-icons": false, "icon-library": false, "twofa-directory": false,
            "sso": false, "scim": false, "admin-notifications": false,
        });
        assert_eq!(on, expected);
    }

    /// A server that ran, with nothing of the extras: all off.
    #[test]
    fn an_updated_server_without_extras_has_them_off() {
        let (mut conn, _) = before_switches();
        conn.execute_batch(
            "INSERT INTO users (id, email, password_hash, user_key, kdf_type, kdf_iterations, security_stamp, language, \
             created, updated, revision) VALUES ('u', 'nyu@example.com', 'h', 'k', 0, 600000, 's', 'de', 't', 't', 't');
             INSERT INTO server (key, value) VALUES ('settings', '{\"sso\":{\"enabled\":true,\"issuer\":\"https://auth.example.com\"}}');
             INSERT INTO notification_channels (id, kind, name, enabled, events, config, created) VALUES
                 ('n', 'ntfy', 'Phone', 1, '[]', '{}', 't');",
        )
        .unwrap();
        run(&mut conn).unwrap();
        let on = switches(&conn).unwrap();
        let mut names: Vec<&str> = on
            .as_object()
            .unwrap()
            .iter()
            .filter(|(_, on)| on.as_bool() == Some(true))
            .map(|(name, _)| name.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(names, ["admin-notifications", "sso"]);
    }

    /// Step 0018's triggers: SCIM's mark goes when an account is enabled (SV-L2), an organisation
    /// item's tombstone keeps its collections (SV-L7), and reminders and masked links go with the
    /// membership (SV-L9).
    #[test]
    fn the_review_triggers_hold() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        conn.execute_batch(
            "INSERT INTO users (id, email, password_hash, user_key, kdf_type, kdf_iterations, security_stamp, language, \
             created, updated, revision) VALUES ('u', 'nyu@example.com', 'h', 'k', 0, 600000, 's', 'de', 't', 't', 't'), \
             ('v', 'mio@example.com', 'h', 'k', 0, 600000, 's', 'de', 't', 't', 't');
             INSERT INTO organizations (id, name, created, revision) VALUES ('o', 'n', 't', 't');
             INSERT INTO org_members (id, org_id, user_id, status, type, created, revision) VALUES ('m', 'o', 'v', 2, 2, 't', 't');
             INSERT INTO collections (id, org_id, name, created, revision) VALUES ('k', 'o', 'n', 't', 't');
             INSERT INTO ciphers (id, organization_id, type, name, data, created, revision) VALUES
                 ('c', 'o', 1, 'n', '{}', 't', 't'), ('d', 'o', 1, 'n', '{}', 't', 't');
             INSERT INTO collection_ciphers (collection_id, cipher_id) VALUES ('k', 'c');
             INSERT INTO reminders (user_id, cipher_id, due) VALUES ('v', 'd', '2020-01-01');
             INSERT INTO masked_links (user_id, masked_id, cipher_id, email, revision) VALUES ('v', 'x', 'd', 'e', 't');
             INSERT INTO scim_disabled (user_id) VALUES ('u');",
        )
        .unwrap();
        let count = |conn: &Connection, sql: &str| conn.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap();

        conn.execute("UPDATE users SET disabled = 1 WHERE id = 'u'", []).unwrap();
        assert_eq!(count(&conn, "SELECT count(*) FROM scim_disabled"), 1, "still disabled");
        conn.execute("UPDATE users SET disabled = 0 WHERE id = 'u'", []).unwrap();
        assert_eq!(count(&conn, "SELECT count(*) FROM scim_disabled"), 0, "enabled: the mark is gone");

        conn.execute("DELETE FROM ciphers WHERE id = 'c'", []).unwrap();
        let collections: String = conn
            .query_row("SELECT collections FROM tombstones WHERE object_id = 'c' AND owner = 'o'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(collections, r#"["k"]"#);

        conn.execute("UPDATE org_members SET status = -1 WHERE id = 'm'", []).unwrap();
        assert_eq!(
            count(&conn, "SELECT count(*) FROM reminders") + count(&conn, "SELECT count(*) FROM masked_links"),
            0
        );
    }

    /// The push relay's settings, the phones' tokens and the relay's event go; the rest stays.
    #[test]
    fn the_push_relay_is_dropped() {
        let mut conn = Connection::open_in_memory().unwrap();
        let step = STEPS.iter().position(|step| step.contains("Bitwarden's push relay is gone")).unwrap();
        for step in &STEPS[..step] {
            conn.execute_batch(step).unwrap();
        }
        conn.pragma_update(None, "user_version", step as i64).unwrap();
        conn.execute_batch(
            "INSERT INTO users (id, email, password_hash, user_key, kdf_type, kdf_iterations, security_stamp, language, \
             created, updated, revision) VALUES ('u', 'nyu@example.com', 'h', 'k', 0, 600000, 's', 'de', 't', 't', 't');
             INSERT INTO devices (user_id, id, name, type, created, last_seen, push_token, push_id) VALUES \
                 ('u', 'd', 'Phone', 0, 't', 't', 'fcm-1', 'p-1');
             INSERT INTO server (key, value) VALUES ('settings',
                 '{\"hibp\":true,\"push\":{\"installationId\":\"i\",\"installationKey\":\"k\",\"region\":\"eu\"}}');
             UPDATE notification_channels SET events = '[\"backupFailed\",\"pushRelayFailing\",\"diskLow\"]';",
        )
        .unwrap();
        run(&mut conn).unwrap();
        let settings: String =
            conn.query_row("SELECT value FROM server WHERE key = 'settings'", [], |row| row.get(0)).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&settings).unwrap(), serde_json::json!({ "hibp": true }));
        let columns: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('devices')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(!columns.iter().any(|name| name.starts_with("push")), "{columns:?}");
        let name: String = conn.query_row("SELECT name FROM devices WHERE id = 'd'", [], |row| row.get(0)).unwrap();
        assert_eq!(name, "Phone");
        let events: String = conn.query_row("SELECT events FROM notification_channels", [], |row| row.get(0)).unwrap();
        assert_eq!(events, r#"["backupFailed","diskLow"]"#);
    }

    /// Extras keys from before `privateKeyWrapped`: the old RSA wrap goes; one that still has
    /// its wrap under the user key keeps working, one that had only the old wrap left is lost.
    #[tokio::test]
    async fn extras_keys_with_only_the_rsa_wrap_are_lost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        {
            let conn = Connection::open(&path).unwrap();
            for step in &STEPS[..15] {
                conn.execute_batch(step).unwrap();
            }
            conn.execute_batch(
                "INSERT INTO users (id, email, password_hash, user_key, public_key, kdf_type, kdf_iterations, \
                 security_stamp, language, created, updated, revision) VALUES \
                 ('u1', 'nyu@example.com', 'h', 'k', 'pub1', 0, 600000, 's', 'de', 't', 't', 't'), \
                 ('u2', 'mika@example.com', 'h', 'k', 'pub2', 0, 600000, 's', 'de', 't', 't', 't');
                 INSERT INTO extras_keys (user_id, user_key_wrapped, public_key_wrapped, public_key, revision) VALUES \
                 ('u1', '2.a', '4.x', 'pub1', 't'), ('u2', NULL, '4.y', 'pub2', 't');",
            )
            .unwrap();
            conn.pragma_update(None, "user_version", 15).unwrap();
        }
        let store = crate::Store::open_sqlite(&path, &crate::Options { readers: 1 }).unwrap();
        let (kept, lost) = store.extras_key("u1").await.unwrap().unwrap();
        assert_eq!((kept.user_key_wrapped.as_deref(), kept.private_key_wrapped, lost), (Some("2.a"), None, false));
        let (gone, lost) = store.extras_key("u2").await.unwrap().unwrap();
        assert_eq!((gone.user_key_wrapped, gone.private_key_wrapped, lost), (None, None, true));
    }
}
