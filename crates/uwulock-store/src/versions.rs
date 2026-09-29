//! Entry versions (docs/uwu-api.md §8): whenever an item's encrypted content changes, the state
//! it had before is kept, as the clients encrypted it — so an old password or note can be brought
//! back. How many per item and for how long is the admin's choice ([`VersionRule`]).
//!
//! Only the content is kept: type, name, notes, the item key, the type's object, the fields, the
//! password history and the re-prompt flag. Folder, favourite, collections and attachments are
//! not; neither is a change that leaves the content as it was.

use crate::vault::{CIPHER_COLUMNS, cipher_from, write_cipher};
use crate::{Cipher, Result, Store, clock};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use serde_json::{Value, json};

/// How many versions an item keeps, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRule {
    /// Per item; 0 keeps none.
    pub per_item: u32,
    /// Days; 0 for no limit.
    pub days: u32,
}

impl Default for VersionRule {
    fn default() -> Self {
        VersionRule { per_item: 20, days: 365 }
    }
}

/// One earlier state of an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub id: String,
    pub cipher_id: String,
    /// The owner of a personal item.
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    /// JSON: see [`content_of`].
    pub content: String,
    /// The revision date the item had in this state.
    pub revision: String,
    /// When it was replaced.
    pub replaced: String,
    pub size: i64,
}

const VERSION_COLUMNS: &str = "id, cipher_id, user_id, organization_id, content, revision, replaced, size";

fn version_from(row: &Row<'_>) -> rusqlite::Result<Version> {
    Ok(Version {
        id: row.get(0)?,
        cipher_id: row.get(1)?,
        user_id: row.get(2)?,
        organization_id: row.get(3)?,
        content: row.get(4)?,
        revision: row.get(5)?,
        replaced: row.get(6)?,
        size: row.get(7)?,
    })
}

/// What of an item a version keeps, as JSON text: `type`, `name`, `notes`, `key`, `data` (the
/// type's object), `fields`, `passwordHistory` and `reprompt`. The last three as the text the
/// item holds them in, so they come back byte for byte.
pub fn content_of(cipher: &Cipher) -> String {
    json!({
        "type": cipher.kind,
        "name": cipher.name,
        "notes": cipher.notes,
        "key": cipher.key,
        "data": cipher.data,
        "fields": cipher.fields,
        "passwordHistory": cipher.password_history,
        "reprompt": cipher.reprompt,
    })
    .to_string()
}

/// `content` (from [`content_of`]) put over `cipher`: the item as it was in that version, with
/// everything else — folder, favourite, times — as it is.
pub fn apply_content(content: &str, cipher: &mut Cipher) {
    let value: Value = serde_json::from_str(content).unwrap_or(Value::Null);
    let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
    cipher.kind = value.get("type").and_then(Value::as_i64).unwrap_or(cipher.kind);
    cipher.name = text("name").unwrap_or_default();
    cipher.notes = text("notes");
    cipher.key = text("key");
    cipher.data = text("data").unwrap_or_else(|| "{}".into());
    cipher.fields = text("fields");
    cipher.password_history = text("passwordHistory");
    cipher.reprompt = value.get("reprompt").and_then(Value::as_i64).unwrap_or(0);
}

fn same_content(a: &Cipher, b: &Cipher) -> bool {
    a.kind == b.kind
        && a.name == b.name
        && a.notes == b.notes
        && a.key == b.key
        && a.data == b.data
        && a.fields == b.fields
        && a.password_history == b.password_history
        && a.reprompt == b.reprompt
}

/// The item as it is stored, before a change.
pub(crate) fn current(conn: &Connection, id: &str) -> rusqlite::Result<Option<Cipher>> {
    conn.prepare_cached(&format!("SELECT {CIPHER_COLUMNS} FROM ciphers WHERE id = ?1"))?
        .query_row([id], cipher_from)
        .optional()
}

/// After `after` replaced `before` (in the same transaction): the old state becomes a version
/// when its content changed, the oldest go when there are too many, and a reminder follows a new
/// password.
pub(crate) fn changed(
    tx: &Transaction<'_>,
    rule: VersionRule,
    before: Option<&Cipher>,
    after: &Cipher,
) -> rusqlite::Result<()> {
    let Some(before) = before else { return Ok(()) };
    crate::reminders::password_changed(tx, before, after)?;
    if rule.per_item == 0 || same_content(before, after) {
        return Ok(());
    }
    let content = content_of(before);
    tx.prepare_cached(&format!(
        "INSERT INTO cipher_versions ({VERSION_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
    ))?
    .execute(params![
        uuid::Uuid::new_v4().to_string(),
        before.id,
        before.organization_id.is_none().then_some(&before.user_id).filter(|user| !user.is_empty()),
        before.organization_id,
        content,
        before.revision,
        clock::now(),
        content.len() as i64,
    ])?;
    prune(tx, rule, Some(&before.id))
}

/// Versions past the rule go: of one item, or of all.
fn prune(tx: &Transaction<'_>, rule: VersionRule, cipher_id: Option<&str>) -> rusqlite::Result<()> {
    if rule.days > 0 {
        let oldest = clock::in_seconds(-i64::from(rule.days) * 86_400);
        match cipher_id {
            Some(id) => {
                tx.execute("DELETE FROM cipher_versions WHERE cipher_id = ?1 AND replaced < ?2", params![id, oldest])?
            }
            None => tx.execute("DELETE FROM cipher_versions WHERE replaced < ?1", [oldest])?,
        };
    }
    let over = "DELETE FROM cipher_versions WHERE id IN (SELECT id FROM (SELECT id, row_number() OVER \
                (PARTITION BY cipher_id ORDER BY replaced DESC, rowid DESC) AS n FROM cipher_versions";
    match cipher_id {
        Some(id) => tx.execute(&format!("{over} WHERE cipher_id = ?1) WHERE n > ?2)"), params![id, rule.per_item])?,
        None => tx.execute(&format!("{over}) WHERE n > ?1)"), [rule.per_item])?,
    };
    Ok(())
}

/// Why a version was not restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreRefusal {
    /// No such item or version.
    Missing,
    /// The item changed since the client last saw it.
    Changed,
}

impl Store {
    /// The rule versions are kept by from now on; the admin's settings.
    pub fn set_version_rule(&self, rule: VersionRule) {
        *self.version_rule.write() = rule;
    }

    pub fn version_rule(&self) -> VersionRule {
        *self.version_rule.read()
    }

    /// The versions of an item, newest first.
    pub async fn versions(&self, cipher_id: &str) -> Result<Vec<Version>> {
        let cipher_id = cipher_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {VERSION_COLUMNS} FROM cipher_versions WHERE cipher_id = ?1 ORDER BY replaced DESC, rowid DESC"
            ))?
            .query_map([cipher_id], version_from)?
            .collect()
        })
        .await
    }

    pub async fn version(&self, cipher_id: &str, id: &str) -> Result<Option<Version>> {
        let (cipher_id, id) = (cipher_id.to_string(), id.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {VERSION_COLUMNS} FROM cipher_versions WHERE cipher_id = ?1 AND id = ?2"
            ))?
            .query_row([cipher_id, id], version_from)
            .optional()
        })
        .await
    }

    /// Every version of the account's own items, for a key rotation. Hidden ones too: a
    /// rotation needs all of them, and is not allowed while travel mode is on.
    pub async fn personal_versions(&self, user_id: &str) -> Result<Vec<Version>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {VERSION_COLUMNS} FROM cipher_versions WHERE user_id = ?1 ORDER BY replaced DESC, rowid DESC"
            ))?
            .query_map([user_id], version_from)?
            .collect()
        })
        .await
    }

    /// One version of an item, or (`id` none) all of them, gone. How many went.
    pub async fn delete_versions(&self, cipher_id: &str, id: Option<String>) -> Result<usize> {
        let cipher_id = cipher_id.to_string();
        self.sqlite_write(move |tx| match id {
            Some(id) => tx.execute("DELETE FROM cipher_versions WHERE cipher_id = ?1 AND id = ?2", [cipher_id, id]),
            None => tx.execute("DELETE FROM cipher_versions WHERE cipher_id = ?1", [cipher_id]),
        })
        .await
    }

    /// Put a version's content back into its item; what the item holds now becomes a version
    /// itself. `revision` is what the client last saw of the item. The item as it is afterwards,
    /// and the users whose revision moved on (its owner, or the organisation's members).
    pub async fn restore_version(
        &self,
        cipher_id: &str,
        version_id: &str,
        revision: &str,
    ) -> Result<Result<(Cipher, Vec<String>), RestoreRefusal>> {
        let (cipher_id, version_id) = (cipher_id.to_string(), version_id.to_string());
        let known = clock::parse(revision);
        let rule = self.version_rule();
        let done = self
            .sqlite_write(move |tx| {
                let Some(before) = current(tx, &cipher_id)? else { return Ok(Err(RestoreRefusal::Missing)) };
                let Some(version) = tx
                    .query_row(
                        &format!("SELECT {VERSION_COLUMNS} FROM cipher_versions WHERE cipher_id = ?1 AND id = ?2"),
                        [&cipher_id, &version_id],
                        version_from,
                    )
                    .optional()?
                else {
                    return Ok(Err(RestoreRefusal::Missing));
                };
                let stored = clock::parse(&before.revision);
                let same = matches!((known, stored), (Some(known), Some(stored))
                    if (stored - known).abs() < time::Duration::milliseconds(1));
                if !same {
                    return Ok(Err(RestoreRefusal::Changed));
                }
                let mut after = before.clone();
                apply_content(&version.content, &mut after);
                after.revision = clock::now();
                write_cipher(tx, &after)?;
                changed(tx, rule, Some(&before), &after)?;
                let users = match &after.organization_id {
                    Some(org) => crate::organizations::bump_org(tx, org)?,
                    None => {
                        crate::accounts::bump_revision(tx, &after.user_id)?;
                        vec![after.user_id.clone()]
                    }
                };
                Ok(Ok((after, users)))
            })
            .await?;
        if let Ok((_, users)) = &done {
            for user in users {
                self.forget_session_of(user);
            }
        }
        Ok(done)
    }

    /// Versions past the rule, gone: what the daily sweep does after the admin changed it.
    pub async fn prune_versions(&self) -> Result<()> {
        let rule = self.version_rule();
        self.sqlite_write(move |tx| prune(tx, rule, None)).await
    }

    /// Bytes all versions take, for the admin portal.
    pub async fn version_bytes(&self) -> Result<i64> {
        self.sqlite_read(|conn| {
            conn.query_row("SELECT coalesce(sum(size), 0) FROM cipher_versions", [], |row| row.get(0))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::{new_user, store};
    use crate::vault::tests::cipher;

    #[tokio::test]
    async fn a_change_keeps_the_state_before_and_a_restore_brings_it_back() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let first = store.save_cipher(cipher(&user.id, "c", None)).await.unwrap().unwrap();
        assert!(store.versions("c").await.unwrap().is_empty(), "creating makes none");

        let mut moved = first.clone();
        moved.favorite = true;
        let moved = store.save_cipher(moved).await.unwrap().unwrap();
        assert!(store.versions("c").await.unwrap().is_empty(), "a star is not content");

        let mut second = moved.clone();
        second.name = "2.second|s|s".into();
        let second = store.save_cipher(second).await.unwrap().unwrap();
        let versions = store.versions("c").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].user_id.as_deref(), Some(user.id.as_str()));
        assert_eq!(versions[0].revision, moved.revision);
        assert_eq!(store.personal_versions(&user.id).await.unwrap().len(), 1);

        let refused = store.restore_version("c", &versions[0].id, &first.revision).await.unwrap();
        assert_eq!(refused.unwrap_err(), RestoreRefusal::Changed, "an old revision");
        let (restored, users) = store.restore_version("c", &versions[0].id, &second.revision).await.unwrap().unwrap();
        assert_eq!(restored.name, "2.name|name|name");
        assert!(restored.favorite, "the star stays");
        assert_eq!(users, std::slice::from_ref(&user.id));
        let versions = store.versions("c").await.unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(serde_json::from_str::<Value>(&versions[0].content).unwrap()["name"], "2.second|s|s");

        assert_eq!(store.delete_versions("c", Some(versions[1].id.clone())).await.unwrap(), 1);
        store.bulk(&user.id, vec!["c".into()], crate::Bulk::Delete).await.unwrap();
        assert!(store.versions("c").await.unwrap().is_empty(), "gone with the item");
    }

    #[tokio::test]
    async fn the_rule_says_how_many_and_how_long() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        store.set_version_rule(VersionRule { per_item: 2, days: 0 });
        let mut item = store.save_cipher(cipher(&user.id, "c", None)).await.unwrap().unwrap();
        for name in ["2.a|a|a", "2.b|b|b", "2.c|c|c", "2.d|d|d"] {
            item.name = name.into();
            item = store.save_cipher(item).await.unwrap().unwrap();
        }
        let names: Vec<Value> = store
            .versions("c")
            .await
            .unwrap()
            .iter()
            .map(|version| serde_json::from_str::<Value>(&version.content).unwrap()["name"].clone())
            .collect();
        assert_eq!(names, [json!("2.c|c|c"), json!("2.b|b|b")], "the newest two");
        store.set_version_rule(VersionRule { per_item: 0, days: 0 });
        item.name = "2.e|e|e".into();
        store.save_cipher(item).await.unwrap().unwrap();
        store.prune_versions().await.unwrap();
        assert!(store.versions("c").await.unwrap().is_empty(), "switched off");
    }

    #[test]
    fn content_goes_back_the_way_it_came() {
        let mut item = cipher("u", "c", None);
        item.fields = Some(r#"[{"name":"2.f|f|f","type":0}]"#.into());
        item.key = Some("2.k|k|k".into());
        let mut other = cipher("u", "c", Some("folder"));
        other.name = "2.x|x|x".into();
        apply_content(&content_of(&item), &mut other);
        assert!(same_content(&item, &other));
        assert_eq!(other.folder_id.as_deref(), Some("folder"));
    }
}
