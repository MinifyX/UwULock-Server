//! Vaults: folders and items, as the clients encrypted them.
//!
//! A sync reads a whole vault in two queries — one for the folders, one for the items — however
//! many items there are. Every change here also moves the account's revision on, in the same
//! step, which is how the clients learn that there is something new to fetch.

use crate::accounts::bump_revision;
use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, Transaction, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub id: String,
    pub user_id: String,
    /// Encrypted by the client.
    pub name: String,
    pub created: String,
    pub revision: String,
}

fn folder_from(row: &Row<'_>) -> rusqlite::Result<Folder> {
    Ok(Folder { id: row.get(0)?, user_id: row.get(1)?, name: row.get(2)?, created: row.get(3)?, revision: row.get(4)? })
}

/// An item. Every text in it the client encrypted, except `data`, `fields` and
/// `password_history`, which are JSON holding encrypted values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cipher {
    pub id: String,
    pub user_id: String,
    pub folder_id: Option<String>,
    /// 1 login, 2 note, 3 card, 4 identity, 5 SSH key.
    pub kind: i64,
    pub name: String,
    pub notes: Option<String>,
    /// The item's own key, wrapped under the user key.
    pub key: Option<String>,
    /// JSON: the object of its type (`login`, `card`, …) as the client sent it.
    pub data: String,
    /// JSON array, or none.
    pub fields: Option<String>,
    /// JSON array, or none.
    pub password_history: Option<String>,
    pub favorite: bool,
    pub reprompt: i64,
    pub created: String,
    pub revision: String,
    /// In the trash since.
    pub deleted: Option<String>,
    pub archived: Option<String>,
}

const CIPHER_COLUMNS: &str = "id, user_id, folder_id, type, name, notes, key, data, fields, password_history, favorite, \
     reprompt, created, revision, deleted, archived";

fn cipher_from(row: &Row<'_>) -> rusqlite::Result<Cipher> {
    Ok(Cipher {
        id: row.get(0)?,
        user_id: row.get(1)?,
        folder_id: row.get(2)?,
        kind: row.get(3)?,
        name: row.get(4)?,
        notes: row.get(5)?,
        key: row.get(6)?,
        data: row.get(7)?,
        fields: row.get(8)?,
        password_history: row.get(9)?,
        favorite: row.get(10)?,
        reprompt: row.get(11)?,
        created: row.get(12)?,
        revision: row.get(13)?,
        deleted: row.get(14)?,
        archived: row.get(15)?,
    })
}

fn write_cipher(tx: &Transaction<'_>, cipher: &Cipher) -> rusqlite::Result<()> {
    tx.prepare_cached(&format!(
        "INSERT INTO ciphers ({CIPHER_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16) \
         ON CONFLICT (id) DO UPDATE SET folder_id = excluded.folder_id, type = excluded.type, name = excluded.name, \
         notes = excluded.notes, key = excluded.key, data = excluded.data, fields = excluded.fields, \
         password_history = excluded.password_history, favorite = excluded.favorite, reprompt = excluded.reprompt, \
         revision = excluded.revision, deleted = excluded.deleted, archived = excluded.archived \
         WHERE ciphers.user_id = excluded.user_id"
    ))?
    .execute(params![
        cipher.id,
        cipher.user_id,
        cipher.folder_id,
        cipher.kind,
        cipher.name,
        cipher.notes,
        cipher.key,
        cipher.data,
        cipher.fields,
        cipher.password_history,
        cipher.favorite,
        cipher.reprompt,
        cipher.created,
        cipher.revision,
        cipher.deleted,
        cipher.archived,
    ])?;
    Ok(())
}

/// A whole vault, as a sync hands it out.
#[derive(Debug, Default)]
pub struct VaultContents {
    pub folders: Vec<Folder>,
    pub ciphers: Vec<Cipher>,
}

/// What a change to several items at once does to each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bulk {
    /// Into the trash.
    Trash,
    /// Out of the trash.
    Restore,
    /// Gone for good.
    Delete,
    Archive,
    Unarchive,
}

impl Store {
    /// Everything of one user: two queries, whatever the size.
    pub async fn vault(&self, user_id: &str) -> Result<VaultContents> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            let folders = conn
                .prepare_cached("SELECT id, user_id, name, created, revision FROM folders WHERE user_id = ?1")?
                .query_map([&user_id], folder_from)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let ciphers = conn
                .prepare_cached(&format!("SELECT {CIPHER_COLUMNS} FROM ciphers WHERE user_id = ?1"))?
                .query_map([&user_id], cipher_from)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(VaultContents { folders, ciphers })
        })
        .await
    }

    // ── Folders ────────────────────────────────────────────

    pub async fn folders(&self, user_id: &str) -> Result<Vec<Folder>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached("SELECT id, user_id, name, created, revision FROM folders WHERE user_id = ?1")?
                .query_map([user_id], folder_from)?
                .collect()
        })
        .await
    }

    /// One of the user's folders; nothing for somebody else's.
    pub async fn folder(&self, user_id: &str, id: &str) -> Result<Option<Folder>> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT id, user_id, name, created, revision FROM folders WHERE id = ?1 AND user_id = ?2",
            )?
            .query_row([id, user_id], folder_from)
            .optional()
        })
        .await
    }

    /// A new folder, or a folder with a new name. Nothing when `id` is somebody else's.
    pub async fn save_folder(&self, user_id: &str, id: Option<String>, name: String) -> Result<Option<Folder>> {
        let owned = user_id.to_string();
        let folder = self
            .sqlite_write(move |tx| {
                let now = clock::now();
                let id = match id {
                    Some(id) => {
                        let changed = tx.execute(
                            "UPDATE folders SET name = ?3, revision = ?4 WHERE id = ?1 AND user_id = ?2",
                            params![id, owned, name, now],
                        )?;
                        if changed == 0 {
                            return Ok(None);
                        }
                        id
                    }
                    None => {
                        let id = uuid::Uuid::new_v4().to_string();
                        tx.execute(
                            "INSERT INTO folders (id, user_id, name, created, revision) VALUES (?1, ?2, ?3, ?4, ?4)",
                            params![id, owned, name, now],
                        )?;
                        id
                    }
                };
                bump_revision(tx, &owned)?;
                tx.query_row(
                    "SELECT id, user_id, name, created, revision FROM folders WHERE id = ?1",
                    [id],
                    folder_from,
                )
                .optional()
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(folder)
    }

    /// The folder goes; its items stay, in no folder.
    pub async fn delete_folder(&self, user_id: &str, id: &str) -> Result<bool> {
        let (owned, id) = (user_id.to_string(), id.to_string());
        let deleted = self
            .sqlite_write(move |tx| {
                let now = clock::now();
                tx.execute(
                    "UPDATE ciphers SET folder_id = NULL, revision = ?3 WHERE folder_id = ?1 AND user_id = ?2",
                    params![id, owned, now],
                )?;
                let deleted = tx.execute("DELETE FROM folders WHERE id = ?1 AND user_id = ?2", [&id, &owned])? > 0;
                if deleted {
                    bump_revision(tx, &owned)?;
                }
                Ok(deleted)
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(deleted)
    }

    // ── Items ──────────────────────────────────────────────

    /// One of the user's items; nothing for somebody else's.
    pub async fn cipher(&self, user_id: &str, id: &str) -> Result<Option<Cipher>> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {CIPHER_COLUMNS} FROM ciphers WHERE id = ?1 AND user_id = ?2"))?
                .query_row([id, user_id], cipher_from)
                .optional()
        })
        .await
    }

    pub async fn ciphers(&self, user_id: &str) -> Result<Vec<Cipher>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {CIPHER_COLUMNS} FROM ciphers WHERE user_id = ?1"))?
                .query_map([user_id], cipher_from)?
                .collect()
        })
        .await
    }

    /// Write an item as it is now, new or changed. Its revision is set to now, and handed back.
    /// Nothing when an item of that id belongs to somebody else, or its folder does.
    pub async fn save_cipher(&self, mut cipher: Cipher) -> Result<Option<Cipher>> {
        let user_id = cipher.user_id.clone();
        let saved = self
            .sqlite_write(move |tx| {
                if !folder_is_theirs(tx, &cipher.user_id, cipher.folder_id.as_deref())? {
                    return Ok(None);
                }
                let owner: Option<String> = tx
                    .query_row("SELECT user_id FROM ciphers WHERE id = ?1", [&cipher.id], |row| row.get(0))
                    .optional()?;
                if owner.is_some_and(|owner| owner != cipher.user_id) {
                    return Ok(None);
                }
                cipher.revision = clock::now();
                write_cipher(tx, &cipher)?;
                bump_revision(tx, &cipher.user_id)?;
                Ok(Some(cipher))
            })
            .await?;
        self.forget_session_of(&user_id);
        Ok(saved)
    }

    /// Several new folders and items at once, the way an import brings them: all of them, or
    /// none if one does not fit.
    pub async fn import(&self, user_id: &str, folders: Vec<Folder>, ciphers: Vec<Cipher>) -> Result<()> {
        let owned = user_id.to_string();
        self.sqlite_write(move |tx| {
            for folder in &folders {
                tx.prepare_cached(
                    "INSERT INTO folders (id, user_id, name, created, revision) VALUES (?1, ?2, ?3, ?4, ?5)",
                )?
                .execute(params![folder.id, owned, folder.name, folder.created, folder.revision])?;
            }
            for cipher in &ciphers {
                let mut cipher = cipher.clone();
                cipher.user_id = owned.clone();
                write_cipher(tx, &cipher)?;
            }
            bump_revision(tx, &owned)
        })
        .await?;
        self.forget_session_of(user_id);
        Ok(())
    }

    /// Do `what` to those of `ids` that are the user's. Returns the ids it was done to.
    pub async fn bulk(&self, user_id: &str, ids: Vec<String>, what: Bulk) -> Result<Vec<String>> {
        let owned = user_id.to_string();
        let done = self
            .sqlite_write(move |tx| {
                let now = clock::now();
                let sql = match what {
                    Bulk::Trash => "UPDATE ciphers SET deleted = ?3, revision = ?3 WHERE id = ?1 AND user_id = ?2",
                    Bulk::Restore => "UPDATE ciphers SET deleted = NULL, revision = ?3 WHERE id = ?1 AND user_id = ?2",
                    Bulk::Archive => "UPDATE ciphers SET archived = ?3, revision = ?3 WHERE id = ?1 AND user_id = ?2",
                    Bulk::Unarchive => {
                        "UPDATE ciphers SET archived = NULL, revision = ?3 WHERE id = ?1 AND user_id = ?2"
                    }
                    Bulk::Delete => "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2 AND ?3 = ?3",
                };
                let mut statement = tx.prepare_cached(sql)?;
                let mut done = Vec::with_capacity(ids.len());
                for id in ids {
                    if statement.execute(params![id, owned, now])? > 0 {
                        done.push(id);
                    }
                }
                drop(statement);
                if !done.is_empty() {
                    bump_revision(tx, &owned)?;
                }
                Ok(done)
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(done)
    }

    /// Move those of `ids` that are the user's into `folder_id`, or out of any folder. Nothing
    /// when the folder is not theirs.
    pub async fn move_ciphers(
        &self,
        user_id: &str,
        ids: Vec<String>,
        folder_id: Option<String>,
    ) -> Result<Option<usize>> {
        let owned = user_id.to_string();
        let moved = self
            .sqlite_write(move |tx| {
                if !folder_is_theirs(tx, &owned, folder_id.as_deref())? {
                    return Ok(None);
                }
                let now = clock::now();
                let mut statement = tx.prepare_cached(
                    "UPDATE ciphers SET folder_id = ?3, revision = ?4 WHERE id = ?1 AND user_id = ?2",
                )?;
                let mut moved = 0;
                for id in ids {
                    moved += statement.execute(params![id, owned, folder_id, now])?;
                }
                drop(statement);
                bump_revision(tx, &owned)?;
                Ok(Some(moved))
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(moved)
    }

    /// Empty the vault: every item and every folder.
    pub async fn purge_vault(&self, user_id: &str) -> Result<()> {
        let owned = user_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM ciphers WHERE user_id = ?1", [&owned])?;
            tx.execute("DELETE FROM folders WHERE user_id = ?1", [&owned])?;
            bump_revision(tx, &owned)
        })
        .await?;
        self.forget_session_of(user_id);
        Ok(())
    }

    /// New keys for a whole account at once, as a key rotation brings them: the user's wrapped
    /// user key and private key, every folder name and every item. Refused (`false`) unless the
    /// folders and items given are exactly the ones the user has — a rotation that missed one
    /// would leave it under a key nobody has any more.
    pub async fn rotate_keys(
        &self,
        user: crate::User,
        folders: Vec<(String, String)>,
        ciphers: Vec<Cipher>,
    ) -> Result<bool> {
        let user_id = user.id.clone();
        let done = self
            .sqlite_write(move |tx| {
                let have = |sql: &str| -> rusqlite::Result<Vec<String>> {
                    let mut ids = tx
                        .prepare(sql)?
                        .query_map([&user.id], |row| row.get(0))?
                        .collect::<rusqlite::Result<Vec<String>>>()?;
                    ids.sort();
                    Ok(ids)
                };
                let mut given: Vec<String> = folders.iter().map(|(id, _)| id.clone()).collect();
                given.sort();
                if have("SELECT id FROM folders WHERE user_id = ?1")? != given {
                    return Ok(false);
                }
                // Every item stays in one of the user's own folders, or in none.
                if ciphers
                    .iter()
                    .any(|cipher| cipher.folder_id.as_ref().is_some_and(|id| given.binary_search(id).is_err()))
                {
                    return Ok(false);
                }
                let mut given: Vec<String> = ciphers.iter().map(|cipher| cipher.id.clone()).collect();
                given.sort();
                if have("SELECT id FROM ciphers WHERE user_id = ?1")? != given {
                    return Ok(false);
                }
                let now = clock::now();
                for (id, name) in &folders {
                    tx.execute(
                        "UPDATE folders SET name = ?3, revision = ?4 WHERE id = ?1 AND user_id = ?2",
                        params![id, user.id, name, now],
                    )?;
                }
                for cipher in &ciphers {
                    let mut cipher = cipher.clone();
                    cipher.user_id = user.id.clone();
                    cipher.revision = now.clone();
                    write_cipher(tx, &cipher)?;
                }
                let mut user = user;
                // A new key has a new name, which the clients will tell.
                user.user_key_id = None;
                user.updated = now.clone();
                user.revision = now;
                crate::accounts::save_user_in(tx, &user)?;
                tx.execute(
                    "UPDATE devices SET refresh_hash = NULL, refresh_expires = NULL, remember_hash = NULL, \
                     remember_expires = NULL WHERE user_id = ?1",
                    [&user.id],
                )?;
                Ok(true)
            })
            .await?;
        self.forget_session_of(&user_id);
        Ok(done)
    }
}

fn folder_is_theirs(tx: &Transaction<'_>, user_id: &str, folder_id: Option<&str>) -> rusqlite::Result<bool> {
    match folder_id {
        None => Ok(true),
        Some(id) => {
            tx.query_row("SELECT EXISTS (SELECT 1 FROM folders WHERE id = ?1 AND user_id = ?2)", [id, user_id], |row| {
                row.get(0)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::{new_user, store};

    fn cipher(user_id: &str, id: &str, folder: Option<&str>) -> Cipher {
        Cipher {
            id: id.into(),
            user_id: user_id.into(),
            folder_id: folder.map(Into::into),
            kind: 1,
            name: "2.name|name|name".into(),
            notes: None,
            key: None,
            data: r#"{"username":"2.u|u|u","uris":[]}"#.into(),
            fields: None,
            password_history: None,
            favorite: false,
            reprompt: 0,
            created: clock::now(),
            revision: String::new(),
            deleted: None,
            archived: None,
        }
    }

    #[tokio::test]
    async fn every_change_moves_the_revision_on() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let revision = |store: Store, id: String| async move {
            store.session_user(&id).await.unwrap().unwrap().user.revision.clone()
        };

        let before = revision(store.clone(), user.id.clone()).await;
        let folder = store.save_folder(&user.id, None, "2.f|f|f".into()).await.unwrap().unwrap();
        let after_folder = revision(store.clone(), user.id.clone()).await;
        assert!(after_folder > before);

        let saved = store.save_cipher(cipher(&user.id, "c1", Some(&folder.id))).await.unwrap().unwrap();
        assert!(!saved.revision.is_empty());
        let after_cipher = revision(store.clone(), user.id.clone()).await;
        assert!(after_cipher > after_folder);

        let vault = store.vault(&user.id).await.unwrap();
        assert_eq!((vault.folders.len(), vault.ciphers.len()), (1, 1));

        store.delete_folder(&user.id, &folder.id).await.unwrap();
        let left = store.cipher(&user.id, "c1").await.unwrap().unwrap();
        assert_eq!(left.folder_id, None, "the item stays, in no folder");
        assert!(revision(store.clone(), user.id.clone()).await > after_cipher);
    }

    #[tokio::test]
    async fn nobody_touches_somebody_else_s_vault() {
        let (store, _dir) = store();
        let nyu = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let other = store.create_user(new_user("other@example.com")).await.unwrap();
        let folder = store.save_folder(&nyu.id, None, "2.f|f|f".into()).await.unwrap().unwrap();
        store.save_cipher(cipher(&nyu.id, "c1", None)).await.unwrap().unwrap();

        assert!(store.save_cipher(cipher(&other.id, "c1", None)).await.unwrap().is_none(), "their item's id");
        assert!(store.save_cipher(cipher(&other.id, "c2", Some(&folder.id))).await.unwrap().is_none(), "their folder");
        assert!(store.save_folder(&other.id, Some(folder.id.clone()), "x".into()).await.unwrap().is_none());
        assert!(!store.delete_folder(&other.id, &folder.id).await.unwrap());
        assert!(store.bulk(&other.id, vec!["c1".into()], Bulk::Delete).await.unwrap().is_empty());
        assert!(store.cipher(&other.id, "c1").await.unwrap().is_none());
        assert!(store.move_ciphers(&other.id, vec!["c1".into()], Some(folder.id.clone())).await.unwrap().is_none());
        assert_eq!(store.cipher(&nyu.id, "c1").await.unwrap().unwrap().name, "2.name|name|name");
    }

    #[tokio::test]
    async fn trash_restore_archive_and_delete() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        for id in ["a", "b"] {
            store.save_cipher(cipher(&user.id, id, None)).await.unwrap();
        }
        let ids = vec!["a".to_string(), "b".to_string(), "nope".to_string()];
        assert_eq!(store.bulk(&user.id, ids.clone(), Bulk::Trash).await.unwrap(), ["a", "b"]);
        assert!(store.cipher(&user.id, "a").await.unwrap().unwrap().deleted.is_some());
        store.bulk(&user.id, vec!["a".into()], Bulk::Restore).await.unwrap();
        assert!(store.cipher(&user.id, "a").await.unwrap().unwrap().deleted.is_none());
        store.bulk(&user.id, vec!["a".into()], Bulk::Archive).await.unwrap();
        assert!(store.cipher(&user.id, "a").await.unwrap().unwrap().archived.is_some());
        store.bulk(&user.id, vec!["b".into()], Bulk::Delete).await.unwrap();
        assert!(store.cipher(&user.id, "b").await.unwrap().is_none());
        store.purge_vault(&user.id).await.unwrap();
        assert!(store.ciphers(&user.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_rotation_has_to_bring_every_item() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let folder = store.save_folder(&user.id, None, "old".into()).await.unwrap().unwrap();
        store.save_cipher(cipher(&user.id, "a", None)).await.unwrap();
        store.save_cipher(cipher(&user.id, "b", None)).await.unwrap();

        let mut rotated = user.clone();
        rotated.user_key = "new key".into();
        let mut a = cipher(&user.id, "a", None);
        a.name = "new".into();
        assert!(
            !store
                .rotate_keys(rotated.clone(), vec![(folder.id.clone(), "new".into())], vec![a.clone()])
                .await
                .unwrap()
        );
        assert_eq!(store.user(&user.id).await.unwrap().unwrap().user_key, user.user_key, "nothing changed");

        let mut b = cipher(&user.id, "b", None);
        b.name = "new".into();
        assert!(store.rotate_keys(rotated, vec![(folder.id.clone(), "new".into())], vec![a, b]).await.unwrap());
        assert_eq!(store.user(&user.id).await.unwrap().unwrap().user_key, "new key");
        assert!(store.ciphers(&user.id).await.unwrap().iter().all(|cipher| cipher.name == "new"));
        assert_eq!(store.folder(&user.id, &folder.id).await.unwrap().unwrap().name, "new");
    }

    #[tokio::test]
    async fn deleting_a_user_takes_the_vault_along() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let folder = store.save_folder(&user.id, None, "f".into()).await.unwrap().unwrap();
        store.save_cipher(cipher(&user.id, "a", Some(&folder.id))).await.unwrap();
        assert!(store.delete_user(&user.id).await.unwrap());
        assert!(store.session_user(&user.id).await.unwrap().is_none());
        assert_eq!(store.stats().await.unwrap(), crate::Stats::default());
    }
}
