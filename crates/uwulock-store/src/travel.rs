//! Travel mode (docs/uwu-api.md §9): folders marked "hide while travelling", and, while the mode
//! is on, their items left out of everything the account asks for — the sync, single items, the
//! attachments, versions, icons and reminders. The server knows the folders only by their ids.
//!
//! Every read of an account's items goes through [`hidden_folders`] in the same query step, so a
//! hidden item cannot slip out through a path that forgot to ask.

use crate::accounts::bump_revision;
use crate::{Result, Store, clock};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashSet;

/// The folders whose items `user_id` does not see right now: the marked ones while travel mode
/// is on, none otherwise.
pub(crate) fn hidden_folders(conn: &Connection, user_id: &str) -> rusqlite::Result<HashSet<String>> {
    conn.prepare_cached(
        "SELECT f.id FROM folders f JOIN travel t ON t.user_id = f.user_id WHERE f.user_id = ?1 AND f.travel",
    )?
    .query_map([user_id], |row| row.get(0))?
    .collect()
}

/// Whether the item `cipher_id` is hidden from `user_id`: their own in a hidden folder, or an
/// organisation's they filed into one.
pub(crate) fn is_hidden(conn: &Connection, user_id: &str, cipher_id: &str) -> rusqlite::Result<bool> {
    conn.prepare_cached(
        "SELECT EXISTS (SELECT 1 FROM travel t JOIN folders f ON f.user_id = t.user_id AND f.travel \
         WHERE t.user_id = ?1 AND ( \
           f.id = (SELECT folder_id FROM ciphers WHERE id = ?2 AND user_id = ?1) \
           OR f.id = (SELECT folder_id FROM cipher_preferences WHERE cipher_id = ?2 AND user_id = ?1)))",
    )?
    .query_row([user_id, cipher_id], |row| row.get(0))
}

/// Travel mode as an account sees it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Travel {
    /// When it was switched on; none while it is off.
    pub enabled: Option<String>,
    pub folder_ids: Vec<String>,
    /// Items hidden right now.
    pub hidden: i64,
}

/// Why the marked folders were not changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TravelRefusal {
    /// One of them is not the account's.
    NotTheirs,
    /// Travel mode is on, and one would stop being hidden.
    Active,
}

impl Store {
    pub async fn travel(&self, user_id: &str) -> Result<Travel> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            let enabled: Option<String> = conn
                .query_row("SELECT enabled FROM travel WHERE user_id = ?1", [&user_id], |row| row.get(0))
                .optional()?;
            let folder_ids: Vec<String> = conn
                .prepare_cached("SELECT id FROM folders WHERE user_id = ?1 AND travel ORDER BY id")?
                .query_map([&user_id], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let hidden = if enabled.is_some() {
                conn.query_row(
                    "SELECT (SELECT count(*) FROM ciphers c JOIN folders f ON f.id = c.folder_id \
                       WHERE c.user_id = ?1 AND f.travel) \
                     + (SELECT count(*) FROM cipher_preferences p JOIN folders f ON f.id = p.folder_id \
                       WHERE p.user_id = ?1 AND f.travel)",
                    [&user_id],
                    |row| row.get(0),
                )?
            } else {
                0
            };
            Ok(Travel { enabled, folder_ids, hidden })
        })
        .await
    }

    /// Whether travel mode is on for the account.
    pub async fn travelling(&self, user_id: &str) -> Result<bool> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT EXISTS (SELECT 1 FROM travel WHERE user_id = ?1)", [user_id], |row| row.get(0))
        })
        .await
    }

    /// The folders marked for travel mode, the whole set. While it is on, folders may be added
    /// but none taken away. `Ok(Ok(true))` when the set grew while it is on: the clients have
    /// to drop what is hidden now.
    pub async fn set_travel_folders(
        &self,
        user_id: &str,
        folder_ids: Vec<String>,
    ) -> Result<Result<bool, TravelRefusal>> {
        let owned = user_id.to_string();
        let changed = self
            .sqlite_write(move |tx| {
                let wanted: HashSet<String> = folder_ids.into_iter().collect();
                let theirs: HashSet<String> = tx
                    .prepare_cached("SELECT id FROM folders WHERE user_id = ?1")?
                    .query_map([&owned], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                if !wanted.is_subset(&theirs) {
                    return Ok(Err(TravelRefusal::NotTheirs));
                }
                let marked: HashSet<String> = tx
                    .prepare_cached("SELECT id FROM folders WHERE user_id = ?1 AND travel")?
                    .query_map([&owned], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                let on: bool =
                    tx.query_row("SELECT EXISTS (SELECT 1 FROM travel WHERE user_id = ?1)", [&owned], |row| {
                        row.get(0)
                    })?;
                if on && !marked.is_subset(&wanted) {
                    return Ok(Err(TravelRefusal::Active));
                }
                for id in &theirs {
                    tx.execute(
                        "UPDATE folders SET travel = ?3 WHERE id = ?1 AND user_id = ?2",
                        params![id, owned, wanted.contains(id)],
                    )?;
                }
                let grew = on && wanted != marked;
                if grew {
                    bump_revision(tx, &owned)?;
                }
                Ok(Ok(grew))
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(changed)
    }

    /// Switch travel mode on or off. False when it already was.
    pub async fn set_travelling(&self, user_id: &str, on: bool) -> Result<bool> {
        let owned = user_id.to_string();
        let changed = self
            .sqlite_write(move |tx| {
                let changed = if on {
                    tx.execute(
                        "INSERT INTO travel (user_id, enabled) VALUES (?1, ?2) ON CONFLICT (user_id) DO NOTHING",
                        params![owned, clock::now()],
                    )?
                } else {
                    tx.execute("DELETE FROM travel WHERE user_id = ?1", [&owned])?
                } > 0;
                if changed {
                    bump_revision(tx, &owned)?;
                }
                Ok(changed)
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(changed)
    }

    /// Whether travel mode hides the item from `user_id` right now: for a download link made for
    /// a member of the item's organisation.
    pub async fn hidden_from(&self, user_id: &str, cipher_id: &str) -> Result<bool> {
        let (user_id, cipher_id) = (user_id.to_string(), cipher_id.to_string());
        self.sqlite_read(move |conn| is_hidden(conn, &user_id, &cipher_id)).await
    }

    /// Whether the item is hidden from its owner by travel mode, for a download that comes with
    /// a link instead of a session. An organisation's item is nobody's alone: never.
    pub async fn hidden_from_owner(&self, cipher_id: &str) -> Result<bool> {
        let cipher_id = cipher_id.to_string();
        self.sqlite_read(move |conn| {
            let owner: Option<Option<String>> = conn
                .query_row("SELECT user_id FROM ciphers WHERE id = ?1", [&cipher_id], |row| row.get(0))
                .optional()?;
            match owner.flatten() {
                Some(owner) => is_hidden(conn, &owner, &cipher_id),
                None => Ok(false),
            }
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
    async fn marked_folders_hide_their_items_only_while_travelling() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let other = store.create_user(new_user("other@example.com")).await.unwrap();
        let secret = store.save_folder(&user.id, None, "2.s|s|s".into()).await.unwrap().unwrap();
        let open = store.save_folder(&user.id, None, "2.o|o|o".into()).await.unwrap().unwrap();
        store.save_cipher(cipher(&user.id, "hidden", Some(&secret.id))).await.unwrap().unwrap();
        store.save_cipher(cipher(&user.id, "shown", Some(&open.id))).await.unwrap().unwrap();

        let refused = store.set_travel_folders(&other.id, vec![secret.id.clone()]).await.unwrap();
        assert_eq!(refused, Err(TravelRefusal::NotTheirs), "somebody else's folder");
        assert_eq!(store.set_travel_folders(&user.id, vec![secret.id.clone()]).await.unwrap(), Ok(false));
        assert_eq!(store.vault(&user.id).await.unwrap().ciphers.len(), 2, "marked, but not travelling");

        assert!(store.set_travelling(&user.id, true).await.unwrap());
        assert!(!store.set_travelling(&user.id, true).await.unwrap(), "on already");
        let vault = store.vault(&user.id).await.unwrap();
        assert_eq!(vault.ciphers.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), ["shown"]);
        assert_eq!(vault.folders.len(), 1, "the folder is hidden too");
        assert!(store.cipher(&user.id, "hidden").await.unwrap().is_none());
        assert!(store.folder(&user.id, &secret.id).await.unwrap().is_none());
        assert!(store.hidden_from_owner("hidden").await.unwrap());
        assert!(store.bulk(&user.id, vec!["hidden".into()], crate::Bulk::Delete).await.unwrap().is_empty());
        assert!(!store.delete_folder(&user.id, &secret.id).await.unwrap(), "a hidden folder stays");
        assert_eq!(store.travel(&user.id).await.unwrap().hidden, 1);

        let removed = store.set_travel_folders(&user.id, Vec::new()).await.unwrap();
        assert_eq!(removed, Err(TravelRefusal::Active), "nothing comes back while travelling");
        let grew = store.set_travel_folders(&user.id, vec![secret.id.clone(), open.id.clone()]).await.unwrap();
        assert_eq!(grew, Ok(true));
        assert!(store.vault(&user.id).await.unwrap().ciphers.is_empty());

        assert!(store.set_travelling(&user.id, false).await.unwrap());
        assert_eq!(store.vault(&user.id).await.unwrap().ciphers.len(), 2);
        assert_eq!(store.travel(&user.id).await.unwrap().hidden, 0);
    }
}
