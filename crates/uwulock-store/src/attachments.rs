//! Files on items. The file itself is on disk, encrypted by the client; here is what it is
//! called (encrypted too), its key (wrapped under the item's key), how large it is, and whether
//! it arrived. An attachment is announced before its upload, so one that never arrived is
//! left out of what the clients get.

use crate::accounts::bump_revision;
use crate::vault::{CIPHER_COLUMNS, cipher_from};
use crate::{Cipher, Result, Store, clock};
use rusqlite::{OptionalExtension, Row, Transaction, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub id: String,
    pub cipher_id: String,
    /// Encrypted by the client.
    pub file_name: String,
    /// The file's key, wrapped under the item's key (or the user key).
    pub key: Option<String>,
    /// Bytes of the encrypted file.
    pub size: i64,
    pub uploaded: bool,
    pub created: String,
}

const COLUMNS: &str = "id, cipher_id, file_name, key, size, uploaded, created";

fn attachment_from(row: &Row<'_>) -> rusqlite::Result<Attachment> {
    Ok(Attachment {
        id: row.get(0)?,
        cipher_id: row.get(1)?,
        file_name: row.get(2)?,
        key: row.get(3)?,
        size: row.get(4)?,
        uploaded: row.get(5)?,
        created: row.get(6)?,
    })
}

/// A new name and key for an attachment, the way a changed item or a key rotation brings them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentKey {
    pub id: String,
    pub file_name: String,
    pub key: String,
}

/// The item `cipher_id` of `user_id`, with its revision moved on: what a change to its
/// attachments does. Nothing when it is not theirs.
fn touch_cipher(tx: &Transaction<'_>, user_id: &str, cipher_id: &str) -> rusqlite::Result<Option<Cipher>> {
    let now = clock::now();
    if tx
        .execute("UPDATE ciphers SET revision = ?3 WHERE id = ?1 AND user_id = ?2", params![cipher_id, user_id, now])?
        == 0
    {
        return Ok(None);
    }
    bump_revision(tx, user_id)?;
    tx.prepare_cached(&format!("SELECT {CIPHER_COLUMNS} FROM ciphers WHERE id = ?1"))?
        .query_row([cipher_id], cipher_from)
        .optional()
}

/// Write new names and keys for those of `keys` that are attachments of `cipher_id`. The rest
/// are left alone: a client may know of an attachment another one deleted.
pub(crate) fn set_keys(tx: &Transaction<'_>, cipher_id: &str, keys: &[AttachmentKey]) -> rusqlite::Result<()> {
    let mut statement =
        tx.prepare_cached("UPDATE attachments SET file_name = ?3, key = ?4 WHERE id = ?1 AND cipher_id = ?2")?;
    for key in keys {
        statement.execute(params![key.id, cipher_id, key.file_name, key.key])?;
    }
    Ok(())
}

impl Store {
    /// Every attachment that arrived, on any of the user's items: one query, for a sync.
    pub async fn attachments_of_user(&self, user_id: &str) -> Result<Vec<Attachment>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            let columns = COLUMNS.split(", ").map(|c| format!("a.{c}")).collect::<Vec<_>>().join(", ");
            conn.prepare_cached(&format!(
                "SELECT {columns} FROM attachments a JOIN ciphers c ON c.id = a.cipher_id \
                 WHERE c.user_id = ?1 AND a.uploaded ORDER BY a.created"
            ))?
            .query_map([user_id], attachment_from)?
            .collect()
        })
        .await
    }

    /// The attachments of one item that arrived.
    pub async fn attachments(&self, cipher_id: &str) -> Result<Vec<Attachment>> {
        let cipher_id = cipher_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM attachments WHERE cipher_id = ?1 AND uploaded ORDER BY created"
            ))?
            .query_map([cipher_id], attachment_from)?
            .collect()
        })
        .await
    }

    /// One attachment of one item, arrived or not.
    pub async fn attachment(&self, cipher_id: &str, id: &str) -> Result<Option<Attachment>> {
        let (cipher_id, id) = (cipher_id.to_string(), id.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {COLUMNS} FROM attachments WHERE id = ?1 AND cipher_id = ?2"))?
                .query_row([id, cipher_id], attachment_from)
                .optional()
        })
        .await
    }

    /// A new attachment on one of the user's items, before (or, `uploaded`, after) its file
    /// arrived. The item as it is afterwards; nothing when it is not theirs.
    pub async fn add_attachment(&self, user_id: &str, attachment: Attachment) -> Result<Option<Cipher>> {
        let owned = user_id.to_string();
        let cipher = self
            .sqlite_write(move |tx| {
                let Some(cipher) = touch_cipher(tx, &owned, &attachment.cipher_id)? else { return Ok(None) };
                tx.execute(
                    &format!("INSERT INTO attachments ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"),
                    params![
                        attachment.id,
                        attachment.cipher_id,
                        attachment.file_name,
                        attachment.key,
                        attachment.size,
                        attachment.uploaded,
                        attachment.created,
                    ],
                )?;
                Ok(Some(cipher))
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(cipher)
    }

    /// The file of an announced attachment arrived, with `size` bytes.
    pub async fn attachment_uploaded(&self, user_id: &str, cipher_id: &str, id: &str, size: i64) -> Result<bool> {
        let (owned, cipher_id, id) = (user_id.to_string(), cipher_id.to_string(), id.to_string());
        let done = self
            .sqlite_write(move |tx| {
                if touch_cipher(tx, &owned, &cipher_id)?.is_none() {
                    return Ok(false);
                }
                Ok(tx.execute(
                    "UPDATE attachments SET uploaded = 1, size = ?3 WHERE id = ?1 AND cipher_id = ?2",
                    params![id, cipher_id, size],
                )? > 0)
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(done)
    }

    /// The attachment goes; its file is swept away later. The item as it is afterwards; nothing
    /// when the item is not the user's or has no such attachment.
    pub async fn delete_attachment(&self, user_id: &str, cipher_id: &str, id: &str) -> Result<Option<Cipher>> {
        let (owned, cipher_id, id) = (user_id.to_string(), cipher_id.to_string(), id.to_string());
        let cipher = self
            .sqlite_write(move |tx| {
                let theirs: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM ciphers WHERE id = ?1 AND user_id = ?2)",
                    [&cipher_id, &owned],
                    |row| row.get(0),
                )?;
                if !theirs
                    || tx.execute("DELETE FROM attachments WHERE id = ?1 AND cipher_id = ?2", [&id, &cipher_id])? == 0
                {
                    return Ok(None);
                }
                touch_cipher(tx, &owned, &cipher_id)
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(cipher)
    }

    /// Bytes in the user's attachments, for the admin portal.
    pub async fn attachment_bytes(&self, user_id: &str) -> Result<i64> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT coalesce(sum(a.size), 0) FROM attachments a JOIN ciphers c ON c.id = a.cipher_id \
                 WHERE c.user_id = ?1",
                [user_id],
                |row| row.get(0),
            )
        })
        .await
    }

    /// Whether a file on disk still belongs to something: an attachment of `cipher_id` called
    /// `id`. The sweep deletes the files nothing claims.
    pub async fn attachment_exists(&self, cipher_id: &str, id: &str) -> Result<bool> {
        let (cipher_id, id) = (cipher_id.to_string(), id.to_string());
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM attachments WHERE id = ?1 AND cipher_id = ?2)",
                [id, cipher_id],
                |row| row.get(0),
            )
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::{new_user, store};
    use crate::vault::tests::cipher;

    fn attachment(cipher_id: &str, id: &str) -> Attachment {
        Attachment {
            id: id.into(),
            cipher_id: cipher_id.into(),
            file_name: "2.name|name|name".into(),
            key: Some("2.key|key|key".into()),
            size: 1024,
            uploaded: false,
            created: clock::now(),
        }
    }

    #[tokio::test]
    async fn an_attachment_counts_once_it_arrived() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        store.save_cipher(cipher(&user.id, "c1", None)).await.unwrap();
        let before = store.cipher(&user.id, "c1").await.unwrap().unwrap().revision;

        let changed = store.add_attachment(&user.id, attachment("c1", "a1")).await.unwrap().unwrap();
        assert!(changed.revision > before, "the item changed");
        assert!(store.attachments_of_user(&user.id).await.unwrap().is_empty(), "not there yet");
        assert!(store.attachment("c1", "a1").await.unwrap().is_some());

        assert!(store.attachment_uploaded(&user.id, "c1", "a1", 1000).await.unwrap());
        let listed = store.attachments_of_user(&user.id).await.unwrap();
        assert_eq!((listed.len(), listed[0].size), (1, 1000));
        assert_eq!(store.attachment_bytes(&user.id).await.unwrap(), 1000);

        assert!(store.delete_attachment(&user.id, "c1", "a1").await.unwrap().is_some());
        assert!(store.attachments("c1").await.unwrap().is_empty());
        assert!(!store.attachment_exists("c1", "a1").await.unwrap());
    }

    #[tokio::test]
    async fn nobody_attaches_to_somebody_else_s_item() {
        let (store, _dir) = store();
        let nyu = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let other = store.create_user(new_user("other@example.com")).await.unwrap();
        store.save_cipher(cipher(&nyu.id, "c1", None)).await.unwrap();
        store.add_attachment(&nyu.id, attachment("c1", "a1")).await.unwrap().unwrap();
        assert!(store.add_attachment(&other.id, attachment("c1", "a2")).await.unwrap().is_none());
        assert!(!store.attachment_uploaded(&other.id, "c1", "a1", 5).await.unwrap());
        assert!(store.delete_attachment(&other.id, "c1", "a1").await.unwrap().is_none());
        assert!(store.attachment("c1", "a1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn deleting_the_item_takes_its_attachments_along() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        store.save_cipher(cipher(&user.id, "c1", None)).await.unwrap();
        store.add_attachment(&user.id, attachment("c1", "a1")).await.unwrap();
        store.bulk(&user.id, vec!["c1".into()], crate::Bulk::Delete).await.unwrap();
        assert!(!store.attachment_exists("c1", "a1").await.unwrap());
    }
}
