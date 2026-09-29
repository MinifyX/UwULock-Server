//! Sends: a text or a file for somebody without an account, behind a link. The link carries
//! the key; the server keeps what the client encrypted, counts how often it was opened, and
//! forgets it on its deletion date.

use crate::accounts::bump_revision;
use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Send {
    pub id: String,
    pub user_id: String,
    /// 0 text, 1 file.
    pub kind: i64,
    pub name: String,
    pub notes: Option<String>,
    /// JSON: `{"text": …, "hidden": …}` or `{"id": …, "fileName": …, "size": …, "sizeName": …}`.
    pub data: String,
    /// The Send's key, wrapped under the user key.
    pub key: String,
    /// The server's hash of the password hash the client sends; none without a password.
    pub password_hash: Option<String>,
    pub max_access_count: Option<i64>,
    pub access_count: i64,
    pub created: String,
    pub revision: String,
    pub expiration: Option<String>,
    pub deletion: String,
    pub disabled: bool,
    pub hide_email: bool,
    /// For a file Send, whether its file arrived.
    pub uploaded: bool,
    /// Only these may open it, with a code mailed to them: lower case, comma-separated. Excludes
    /// a password.
    pub emails: Option<String>,
}

pub const TEXT: i64 = 0;
pub const FILE: i64 = 1;

const COLUMNS: &str = "id, user_id, type, name, notes, data, key, password_hash, max_access_count, access_count, \
     created, revision, expiration, deletion, disabled, hide_email, uploaded, emails";

fn send_from(row: &Row<'_>) -> rusqlite::Result<Send> {
    Ok(Send {
        id: row.get(0)?,
        user_id: row.get(1)?,
        kind: row.get(2)?,
        name: row.get(3)?,
        notes: row.get(4)?,
        data: row.get(5)?,
        key: row.get(6)?,
        password_hash: row.get(7)?,
        max_access_count: row.get(8)?,
        access_count: row.get(9)?,
        created: row.get(10)?,
        revision: row.get(11)?,
        expiration: row.get(12)?,
        deletion: row.get(13)?,
        disabled: row.get(14)?,
        hide_email: row.get(15)?,
        uploaded: row.get(16)?,
        emails: row.get(17)?,
    })
}

impl Send {
    /// Whether the link opens it now: not disabled, not expired, not past its deletion date,
    /// not opened as often as it may be, and for a file, with its file there.
    pub fn accessible(&self) -> bool {
        self.open() && self.max_access_count.is_none_or(|max| self.access_count < max)
    }

    /// Like [`Send::accessible`], but for somebody whose opening was counted already.
    pub fn open(&self) -> bool {
        let now = clock::now();
        !self.disabled
            && self.expiration.as_ref().is_none_or(|expiration| *expiration > now)
            && self.deletion > now
            && (self.kind != FILE || self.uploaded)
    }
}

pub(crate) fn write_send(tx: &rusqlite::Transaction<'_>, send: &Send) -> rusqlite::Result<usize> {
    tx.prepare_cached(&format!(
        "INSERT INTO sends ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18) \
         ON CONFLICT (id) DO UPDATE SET name = excluded.name, notes = excluded.notes, data = excluded.data, \
         key = excluded.key, password_hash = excluded.password_hash, max_access_count = excluded.max_access_count, \
         revision = excluded.revision, expiration = excluded.expiration, deletion = excluded.deletion, \
         disabled = excluded.disabled, hide_email = excluded.hide_email, uploaded = excluded.uploaded, emails = excluded.emails \
         WHERE sends.user_id = excluded.user_id"
    ))?
    .execute(params![
        send.id,
        send.user_id,
        send.kind,
        send.name,
        send.notes,
        send.data,
        send.key,
        send.password_hash,
        send.max_access_count,
        send.access_count,
        send.created,
        send.revision,
        send.expiration,
        send.deletion,
        send.disabled,
        send.hide_email,
        send.uploaded,
        send.emails,
    ])
}

impl Store {
    pub async fn sends(&self, user_id: &str) -> Result<Vec<Send>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {COLUMNS} FROM sends WHERE user_id = ?1 ORDER BY created"))?
                .query_map([user_id], send_from)?
                .collect()
        })
        .await
    }

    /// One of the user's Sends; nothing for somebody else's.
    pub async fn send(&self, user_id: &str, id: &str) -> Result<Option<Send>> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {COLUMNS} FROM sends WHERE id = ?1 AND user_id = ?2"))?
                .query_row([id, user_id], send_from)
                .optional()
        })
        .await
    }

    /// Mark that the file of `user_id`'s Send `id` arrived — only that, so whatever changed on
    /// the Send while the file was on its way stays. The Send afterwards; nothing when it is not
    /// theirs or its file was there already.
    pub async fn send_file_uploaded(&self, user_id: &str, id: &str) -> Result<Option<Send>> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        let owner = user_id.clone();
        let saved = self
            .sqlite_write(move |tx| {
                let marked = tx.execute(
                    "UPDATE sends SET uploaded = 1, revision = ?3 WHERE id = ?1 AND user_id = ?2 AND uploaded = 0",
                    params![id, user_id, clock::now()],
                )? > 0;
                if !marked {
                    return Ok(None);
                }
                bump_revision(tx, &user_id)?;
                tx.query_row(&format!("SELECT {COLUMNS} FROM sends WHERE id = ?1"), [&id], send_from).optional()
            })
            .await?;
        self.forget_session_of(&owner);
        Ok(saved)
    }

    /// A Send by its id alone, for somebody with the link.
    pub async fn send_by_id(&self, id: &str) -> Result<Option<Send>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {COLUMNS} FROM sends WHERE id = ?1"))?
                .query_row([id], send_from)
                .optional()
        })
        .await
    }

    /// Write a Send as it is now, new or changed; its revision is set to now. Nothing when a
    /// Send of that id is somebody else's.
    pub async fn save_send(&self, mut send: Send) -> Result<Option<Send>> {
        let user_id = send.user_id.clone();
        let saved = self
            .sqlite_write(move |tx| {
                send.revision = clock::now();
                if write_send(tx, &send)? == 0 {
                    return Ok(None);
                }
                bump_revision(tx, &send.user_id)?;
                tx.query_row(&format!("SELECT {COLUMNS} FROM sends WHERE id = ?1"), [&send.id], send_from).optional()
            })
            .await?;
        self.forget_session_of(&user_id);
        Ok(saved)
    }

    /// The Send goes; its file, if any, is swept away later.
    pub async fn delete_send(&self, user_id: &str, id: &str) -> Result<bool> {
        let (owned, id) = (user_id.to_string(), id.to_string());
        let deleted = self
            .sqlite_write(move |tx| {
                let deleted = tx.execute("DELETE FROM sends WHERE id = ?1 AND user_id = ?2", [&id, &owned])? > 0;
                if deleted {
                    bump_revision(tx, &owned)?;
                }
                Ok(deleted)
            })
            .await?;
        self.forget_session_of(user_id);
        Ok(deleted)
    }

    /// Count one opening of the Send, unless it was opened as often as it may be already. In
    /// one statement, so two at the same moment cannot both take the last one.
    pub async fn register_send_access(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        let owner = self
            .sqlite_write(move |tx| {
                let now = clock::now();
                let counted = tx.execute(
                    "UPDATE sends SET access_count = access_count + 1, revision = ?2 \
                     WHERE id = ?1 AND (max_access_count IS NULL OR access_count < max_access_count)",
                    params![id, now],
                )? > 0;
                if !counted {
                    return Ok(None);
                }
                let owner: String = tx.query_row("SELECT user_id FROM sends WHERE id = ?1", [&id], |row| row.get(0))?;
                bump_revision(tx, &owner)?;
                Ok(Some(owner))
            })
            .await?;
        if let Some(owner) = &owner {
            self.forget_session_of(owner);
        }
        Ok(owner.is_some())
    }

    /// Whether a file on disk still belongs to a Send.
    pub async fn send_exists(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT EXISTS (SELECT 1 FROM sends WHERE id = ?1)", [id], |row| row.get(0))
        })
        .await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::accounts::tests::{new_user, store};

    pub(crate) fn text_send(user_id: &str, id: &str) -> Send {
        Send {
            id: id.into(),
            user_id: user_id.into(),
            kind: TEXT,
            name: "2.name|name|name".into(),
            notes: None,
            data: r#"{"text":"2.t|t|t","hidden":false}"#.into(),
            key: "2.key|key|key".into(),
            password_hash: None,
            max_access_count: None,
            access_count: 0,
            created: clock::now(),
            revision: clock::now(),
            expiration: None,
            deletion: clock::in_seconds(86_400),
            disabled: false,
            hide_email: false,
            uploaded: false,
            emails: None,
        }
    }

    #[tokio::test]
    async fn a_send_opens_as_often_as_it_may() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let mut send = text_send(&user.id, "s1");
        send.max_access_count = Some(2);
        let saved = store.save_send(send).await.unwrap().unwrap();
        assert!(saved.accessible());
        assert!(store.register_send_access("s1").await.unwrap());
        assert!(store.register_send_access("s1").await.unwrap());
        assert!(!store.register_send_access("s1").await.unwrap(), "the third time");
        assert!(!store.send_by_id("s1").await.unwrap().unwrap().accessible());
    }

    #[tokio::test]
    async fn expired_disabled_and_waiting_sends_do_not_open() {
        let mut send = text_send("u", "s");
        assert!(send.accessible());
        send.expiration = Some(clock::in_seconds(-1));
        assert!(!send.accessible());
        send.expiration = None;
        send.disabled = true;
        assert!(!send.accessible());
        send.disabled = false;
        send.deletion = clock::in_seconds(-1);
        assert!(!send.accessible());
        send.deletion = clock::in_seconds(60);
        send.kind = FILE;
        assert!(!send.accessible(), "the file did not arrive");
    }

    #[tokio::test]
    async fn sends_stay_their_owner_s() {
        let (store, _dir) = store();
        let nyu = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let other = store.create_user(new_user("other@example.com")).await.unwrap();
        store.save_send(text_send(&nyu.id, "s1")).await.unwrap().unwrap();
        assert!(store.save_send(text_send(&other.id, "s1")).await.unwrap().is_none());
        assert!(store.send(&other.id, "s1").await.unwrap().is_none());
        assert!(!store.delete_send(&other.id, "s1").await.unwrap());
        assert_eq!(store.sends(&nyu.id).await.unwrap().len(), 1);
        assert!(store.delete_send(&nyu.id, "s1").await.unwrap());
        assert!(!store.send_exists("s1").await.unwrap());
    }
}
