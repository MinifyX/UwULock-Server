//! Own icons of items (docs/uwu-api.md §7.3): a small PNG the person chose, encrypted by the
//! client, kept per item. The server never learns what it shows, nor which website it is for.

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnIcon {
    pub cipher_id: String,
    /// `extras` or `organization`: the key it is under.
    pub key_type: String,
    /// The EncString; left out where only the list is asked for.
    pub data: Option<String>,
    pub revision: String,
}

fn icon_from(row: &Row<'_>) -> rusqlite::Result<OwnIcon> {
    Ok(OwnIcon { cipher_id: row.get(0)?, key_type: row.get(1)?, data: row.get(2)?, revision: row.get(3)? })
}

impl Store {
    pub async fn own_icon(&self, cipher_id: &str) -> Result<Option<OwnIcon>> {
        let cipher_id = cipher_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached("SELECT cipher_id, key_type, data, revision FROM own_icons WHERE cipher_id = ?1")?
                .query_row([cipher_id], icon_from)
                .optional()
        })
        .await
    }

    /// The own icons of those of `cipher_ids` that have one; with their data, or only which
    /// there are.
    pub async fn own_icons(&self, cipher_ids: Vec<String>, with_data: bool) -> Result<Vec<OwnIcon>> {
        self.sqlite_read(move |conn| {
            let sql = if with_data {
                "SELECT cipher_id, key_type, data, revision FROM own_icons WHERE cipher_id = ?1"
            } else {
                "SELECT cipher_id, key_type, NULL, revision FROM own_icons WHERE cipher_id = ?1"
            };
            let mut statement = conn.prepare_cached(sql)?;
            let mut icons = Vec::new();
            for id in cipher_ids {
                if let Some(icon) = statement.query_row([id], icon_from).optional()? {
                    icons.push(icon);
                }
            }
            Ok(icons)
        })
        .await
    }

    /// Keep an item's own icon, in place of the one it had. The caller checked the item.
    pub async fn put_own_icon(&self, cipher_id: &str, key_type: &str, data: String) -> Result<OwnIcon> {
        let icon = OwnIcon {
            cipher_id: cipher_id.to_string(),
            key_type: key_type.to_string(),
            data: Some(data),
            revision: clock::now(),
        };
        let kept = icon.clone();
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO own_icons (cipher_id, key_type, data, revision) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT (cipher_id) DO UPDATE SET key_type = excluded.key_type, data = excluded.data, \
                 revision = excluded.revision",
                params![kept.cipher_id, kept.key_type, kept.data, kept.revision],
            )
            .map(drop)
        })
        .await?;
        Ok(icon)
    }

    pub async fn delete_own_icon(&self, cipher_id: &str) -> Result<bool> {
        let cipher_id = cipher_id.to_string();
        self.sqlite_write(move |tx| Ok(tx.execute("DELETE FROM own_icons WHERE cipher_id = ?1", [cipher_id])? > 0))
            .await
    }

    /// Bytes all own icons take, for the admin portal.
    pub async fn own_icon_bytes(&self) -> Result<i64> {
        self.sqlite_read(|conn| {
            conn.query_row("SELECT coalesce(sum(length(data)), 0) FROM own_icons", [], |row| row.get(0))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::accounts::tests::{new_user, store};
    use crate::vault::tests::cipher;

    #[tokio::test]
    async fn an_icon_lives_and_dies_with_its_item() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        store.save_cipher(cipher(&user.id, "c", None)).await.unwrap().unwrap();
        store.put_own_icon("c", "extras", "2.a|a|a".into()).await.unwrap();
        store.put_own_icon("c", "extras", "2.b|b|b".into()).await.unwrap();
        assert_eq!(store.own_icon("c").await.unwrap().unwrap().data.as_deref(), Some("2.b|b|b"));
        let listed = store.own_icons(vec!["c".into(), "nope".into()], false).await.unwrap();
        assert_eq!((listed.len(), listed[0].data.clone()), (1, None));
        assert!(store.own_icon_bytes().await.unwrap() > 0);
        store.bulk(&user.id, vec!["c".into()], crate::Bulk::Delete).await.unwrap();
        assert!(store.own_icon("c").await.unwrap().is_none());
    }
}
