//! Passkeys that log in to the web vault, and the API key the CLI logs in with.

use crate::{Result, Store, StoreError, clock};
use rusqlite::{OptionalExtension, Row, params};

/// How many passkeys one account may have for logging in, like at Bitwarden.
pub const MAX_PASSKEYS: i64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passkey {
    /// The credential id, base64url.
    pub id: String,
    pub user_id: String,
    pub name: String,
    /// The COSE public key, base64url.
    pub public_key: String,
    pub counter: i64,
    pub supports_prf: bool,
    pub encrypted_user_key: Option<String>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
    pub created: String,
    pub last_used: Option<String>,
}

const COLUMNS: &str = "id, user_id, name, public_key, counter, supports_prf, encrypted_user_key, \
     encrypted_public_key, encrypted_private_key, created, last_used";

fn passkey_from(row: &Row<'_>) -> rusqlite::Result<Passkey> {
    Ok(Passkey {
        id: row.get(0)?,
        user_id: row.get(1)?,
        name: row.get(2)?,
        public_key: row.get(3)?,
        counter: row.get(4)?,
        supports_prf: row.get(5)?,
        encrypted_user_key: row.get(6)?,
        encrypted_public_key: row.get(7)?,
        encrypted_private_key: row.get(8)?,
        created: row.get(9)?,
        last_used: row.get(10)?,
    })
}

impl Store {
    pub async fn passkeys(&self, user_id: &str) -> Result<Vec<Passkey>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {COLUMNS} FROM passkeys WHERE user_id = ?1 ORDER BY created"))?
                .query_map([user_id], passkey_from)?
                .collect()
        })
        .await
    }

    /// A passkey by its credential id, whoever's it is: a login says only that.
    pub async fn passkey(&self, id: &str) -> Result<Option<Passkey>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {COLUMNS} FROM passkeys WHERE id = ?1"))?
                .query_row([id], passkey_from)
                .optional()
        })
        .await
    }

    /// A new passkey. [`StoreError::Exists`] when the credential is known already, or the
    /// account has [`MAX_PASSKEYS`] of them.
    pub async fn add_passkey(&self, passkey: Passkey) -> Result<()> {
        let added = self
            .sqlite_write(move |tx| {
                let count: i64 =
                    tx.query_row("SELECT count(*) FROM passkeys WHERE user_id = ?1", [&passkey.user_id], |row| {
                        row.get(0)
                    })?;
                if count >= MAX_PASSKEYS {
                    return Ok(false);
                }
                let inserted = tx.execute(
                    &format!(
                        "INSERT INTO passkeys ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) \
                         ON CONFLICT (id) DO NOTHING"
                    ),
                    params![
                        passkey.id,
                        passkey.user_id,
                        passkey.name,
                        passkey.public_key,
                        passkey.counter,
                        passkey.supports_prf,
                        passkey.encrypted_user_key,
                        passkey.encrypted_public_key,
                        passkey.encrypted_private_key,
                        passkey.created,
                        passkey.last_used,
                    ],
                )?;
                Ok(inserted > 0)
            })
            .await?;
        if added { Ok(()) } else { Err(StoreError::Exists) }
    }

    /// A login with the passkey: its new signature counter, and when.
    pub async fn passkey_used(&self, id: &str, counter: i64) -> Result<()> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE passkeys SET counter = ?2, last_used = ?3 WHERE id = ?1",
                params![id, counter, clock::now()],
            )
            .map(drop)
        })
        .await
    }

    /// New wrapped keys for a passkey of the user's, after a key rotation or when unlocking with
    /// it is turned on later.
    pub async fn set_passkey_keys(
        &self,
        user_id: &str,
        id: &str,
        user_key: String,
        public_key: String,
        private_key: String,
    ) -> Result<bool> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        self.sqlite_write(move |tx| {
            Ok(tx.execute(
                "UPDATE passkeys SET supports_prf = 1, encrypted_user_key = ?3, encrypted_public_key = ?4, \
                 encrypted_private_key = ?5 WHERE id = ?1 AND user_id = ?2",
                params![id, user_id, user_key, public_key, private_key],
            )? > 0)
        })
        .await
    }

    pub async fn delete_passkey(&self, user_id: &str, id: &str) -> Result<bool> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        self.sqlite_write(move |tx| {
            Ok(tx.execute("DELETE FROM passkeys WHERE id = ?1 AND user_id = ?2", [id, user_id])? > 0)
        })
        .await
    }

    // ── The API key ────────────────────────────────────────

    /// The user's API key, made with `fresh` if there is none yet — or if the one there was made
    /// under an earlier security stamp (R1-5).
    pub async fn api_key(&self, user_id: &str, fresh: String) -> Result<(String, String)> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO api_keys (user_id, secret, revision, stamp) \
                 SELECT ?1, ?2, ?3, security_stamp FROM users WHERE id = ?1 \
                 ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, revision = excluded.revision, \
                 stamp = excluded.stamp WHERE api_keys.stamp <> excluded.stamp",
                params![user_id, fresh, clock::now()],
            )?;
            tx.query_row("SELECT secret, revision FROM api_keys WHERE user_id = ?1", [&user_id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
        })
        .await
    }

    /// A new API key for the user; the old one stops working.
    pub async fn rotate_api_key(&self, user_id: &str, secret: String) -> Result<(String, String)> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            let now = clock::now();
            tx.execute(
                "INSERT INTO api_keys (user_id, secret, revision, stamp) \
                 SELECT ?1, ?2, ?3, security_stamp FROM users WHERE id = ?1 \
                 ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, revision = excluded.revision, \
                 stamp = excluded.stamp",
                params![user_id, secret, now],
            )?;
            Ok((secret, now))
        })
        .await
    }

    /// The API key of a user, to check a login with it: only one made under the account's
    /// current security stamp.
    pub async fn api_key_of(&self, user_id: &str) -> Result<Option<String>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT k.secret FROM api_keys k JOIN users u ON u.id = k.user_id \
                 WHERE k.user_id = ?1 AND k.stamp = u.security_stamp",
                [user_id],
                |row| row.get(0),
            )
            .optional()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::{new_user, store};

    fn passkey(user_id: &str, id: &str) -> Passkey {
        Passkey {
            id: id.into(),
            user_id: user_id.into(),
            name: "Key".into(),
            public_key: "pQECAyYgASFY".into(),
            counter: 0,
            supports_prf: false,
            encrypted_user_key: None,
            encrypted_public_key: None,
            encrypted_private_key: None,
            created: clock::now(),
            last_used: None,
        }
    }

    #[tokio::test]
    async fn at_most_five_passkeys_each_once() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        for n in 0..MAX_PASSKEYS {
            store.add_passkey(passkey(&user.id, &format!("k{n}"))).await.unwrap();
        }
        assert!(matches!(store.add_passkey(passkey(&user.id, "k9")).await, Err(StoreError::Exists)));
        store.delete_passkey(&user.id, "k4").await.unwrap();
        assert!(matches!(store.add_passkey(passkey(&user.id, "k0")).await, Err(StoreError::Exists)), "known");
        store.passkey_used("k0", 7).await.unwrap();
        assert_eq!(store.passkey("k0").await.unwrap().unwrap().counter, 7);
        assert!(store.set_passkey_keys(&user.id, "k0", "4.u".into(), "2.p".into(), "2.q".into()).await.unwrap());
        assert!(store.passkey("k0").await.unwrap().unwrap().supports_prf);
    }

    #[tokio::test]
    async fn an_api_key_is_made_once_and_rotated_on_request() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let (first, _) = store.api_key(&user.id, "one".into()).await.unwrap();
        let (again, _) = store.api_key(&user.id, "two".into()).await.unwrap();
        assert_eq!((first.as_str(), again.as_str()), ("one", "one"));
        store.rotate_api_key(&user.id, "three".into()).await.unwrap();
        assert_eq!(store.api_key_of(&user.id).await.unwrap().as_deref(), Some("three"));
        // A new security stamp (password change, log out everywhere, …) ends the key (R1-5).
        store.update_user(&user.id, |user| user.security_stamp = "new".into()).await.unwrap();
        assert_eq!(store.api_key_of(&user.id).await.unwrap(), None);
        let (fresh, _) = store.api_key(&user.id, "four".into()).await.unwrap();
        assert_eq!(fresh, "four");
        assert_eq!(store.api_key_of(&user.id).await.unwrap().as_deref(), Some("four"));
    }
}
