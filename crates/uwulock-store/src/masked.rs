//! Masked addresses from UwUMail (docs/uwu-api.md §13): the OAuth client registered at each
//! UwUMail server, each account's connection (with its tokens as the API sealed them), the links
//! between masked addresses and items, and the API keys of the official clients' generators.
//!
//! Nothing here opens a token: they come in sealed and go out sealed.

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};
use std::collections::BTreeMap;

/// This server as an OAuth client of one UwUMail server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedClient {
    pub server: String,
    pub client_id: String,
    pub redirect_uri: String,
    /// Seconds since 1970 of the last call UwUMail took from it.
    pub used: i64,
}

/// An account's grant at a UwUMail server.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MaskedConnection {
    pub user_id: String,
    pub server: String,
    pub issuer: String,
    pub client_id: String,
    pub token_endpoint: String,
    pub revocation_endpoint: Option<String>,
    pub api_url: String,
    /// The JMAP account the masked addresses are in.
    pub account_id: String,
    pub username: String,
    pub domains: Vec<String>,
    pub default_domain: Option<String>,
    /// Sealed.
    pub access_token: Option<String>,
    /// Seconds since 1970.
    pub access_expires: i64,
    /// Sealed.
    pub refresh_token: String,
    /// `ok`, `revoked` or `unreachable`.
    pub status: String,
    pub connected: String,
    pub last_used: Option<String>,
}

const CONNECTION_COLUMNS: &str = "user_id, server, issuer, client_id, token_endpoint, revocation_endpoint, api_url, \
     account_id, username, domains, default_domain, access_token, access_expires, refresh_token, status, connected, \
     last_used";

fn connection_from(row: &Row<'_>) -> rusqlite::Result<MaskedConnection> {
    let domains: String = row.get(9)?;
    Ok(MaskedConnection {
        user_id: row.get(0)?,
        server: row.get(1)?,
        issuer: row.get(2)?,
        client_id: row.get(3)?,
        token_endpoint: row.get(4)?,
        revocation_endpoint: row.get(5)?,
        api_url: row.get(6)?,
        account_id: row.get(7)?,
        username: row.get(8)?,
        domains: serde_json::from_str(&domains).unwrap_or_default(),
        default_domain: row.get(10)?,
        access_token: row.get(11)?,
        access_expires: row.get(12)?,
        refresh_token: row.get(13)?,
        status: row.get(14)?,
        connected: row.get(15)?,
        last_used: row.get(16)?,
    })
}

/// A masked address that belongs to an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedLink {
    pub masked_id: String,
    pub cipher_id: String,
    pub email: String,
    /// The state UwUMail last said it has.
    pub state: Option<String>,
}

/// A key for the addy.io- and SimpleLogin-compatible endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedApiKey {
    pub id: String,
    pub user_id: String,
    pub name: String,
    /// SHA-256 of the secret part.
    pub hash: Vec<u8>,
    /// The secret's last four characters, to tell keys apart.
    pub hint: String,
    pub created: String,
    pub last_used: Option<String>,
}

fn key_from(row: &Row<'_>) -> rusqlite::Result<MaskedApiKey> {
    Ok(MaskedApiKey {
        id: row.get(0)?,
        user_id: row.get(1)?,
        name: row.get(2)?,
        hash: row.get(3)?,
        hint: row.get(4)?,
        created: row.get(5)?,
        last_used: row.get(6)?,
    })
}

/// How a link could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRefusal {
    /// The item has another masked address already.
    ItemTaken,
}

impl Store {
    // ── Clients ──────────────────────────────────────────

    pub async fn masked_client(&self, server: &str) -> Result<Option<MaskedClient>> {
        let server = server.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT server, client_id, redirect_uri, used FROM masked_clients WHERE server = ?1",
                [server],
                |row| {
                    Ok(MaskedClient {
                        server: row.get(0)?,
                        client_id: row.get(1)?,
                        redirect_uri: row.get(2)?,
                        used: row.get(3)?,
                    })
                },
            )
            .optional()
        })
        .await
    }

    /// Remember a (new) registration at `server`. Connections made with an older client id keep
    /// theirs: UwUMail refreshes a grant only for the client it was given to.
    pub async fn set_masked_client(&self, client: MaskedClient) -> Result<()> {
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO masked_clients (server, client_id, redirect_uri, used) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT (server) DO UPDATE SET client_id = excluded.client_id, \
                 redirect_uri = excluded.redirect_uri, used = excluded.used",
                params![client.server, client.client_id, client.redirect_uri, client.used],
            )?;
            Ok(())
        })
        .await
    }

    /// UwUMail took a call from `client_id` at `now` (seconds since 1970).
    pub async fn masked_client_used(&self, server: &str, client_id: &str, now: i64) -> Result<()> {
        let (server, client_id) = (server.to_string(), client_id.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE masked_clients SET used = ?3 WHERE server = ?1 AND client_id = ?2",
                params![server, client_id, now],
            )?;
            Ok(())
        })
        .await
    }

    /// Whether any account's connection holds a grant of `client_id`: UwUMail keeps such a client.
    pub async fn masked_client_in_use(&self, client_id: &str) -> Result<bool> {
        let client_id = client_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM masked_connections WHERE client_id = ?1 AND status != 'revoked')",
                [client_id],
                |row| row.get(0),
            )
        })
        .await
    }

    /// Forget the registration at `server`, after UwUMail said it does not know it.
    pub async fn forget_masked_client(&self, server: &str, client_id: &str) -> Result<()> {
        let (server, client_id) = (server.to_string(), client_id.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM masked_clients WHERE server = ?1 AND client_id = ?2", [server, client_id])?;
            Ok(())
        })
        .await
    }

    // ── Connections ──────────────────────────────────────

    pub async fn masked_connection(&self, user_id: &str) -> Result<Option<MaskedConnection>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                &format!("SELECT {CONNECTION_COLUMNS} FROM masked_connections WHERE user_id = ?1"),
                [user_id],
                connection_from,
            )
            .optional()
        })
        .await
    }

    /// The account's connection, new or in place of the one it had.
    pub async fn set_masked_connection(&self, connection: MaskedConnection) -> Result<()> {
        self.sqlite_write(move |tx| {
            let c = &connection;
            tx.execute(
                &format!(
                    "INSERT OR REPLACE INTO masked_connections ({CONNECTION_COLUMNS}) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"
                ),
                params![
                    c.user_id,
                    c.server,
                    c.issuer,
                    c.client_id,
                    c.token_endpoint,
                    c.revocation_endpoint,
                    c.api_url,
                    c.account_id,
                    c.username,
                    serde_json::to_string(&c.domains).expect("strings serialize"),
                    c.default_domain,
                    c.access_token,
                    c.access_expires,
                    c.refresh_token,
                    c.status,
                    c.connected,
                    c.last_used,
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// New tokens after a refresh, written before the new access token is used: UwUMail ends the
    /// grant when an old refresh token comes again. Only when the connection still has the refresh
    /// token `used` — a disconnect in between wins.
    pub async fn masked_tokens_refreshed(
        &self,
        user_id: &str,
        used: &str,
        access_token: String,
        access_expires: i64,
        refresh_token: String,
    ) -> Result<bool> {
        let (user_id, used) = (user_id.to_string(), used.to_string());
        self.sqlite_write(move |tx| {
            Ok(tx.execute(
                "UPDATE masked_connections SET access_token = ?3, access_expires = ?4, refresh_token = ?5, \
                 status = 'ok' WHERE user_id = ?1 AND refresh_token = ?2",
                params![user_id, used, access_token, access_expires, refresh_token],
            )? > 0)
        })
        .await
    }

    /// What UwUMail said about the account's connection: `ok`, `revoked`, `unreachable`. Also
    /// when it was last used, for `ok`; the domains, when the session was read again.
    pub async fn masked_status(
        &self,
        user_id: &str,
        status: &str,
        domains: Option<(Vec<String>, Option<String>)>,
    ) -> Result<()> {
        let (user_id, status) = (user_id.to_string(), status.to_string());
        self.sqlite_write(move |tx| {
            let now = clock::now();
            if status == "ok" {
                tx.execute(
                    "UPDATE masked_connections SET status = 'ok', last_used = ?2 WHERE user_id = ?1",
                    params![user_id, now],
                )?;
            } else {
                tx.execute("UPDATE masked_connections SET status = ?2 WHERE user_id = ?1", params![user_id, status])?;
            }
            if let Some((domains, default_domain)) = domains {
                tx.execute(
                    "UPDATE masked_connections SET domains = ?2, default_domain = ?3 WHERE user_id = ?1",
                    params![user_id, serde_json::to_string(&domains).expect("strings serialize"), default_domain],
                )?;
            }
            Ok(())
        })
        .await
    }

    /// The connection goes, with the links of its addresses. The addresses stay at UwUMail.
    pub async fn delete_masked_connection(&self, user_id: &str) -> Result<bool> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM masked_links WHERE user_id = ?1", [&user_id])?;
            Ok(tx.execute("DELETE FROM masked_connections WHERE user_id = ?1", [&user_id])? > 0)
        })
        .await
    }

    // ── Links ────────────────────────────────────────────

    pub async fn masked_links(&self, user_id: &str) -> Result<Vec<MaskedLink>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT masked_id, cipher_id, email, state FROM masked_links WHERE user_id = ?1 ORDER BY cipher_id",
            )?
            .query_map([user_id], |row| {
                Ok(MaskedLink {
                    masked_id: row.get(0)?,
                    cipher_id: row.get(1)?,
                    email: row.get(2)?,
                    state: row.get(3)?,
                })
            })?
            .collect()
        })
        .await
    }

    /// Link `link.masked_id` to `link.cipher_id`, instead of whatever that address was linked to.
    /// The caller checked that the account sees the item.
    pub async fn link_masked(&self, user_id: &str, link: MaskedLink) -> Result<Result<(), LinkRefusal>> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            let other: Option<String> = tx
                .query_row(
                    "SELECT masked_id FROM masked_links WHERE user_id = ?1 AND cipher_id = ?2",
                    [&user_id, &link.cipher_id],
                    |row| row.get(0),
                )
                .optional()?;
            if other.is_some_and(|other| other != link.masked_id) {
                return Ok(Err(LinkRefusal::ItemTaken));
            }
            tx.execute(
                "INSERT OR REPLACE INTO masked_links (user_id, masked_id, cipher_id, email, state, revision) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![user_id, link.masked_id, link.cipher_id, link.email, link.state, clock::now()],
            )?;
            Ok(Ok(()))
        })
        .await
    }

    /// The address belongs to no item any more; whether it belonged to one.
    pub async fn unlink_masked(&self, user_id: &str, masked_id: &str) -> Result<bool> {
        let (user_id, masked_id) = (user_id.to_string(), masked_id.to_string());
        self.sqlite_write(move |tx| {
            Ok(tx.execute("DELETE FROM masked_links WHERE user_id = ?1 AND masked_id = ?2", [user_id, masked_id])? > 0)
        })
        .await
    }

    /// Remember the state UwUMail gave for the account's addresses, where they are linked; whether
    /// one of them was not known that way.
    pub async fn masked_link_states(&self, user_id: &str, states: BTreeMap<String, String>) -> Result<bool> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            let mut changed = false;
            for (masked_id, state) in states {
                changed |= tx.execute(
                    "UPDATE masked_links SET state = ?3, revision = ?4 \
                     WHERE user_id = ?1 AND masked_id = ?2 AND state IS NOT ?3",
                    params![user_id, masked_id, state, clock::now()],
                )? > 0;
            }
            Ok(changed)
        })
        .await
    }

    // ── API keys ─────────────────────────────────────────

    pub async fn masked_api_keys(&self, user_id: &str) -> Result<Vec<MaskedApiKey>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT id, user_id, name, hash, hint, created, last_used FROM masked_api_keys \
                 WHERE user_id = ?1 ORDER BY created",
            )?
            .query_map([user_id], key_from)?
            .collect()
        })
        .await
    }

    pub async fn masked_api_key(&self, id: &str) -> Result<Option<MaskedApiKey>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT id, user_id, name, hash, hint, created, last_used FROM masked_api_keys WHERE id = ?1",
                [id],
                key_from,
            )
            .optional()
        })
        .await
    }

    /// A new key, unless the account has `most` already.
    pub async fn add_masked_api_key(&self, key: MaskedApiKey, most: i64) -> Result<bool> {
        self.sqlite_write(move |tx| {
            let count: i64 =
                tx.query_row("SELECT count(*) FROM masked_api_keys WHERE user_id = ?1", [&key.user_id], |row| {
                    row.get(0)
                })?;
            if count >= most {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO masked_api_keys (id, user_id, name, hash, hint, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![key.id, key.user_id, key.name, key.hash, key.hint, key.created],
            )?;
            Ok(true)
        })
        .await
    }

    pub async fn delete_masked_api_key(&self, user_id: &str, id: &str) -> Result<bool> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        self.sqlite_write(move |tx| {
            Ok(tx.execute("DELETE FROM masked_api_keys WHERE id = ?1 AND user_id = ?2", [id, user_id])? > 0)
        })
        .await
    }

    pub async fn masked_api_key_used(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE masked_api_keys SET last_used = ?2 WHERE id = ?1", params![id, clock::now()])?;
            Ok(())
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
    async fn one_address_per_item_and_the_link_goes_with_the_item() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        store.save_cipher(cipher(&user.id, "c1", None)).await.unwrap().unwrap();
        store.save_cipher(cipher(&user.id, "c2", None)).await.unwrap().unwrap();
        let link = |masked: &str, cipher: &str| MaskedLink {
            masked_id: masked.into(),
            cipher_id: cipher.into(),
            email: format!("{masked}@masked.example.com"),
            state: Some("enabled".into()),
        };
        store.link_masked(&user.id, link("x1", "c1")).await.unwrap().unwrap();
        assert_eq!(store.link_masked(&user.id, link("x2", "c1")).await.unwrap(), Err(LinkRefusal::ItemTaken));
        // The same address to another item moves it.
        store.link_masked(&user.id, link("x1", "c2")).await.unwrap().unwrap();
        store.link_masked(&user.id, link("x2", "c1")).await.unwrap().unwrap();
        let states = BTreeMap::from([("x1".to_string(), "disabled".to_string())]);
        store.masked_link_states(&user.id, states).await.unwrap();
        let links = store.masked_links(&user.id).await.unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!((links[1].cipher_id.as_str(), links[1].state.as_deref()), ("c2", Some("disabled")));

        store.bulk(&user.id, vec!["c2".into()], crate::Bulk::Delete).await.unwrap();
        let links = store.masked_links(&user.id).await.unwrap();
        assert_eq!(links.iter().map(|link| link.masked_id.as_str()).collect::<Vec<_>>(), ["x2"], "gone with the item");
    }

    #[tokio::test]
    async fn a_refresh_is_kept_only_for_the_token_it_used() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let connection = MaskedConnection {
            user_id: user.id.clone(),
            server: "https://mail.example.com".into(),
            refresh_token: "r1".into(),
            status: "ok".into(),
            domains: vec!["masked.example.com".into()],
            ..MaskedConnection::default()
        };
        store.set_masked_connection(connection).await.unwrap();
        assert!(store.masked_tokens_refreshed(&user.id, "r1", "a2".into(), 10, "r2".into()).await.unwrap());
        assert!(!store.masked_tokens_refreshed(&user.id, "r1", "a3".into(), 10, "r3".into()).await.unwrap());
        let now = store.masked_connection(&user.id).await.unwrap().unwrap();
        assert_eq!((now.refresh_token.as_str(), now.access_token.as_deref()), ("r2", Some("a2")));
        assert_eq!(now.domains, ["masked.example.com"]);

        let key = MaskedApiKey {
            id: "k1".into(),
            user_id: user.id.clone(),
            name: "Firefox".into(),
            hash: vec![1; 32],
            hint: "3fQa".into(),
            created: clock::now(),
            last_used: None,
        };
        assert!(store.add_masked_api_key(key.clone(), 1).await.unwrap());
        assert!(!store.add_masked_api_key(MaskedApiKey { id: "k2".into(), ..key }, 1).await.unwrap(), "at most one");
        assert!(store.delete_masked_connection(&user.id).await.unwrap());
        assert!(store.masked_connection(&user.id).await.unwrap().is_none());
        assert_eq!(store.masked_api_keys(&user.id).await.unwrap().len(), 1, "keys stay");
    }
}
