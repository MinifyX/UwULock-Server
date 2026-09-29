//! Send domains (docs/uwu-api.md §14.1, §14.2): extra hosts an admin adds that serve only Sends
//! and file requests, the choice of one per Send, and each account's default.

use crate::{Result, Store, StoreError, clock};
use rusqlite::{OptionalExtension, Row, params};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendDomain {
    pub id: String,
    /// Lower case, no scheme, no port.
    pub host: String,
    /// `acme` or `proxy`.
    pub tls: String,
    pub created: String,
}

fn domain_from(row: &Row<'_>) -> rusqlite::Result<SendDomain> {
    Ok(SendDomain { id: row.get(0)?, host: row.get(1)?, tls: row.get(2)?, created: row.get(3)? })
}

impl Store {
    /// Every send domain, by host.
    pub async fn send_domains(&self) -> Result<Vec<SendDomain>> {
        self.sqlite_read(|conn| {
            conn.prepare_cached("SELECT id, host, tls, created FROM send_domains ORDER BY host")?
                .query_map([], domain_from)?
                .collect()
        })
        .await
    }

    /// A new send domain; `Exists` when the host is taken.
    pub async fn add_send_domain(&self, host: &str, tls: &str) -> Result<SendDomain> {
        let domain = SendDomain {
            id: uuid::Uuid::new_v4().to_string(),
            host: host.to_string(),
            tls: tls.to_string(),
            created: clock::now(),
        };
        let row = domain.clone();
        self.sqlite_write(move |tx| {
            let taken: bool =
                tx.query_row("SELECT EXISTS (SELECT 1 FROM send_domains WHERE host = ?1)", [&row.host], |r| r.get(0))?;
            if taken {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO send_domains (id, host, tls, created) VALUES (?1, ?2, ?3, ?4)",
                params![row.id, row.host, row.tls, row.created],
            )?;
            Ok(true)
        })
        .await?
        .then_some(domain)
        .ok_or(StoreError::Exists)
    }

    /// Change how the domain gets its certificate; the domain afterwards, nothing when it is gone.
    pub async fn set_send_domain_tls(&self, id: &str, tls: &str) -> Result<Option<SendDomain>> {
        let (id, tls) = (id.to_string(), tls.to_string());
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE send_domains SET tls = ?2 WHERE id = ?1", params![id, tls])?;
            tx.query_row("SELECT id, host, tls, created FROM send_domains WHERE id = ?1", [&id], domain_from).optional()
        })
        .await
    }

    /// The domain goes, with its branding. Sends, file requests and accounts that chose it fall
    /// back to the main host.
    pub async fn delete_send_domain(&self, id: &str) -> Result<bool> {
        let id = id.to_string();
        self.sqlite_write(move |tx| {
            // The foreign keys clear sends and users; file requests keep the id without one.
            tx.execute("UPDATE file_requests SET send_domain_id = NULL WHERE send_domain_id = ?1", [&id])?;
            tx.execute("DELETE FROM branding WHERE scope = ?1", [&id])?;
            Ok(tx.execute("DELETE FROM send_domains WHERE id = ?1", [&id])? > 0)
        })
        .await
    }

    /// The account's default send domain; `None` is the main host.
    pub async fn account_send_domain(&self, user_id: &str) -> Result<Option<String>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT send_domain_id FROM users WHERE id = ?1", [user_id], |row| row.get(0))
                .optional()
                .map(Option::flatten)
        })
        .await
    }

    /// Set the account's default; false when `domain_id` names no send domain.
    pub async fn set_account_send_domain(&self, user_id: &str, domain_id: Option<String>) -> Result<bool> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            if let Some(id) = &domain_id
                && !domain_exists(tx, id)?
            {
                return Ok(false);
            }
            tx.execute("UPDATE users SET send_domain_id = ?2 WHERE id = ?1", params![user_id, domain_id])?;
            Ok(true)
        })
        .await
    }

    /// The domain of each of the account's Sends.
    pub async fn send_domain_choices(&self, user_id: &str) -> Result<BTreeMap<String, Option<String>>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached("SELECT id, domain_id FROM sends WHERE user_id = ?1")?
                .query_map([user_id], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        })
        .await
    }

    /// The domain one Send's link and page use; the outer `None` when the Send does not exist.
    pub async fn send_domain_of(&self, send_id: &str) -> Result<Option<Option<String>>> {
        let send_id = send_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT domain_id FROM sends WHERE id = ?1", [send_id], |row| row.get(0)).optional()
        })
        .await
    }

    /// Choose the domain of `user_id`'s Send `send_id`. `None` when the Send is not theirs,
    /// `Some(false)` when the domain does not exist.
    pub async fn set_send_domain(
        &self,
        user_id: &str,
        send_id: &str,
        domain_id: Option<String>,
    ) -> Result<Option<bool>> {
        let (user_id, send_id) = (user_id.to_string(), send_id.to_string());
        let owner = user_id.clone();
        let set = self
            .sqlite_write(move |tx| {
                if let Some(id) = &domain_id
                    && !domain_exists(tx, id)?
                {
                    let theirs: bool = tx.query_row(
                        "SELECT EXISTS (SELECT 1 FROM sends WHERE id = ?1 AND user_id = ?2)",
                        [&send_id, &user_id],
                        |row| row.get(0),
                    )?;
                    return Ok(theirs.then_some(false));
                }
                let changed = tx.execute(
                    "UPDATE sends SET domain_id = ?3, revision = ?4 WHERE id = ?1 AND user_id = ?2",
                    params![send_id, user_id, domain_id, clock::now()],
                )?;
                Ok((changed > 0).then_some(true))
            })
            .await?;
        self.forget_session_of(&owner);
        Ok(set)
    }

    /// A new Send made through Bitwarden's API gets the account's default, which the official
    /// clients cannot choose.
    pub async fn default_send_domain(&self, user_id: &str, send_id: &str) -> Result<()> {
        let (user_id, send_id) = (user_id.to_string(), send_id.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE sends SET domain_id = (SELECT send_domain_id FROM users WHERE id = ?1) \
                 WHERE id = ?2 AND user_id = ?1",
                params![user_id, send_id],
            )?;
            Ok(())
        })
        .await
    }
}

fn domain_exists(tx: &rusqlite::Transaction<'_>, id: &str) -> rusqlite::Result<bool> {
    tx.query_row("SELECT EXISTS (SELECT 1 FROM send_domains WHERE id = ?1)", [id], |row| row.get(0))
}

#[cfg(test)]
mod tests {
    use crate::accounts::tests::{new_user, store};
    use crate::sends::Send;

    fn send(user_id: &str, id: &str) -> Send {
        Send {
            id: id.into(),
            user_id: user_id.into(),
            kind: crate::sends::TEXT,
            name: "2.n|n|n".into(),
            notes: None,
            data: "{}".into(),
            key: "2.k|k|k".into(),
            password_hash: None,
            max_access_count: None,
            access_count: 0,
            created: crate::clock::now(),
            revision: crate::clock::now(),
            expiration: None,
            deletion: "2999-01-01T00:00:00.000000Z".into(),
            disabled: false,
            hide_email: false,
            uploaded: false,
            emails: None,
        }
    }

    #[tokio::test]
    async fn a_send_uses_the_account_default_until_it_chooses_and_falls_back_when_the_domain_goes() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let domain = store.add_send_domain("send.example.com", "acme").await.unwrap();
        assert!(matches!(store.add_send_domain("send.example.com", "proxy").await, Err(crate::StoreError::Exists)));
        assert!(!store.set_account_send_domain(&user.id, Some("nope".into())).await.unwrap());
        assert!(store.set_account_send_domain(&user.id, Some(domain.id.clone())).await.unwrap());

        store.save_send(send(&user.id, "s1")).await.unwrap().unwrap();
        store.default_send_domain(&user.id, "s1").await.unwrap();
        store.save_send(send(&user.id, "s2")).await.unwrap().unwrap();
        assert_eq!(store.set_send_domain(&user.id, "s2", None).await.unwrap(), Some(true));
        assert_eq!(store.set_send_domain(&user.id, "s2", Some("nope".into())).await.unwrap(), Some(false));
        assert_eq!(store.set_send_domain("someone else", "s2", None).await.unwrap(), None);
        let choices = store.send_domain_choices(&user.id).await.unwrap();
        assert_eq!(choices["s1"].as_deref(), Some(domain.id.as_str()));
        assert_eq!(choices["s2"], None);

        // A save of the Send through Bitwarden's API keeps the choice.
        store.save_send(send(&user.id, "s1")).await.unwrap().unwrap();
        assert_eq!(store.send_domain_of("s1").await.unwrap(), Some(Some(domain.id.clone())));

        assert!(store.delete_send_domain(&domain.id).await.unwrap());
        assert_eq!(store.send_domain_of("s1").await.unwrap(), Some(None));
        assert_eq!(store.account_send_domain(&user.id).await.unwrap(), None);
        assert!(store.send_domains().await.unwrap().is_empty());
    }
}
