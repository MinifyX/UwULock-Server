//! "Log in with a device": a new device asks to be let in, a device that is logged in already
//! answers — with the user key wrapped for the new device's public key — and the new device
//! logs in once with the code it made when it asked.

use crate::{Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

/// How long a request waits for an answer, and how long an answer waits to be used.
pub const AUTH_REQUEST_SECONDS: i64 = 15 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub id: String,
    pub user_id: String,
    /// 0 log in and unlock, 1 unlock only.
    pub kind: i64,
    pub device_id: String,
    pub device_type: i64,
    pub ip: String,
    pub public_key: String,
    pub access_code_hash: Vec<u8>,
    pub key: Option<String>,
    pub master_password_hash: Option<String>,
    pub approved: Option<bool>,
    pub response_device_id: Option<String>,
    pub created: String,
    pub responded: Option<String>,
    pub used: Option<String>,
}

const COLUMNS: &str = "id, user_id, type, device_id, device_type, ip, public_key, access_code_hash, key, \
     master_password_hash, approved, response_device_id, created, responded, used";

fn request_from(row: &Row<'_>) -> rusqlite::Result<AuthRequest> {
    Ok(AuthRequest {
        id: row.get(0)?,
        user_id: row.get(1)?,
        kind: row.get(2)?,
        device_id: row.get(3)?,
        device_type: row.get(4)?,
        ip: row.get(5)?,
        public_key: row.get(6)?,
        access_code_hash: row.get(7)?,
        key: row.get(8)?,
        master_password_hash: row.get(9)?,
        approved: row.get(10)?,
        response_device_id: row.get(11)?,
        created: row.get(12)?,
        responded: row.get(13)?,
        used: row.get(14)?,
    })
}

impl AuthRequest {
    /// Asked for less than [`AUTH_REQUEST_SECONDS`] ago.
    pub fn fresh(&self) -> bool {
        self.created > clock::in_seconds(-AUTH_REQUEST_SECONDS)
    }
}

impl Store {
    pub async fn add_auth_request(&self, request: AuthRequest) -> Result<()> {
        self.sqlite_write(move |tx| {
            tx.execute(
                &format!(
                    "INSERT INTO auth_requests ({COLUMNS}) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"
                ),
                params![
                    request.id,
                    request.user_id,
                    request.kind,
                    request.device_id,
                    request.device_type,
                    request.ip,
                    request.public_key,
                    request.access_code_hash,
                    request.key,
                    request.master_password_hash,
                    request.approved,
                    request.response_device_id,
                    request.created,
                    request.responded,
                    request.used,
                ],
            )
            .map(drop)
        })
        .await
    }

    pub async fn auth_request(&self, id: &str) -> Result<Option<AuthRequest>> {
        let id = id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!("SELECT {COLUMNS} FROM auth_requests WHERE id = ?1"))?
                .query_row([id], request_from)
                .optional()
        })
        .await
    }

    /// The user's requests of the last [`AUTH_REQUEST_SECONDS`], newest first.
    pub async fn auth_requests(&self, user_id: &str) -> Result<Vec<AuthRequest>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM auth_requests WHERE user_id = ?1 AND created > ?2 ORDER BY created DESC"
            ))?
            .query_map(params![user_id, clock::in_seconds(-AUTH_REQUEST_SECONDS)], request_from)?
            .collect()
        })
        .await
    }

    /// Answer a request of the user's that nobody answered yet. Nothing when it is not theirs,
    /// was answered, or is too old.
    pub async fn answer_auth_request(
        &self,
        user_id: &str,
        id: &str,
        approved: bool,
        key: Option<String>,
        master_password_hash: Option<String>,
        response_device_id: &str,
    ) -> Result<Option<AuthRequest>> {
        let (user_id, id, device) = (user_id.to_string(), id.to_string(), response_device_id.to_string());
        self.sqlite_write(move |tx| {
            let now = clock::now();
            let answered = tx.execute(
                "UPDATE auth_requests SET approved = ?3, key = ?4, master_password_hash = ?5, \
                 response_device_id = ?6, responded = ?7 \
                 WHERE id = ?1 AND user_id = ?2 AND approved IS NULL AND created > ?8",
                params![
                    id,
                    user_id,
                    approved,
                    key.filter(|_| approved),
                    master_password_hash.filter(|_| approved),
                    device,
                    now,
                    clock::in_seconds(-AUTH_REQUEST_SECONDS)
                ],
            )? > 0;
            if !answered {
                return Ok(None);
            }
            tx.query_row(&format!("SELECT {COLUMNS} FROM auth_requests WHERE id = ?1"), [&id], request_from).optional()
        })
        .await
    }

    /// Log in with an approved request, once: the device that asked, with the code it made.
    /// The request as it was; nothing when any of that does not hold.
    pub async fn use_auth_request(
        &self,
        id: &str,
        device_id: &str,
        access_code_hash: Vec<u8>,
    ) -> Result<Option<AuthRequest>> {
        let (id, device_id) = (id.to_string(), device_id.to_string());
        self.sqlite_write(move |tx| {
            let Some(request) = tx
                .query_row(&format!("SELECT {COLUMNS} FROM auth_requests WHERE id = ?1"), [&id], request_from)
                .optional()?
            else {
                return Ok(None);
            };
            let code_ok = crate::accounts::constant_time_eq(&request.access_code_hash, &access_code_hash);
            if !code_ok || request.device_id != device_id || request.approved != Some(true) || request.used.is_some() {
                return Ok(None);
            }
            if !request.responded.as_deref().is_some_and(|at| at > clock::in_seconds(-AUTH_REQUEST_SECONDS).as_str()) {
                return Ok(None);
            }
            tx.execute("UPDATE auth_requests SET used = ?2 WHERE id = ?1", [&id, &clock::now()])?;
            Ok(Some(request))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::{new_user, store};

    fn request(user_id: &str) -> AuthRequest {
        AuthRequest {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            kind: 0,
            device_id: "new-device".into(),
            device_type: 9,
            ip: "192.0.2.1".into(),
            public_key: "MIIB".into(),
            access_code_hash: vec![5; 32],
            key: None,
            master_password_hash: None,
            approved: None,
            response_device_id: None,
            created: clock::now(),
            responded: None,
            used: None,
        }
    }

    #[tokio::test]
    async fn an_approved_request_logs_in_once() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let asked = request(&user.id);
        store.add_auth_request(asked.clone()).await.unwrap();
        assert!(store.use_auth_request(&asked.id, "new-device", vec![5; 32]).await.unwrap().is_none(), "no answer yet");

        let other = store.create_user(new_user("other@example.com")).await.unwrap();
        assert!(
            store
                .answer_auth_request(&other.id, &asked.id, true, Some("4.k".into()), None, "d")
                .await
                .unwrap()
                .is_none()
        );
        let answered =
            store.answer_auth_request(&user.id, &asked.id, true, Some("4.k".into()), None, "d").await.unwrap().unwrap();
        assert_eq!(answered.key.as_deref(), Some("4.k"));
        assert!(
            store.answer_auth_request(&user.id, &asked.id, false, None, None, "d").await.unwrap().is_none(),
            "answered already"
        );

        assert!(store.use_auth_request(&asked.id, "elsewhere", vec![5; 32]).await.unwrap().is_none());
        assert!(store.use_auth_request(&asked.id, "new-device", vec![6; 32]).await.unwrap().is_none());
        assert!(store.use_auth_request(&asked.id, "new-device", vec![5; 32]).await.unwrap().is_some());
        assert!(store.use_auth_request(&asked.id, "new-device", vec![5; 32]).await.unwrap().is_none(), "once");
    }

    #[tokio::test]
    async fn a_denied_or_old_request_logs_nobody_in() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let denied = request(&user.id);
        store.add_auth_request(denied.clone()).await.unwrap();
        let answer = store.answer_auth_request(&user.id, &denied.id, false, Some("4.k".into()), None, "d").await;
        assert_eq!(answer.unwrap().unwrap().key, None, "a no carries no key");
        assert!(store.use_auth_request(&denied.id, "new-device", vec![5; 32]).await.unwrap().is_none());

        let mut old = request(&user.id);
        old.created = clock::in_seconds(-AUTH_REQUEST_SECONDS - 1);
        store.add_auth_request(old.clone()).await.unwrap();
        assert!(store.answer_auth_request(&user.id, &old.id, true, None, None, "d").await.unwrap().is_none());
        assert_eq!(store.auth_requests(&user.id).await.unwrap().len(), 1, "the old one is not listed");
    }
}
