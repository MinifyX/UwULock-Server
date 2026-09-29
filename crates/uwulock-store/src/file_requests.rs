//! The extras key and file requests (docs/uwu-api.md §3 and §11).
//!
//! A file request is a link somebody without an account uploads files and text to, encrypted in
//! their browser for the owner. What the server keeps is ciphertext and bookkeeping: how many
//! submissions and files, how large, until when. The files lie at `file-requests/<request>/<id>`
//! in the data directory; taking one into an item moves it among the attachments.

use crate::attachments::{Owner, touch_cipher};
use crate::{Cipher, Result, Store, clock};
use rusqlite::{OptionalExtension, Row, params};

/// The extras key of an account, as it is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtrasKey {
    /// Under the user key; none after an official client rotated it.
    pub user_key_wrapped: Option<String>,
    /// For the account's public key.
    pub public_key_wrapped: String,
    /// The account's public key it was wrapped for.
    pub public_key: String,
    pub revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileRequest {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub link_secret: Option<String>,
    pub public_info: String,
    pub password_hash: Option<String>,
    pub expiration: String,
    pub deletion: String,
    pub max_submissions: Option<i64>,
    pub submission_count: i64,
    pub max_files: i64,
    pub max_file_bytes: i64,
    pub text_allowed: bool,
    pub send_domain_id: Option<String>,
    pub disabled: bool,
    pub created: String,
    pub revision: String,
}

/// A request with what the owner's list shows beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRequestSummary {
    pub request: FileRequest,
    /// Completed submissions the owner has not looked at.
    pub unseen: i64,
    /// Bytes of its files.
    pub bytes: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Submission {
    pub id: String,
    pub request_id: String,
    pub wrapped_key: String,
    pub sender: Option<String>,
    pub text: Option<String>,
    pub created: String,
    pub completed: Option<String>,
    pub seen: bool,
    pub files: Vec<RequestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestFile {
    pub id: String,
    pub file_name: String,
    pub key: String,
    pub size: i64,
    pub uploaded: bool,
}

/// Why a submission could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Expired, disabled, full, or not there at all: the same to the uploader.
    Gone,
    /// The owner's storage is full.
    Quota,
}

/// Submissions that were started but never completed go after this long.
pub const INCOMPLETE_SECONDS: i64 = 24 * 60 * 60;
/// The owner hears of new submissions at most this often per request.
pub const MAIL_SECONDS: i64 = 15 * 60;

const REQUEST_COLUMNS: &str = "id, user_id, name, link_secret, public_info, password_hash, expiration, deletion, \
     max_submissions, submission_count, max_files, max_file_bytes, text_allowed, send_domain_id, disabled, created, \
     revision";

fn request_from(row: &Row<'_>) -> rusqlite::Result<FileRequest> {
    Ok(FileRequest {
        id: row.get(0)?,
        user_id: row.get(1)?,
        name: row.get(2)?,
        link_secret: row.get(3)?,
        public_info: row.get(4)?,
        password_hash: row.get(5)?,
        expiration: row.get(6)?,
        deletion: row.get(7)?,
        max_submissions: row.get(8)?,
        submission_count: row.get(9)?,
        max_files: row.get(10)?,
        max_file_bytes: row.get(11)?,
        text_allowed: row.get(12)?,
        send_domain_id: row.get(13)?,
        disabled: row.get(14)?,
        created: row.get(15)?,
        revision: row.get(16)?,
    })
}

/// What a file request needs of the account's storage beside everything else: attachments of
/// its own items, the files of its Sends, and every file uploaded (or on its way) to its
/// requests.
const USER_BYTES: &str = "SELECT \
     (SELECT coalesce(sum(a.size), 0) FROM attachments a JOIN ciphers c ON c.id = a.cipher_id WHERE c.user_id = ?1) \
     + (SELECT coalesce(sum(CAST(coalesce(json_extract(data, '$.size'), 0) AS INTEGER)), 0) FROM sends \
        WHERE user_id = ?1 AND type = 1) \
     + (SELECT coalesce(sum(f.size), 0) FROM file_request_files f \
        JOIN file_request_submissions s ON s.id = f.submission_id \
        JOIN file_requests r ON r.id = s.request_id WHERE r.user_id = ?1) \
     + (SELECT coalesce(sum(size), 0) FROM cipher_versions WHERE user_id = ?1) \
     + (SELECT coalesce(sum(length(i.data)), 0) FROM own_icons i JOIN ciphers c ON c.id = i.cipher_id \
        WHERE c.user_id = ?1) \
     + (SELECT coalesce(sum(length(blob) + length(nonce)), 0) FROM suite_records WHERE user_id = ?1)";

fn files_of(conn: &rusqlite::Connection, submission_id: &str) -> rusqlite::Result<Vec<RequestFile>> {
    conn.prepare_cached(
        "SELECT id, file_name, key, size, uploaded FROM file_request_files WHERE submission_id = ?1 ORDER BY rowid",
    )?
    .query_map([submission_id], |row| {
        Ok(RequestFile {
            id: row.get(0)?,
            file_name: row.get(1)?,
            key: row.get(2)?,
            size: row.get(3)?,
            uploaded: row.get(4)?,
        })
    })?
    .collect()
}

fn submission_from(row: &Row<'_>) -> rusqlite::Result<Submission> {
    Ok(Submission {
        id: row.get(0)?,
        request_id: row.get(1)?,
        wrapped_key: row.get(2)?,
        sender: row.get(3)?,
        text: row.get(4)?,
        created: row.get(5)?,
        completed: row.get(6)?,
        seen: row.get(7)?,
        files: Vec::new(),
    })
}

const SUBMISSION_COLUMNS: &str = "id, request_id, wrapped_key, sender, text, created, completed, seen";

impl Store {
    // ── The extras key ─────────────────────────────────────

    /// The account's extras key, and whether it is lost: the account's public key is not the
    /// one it was wrapped for any more.
    pub async fn extras_key(&self, user_id: &str) -> Result<Option<(ExtrasKey, bool)>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT e.user_key_wrapped, e.public_key_wrapped, e.public_key, e.revision, \
                 coalesce(u.public_key, '') != e.public_key \
                 FROM extras_keys e JOIN users u ON u.id = e.user_id WHERE e.user_id = ?1",
                [user_id],
                |row| {
                    Ok((
                        ExtrasKey {
                            user_key_wrapped: row.get(0)?,
                            public_key_wrapped: row.get(1)?,
                            public_key: row.get(2)?,
                            revision: row.get(3)?,
                        },
                        row.get(4)?,
                    ))
                },
            )
            .optional()
        })
        .await
    }

    /// Keeps a new extras key. False when the account has one already (another client was
    /// quicker).
    pub async fn create_extras_key(&self, user_id: &str, key: ExtrasKey) -> Result<bool> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            // A lost one makes way: its wraps open nothing any more.
            tx.execute(
                "DELETE FROM extras_keys WHERE user_id = ?1 AND public_key != \
                 (SELECT coalesce(public_key, '') FROM users WHERE id = ?1)",
                [&user_id],
            )?;
            Ok(tx.execute(
                "INSERT INTO extras_keys (user_id, user_key_wrapped, public_key_wrapped, public_key, revision) \
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (user_id) DO NOTHING",
                params![user_id, key.user_key_wrapped, key.public_key_wrapped, key.public_key, key.revision],
            )? == 1)
        })
        .await
    }

    /// The wrap under the user key again, after an official rotation dropped it. False when
    /// there is one.
    pub async fn set_extras_user_wrap(&self, user_id: &str, wrapped: &str) -> Result<bool> {
        let (user_id, wrapped) = (user_id.to_string(), wrapped.to_string());
        self.sqlite_write(move |tx| {
            Ok(tx.execute(
                "UPDATE extras_keys SET user_key_wrapped = ?2, revision = ?3 \
                 WHERE user_id = ?1 AND user_key_wrapped IS NULL",
                params![user_id, wrapped, clock::now()],
            )? == 1)
        })
        .await
    }

    /// The wrap under the user key goes: what a rotation by an official client does (in its own
    /// transaction), for the tests of what comes after.
    pub async fn drop_extras_user_wrap(&self, user_id: &str) -> Result<()> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("UPDATE extras_keys SET user_key_wrapped = NULL WHERE user_id = ?1", [user_id]).map(drop)
        })
        .await
    }

    /// The extras key goes, and what was under it: own icons, the stored health report, the
    /// labels and link secrets of file requests (their links keep working; the owner just cannot
    /// show them again).
    pub async fn delete_extras_key(&self, user_id: &str) -> Result<()> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute("DELETE FROM extras_keys WHERE user_id = ?1", [&user_id])?;
            tx.execute(
                "DELETE FROM own_icons WHERE key_type = 'extras' AND cipher_id IN (SELECT id FROM ciphers WHERE user_id = ?1)",
                [&user_id],
            )?;
            tx.execute("DELETE FROM health_reports WHERE user_id = ?1", [&user_id])?;
            tx.execute("DELETE FROM suite_records WHERE user_id = ?1", [&user_id])?;
            tx.execute("DELETE FROM suite_spaces WHERE user_id = ?1", [&user_id])?;
            tx.execute(
                "UPDATE file_requests SET name = NULL, link_secret = NULL, revision = ?2 WHERE user_id = ?1",
                params![user_id, clock::now()],
            )?;
            Ok(())
        })
        .await
    }

    // ── The owner's side ───────────────────────────────────

    /// The account's requests, newest first.
    pub async fn file_requests(&self, user_id: &str) -> Result<Vec<FileRequestSummary>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            let columns = REQUEST_COLUMNS.split(", ").map(|c| format!("r.{c}")).collect::<Vec<_>>().join(", ");
            conn.prepare_cached(&format!(
                "SELECT {columns}, \
                 (SELECT count(*) FROM file_request_submissions s WHERE s.request_id = r.id \
                  AND s.completed IS NOT NULL AND NOT s.seen), \
                 (SELECT coalesce(sum(f.size), 0) FROM file_request_files f \
                  JOIN file_request_submissions s ON s.id = f.submission_id WHERE s.request_id = r.id) \
                 FROM file_requests r WHERE r.user_id = ?1 ORDER BY r.created DESC"
            ))?
            .query_map([user_id], |row| {
                Ok(FileRequestSummary { request: request_from(row)?, unseen: row.get(17)?, bytes: row.get(18)? })
            })?
            .collect()
        })
        .await
    }

    /// One of the account's requests.
    pub async fn file_request(&self, user_id: &str, id: &str) -> Result<Option<FileRequestSummary>> {
        let id = id.to_string();
        Ok(self.file_requests(user_id).await?.into_iter().find(|summary| summary.request.id == id))
    }

    /// How many requests the account has.
    pub async fn file_request_count(&self, user_id: &str) -> Result<i64> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.query_row("SELECT count(*) FROM file_requests WHERE user_id = ?1", [user_id], |row| row.get(0))
        })
        .await
    }

    /// A new request, unless the account has `most` already. False then.
    pub async fn create_file_request(&self, request: FileRequest, most: i64) -> Result<bool> {
        self.sqlite_write(move |tx| {
            let count: i64 =
                tx.query_row("SELECT count(*) FROM file_requests WHERE user_id = ?1", [&request.user_id], |row| {
                    row.get(0)
                })?;
            if count >= most {
                return Ok(false);
            }
            tx.execute(
                &format!(
                    "INSERT INTO file_requests ({REQUEST_COLUMNS}) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"
                ),
                params![
                    request.id,
                    request.user_id,
                    request.name,
                    request.link_secret,
                    request.public_info,
                    request.password_hash,
                    request.expiration,
                    request.deletion,
                    request.max_submissions,
                    request.submission_count,
                    request.max_files,
                    request.max_file_bytes,
                    request.text_allowed,
                    request.send_domain_id,
                    request.disabled,
                    request.created,
                    request.revision,
                ],
            )?;
            Ok(true)
        })
        .await
    }

    /// The owner changed a request. False when it is not theirs.
    pub async fn update_file_request(&self, request: FileRequest) -> Result<bool> {
        self.sqlite_write(move |tx| {
            Ok(tx.execute(
                "UPDATE file_requests SET name = ?3, link_secret = ?4, public_info = ?5, password_hash = ?6, \
                 expiration = ?7, deletion = ?8, max_submissions = ?9, max_files = ?10, max_file_bytes = ?11, \
                 text_allowed = ?12, send_domain_id = ?13, disabled = ?14, revision = ?15 \
                 WHERE id = ?1 AND user_id = ?2",
                params![
                    request.id,
                    request.user_id,
                    request.name,
                    request.link_secret,
                    request.public_info,
                    request.password_hash,
                    request.expiration,
                    request.deletion,
                    request.max_submissions,
                    request.max_files,
                    request.max_file_bytes,
                    request.text_allowed,
                    request.send_domain_id,
                    request.disabled,
                    request.revision,
                ],
            )? == 1)
        })
        .await
    }

    /// The request goes, with its submissions; its files are the caller's to remove. False when
    /// it is not theirs.
    pub async fn delete_file_request(&self, user_id: &str, id: &str) -> Result<bool> {
        let (user_id, id) = (user_id.to_string(), id.to_string());
        self.sqlite_write(move |tx| {
            Ok(tx.execute("DELETE FROM file_requests WHERE id = ?1 AND user_id = ?2", [id, user_id])? == 1)
        })
        .await
    }

    /// The completed submissions of a request, newest first, with their files. Only for the
    /// request's owner; nothing for anybody else.
    pub async fn submissions(&self, user_id: &str, request_id: &str) -> Result<Option<Vec<Submission>>> {
        let (user_id, request_id) = (user_id.to_string(), request_id.to_string());
        self.sqlite_read(move |conn| {
            let owned: bool = conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM file_requests WHERE id = ?1 AND user_id = ?2)",
                [&request_id, &user_id],
                |row| row.get(0),
            )?;
            if !owned {
                return Ok(None);
            }
            let mut submissions: Vec<Submission> = conn
                .prepare_cached(&format!(
                    "SELECT {SUBMISSION_COLUMNS} FROM file_request_submissions \
                     WHERE request_id = ?1 AND completed IS NOT NULL ORDER BY completed DESC"
                ))?
                .query_map([&request_id], submission_from)?
                .collect::<rusqlite::Result<_>>()?;
            for submission in &mut submissions {
                submission.files = files_of(conn, &submission.id)?;
            }
            Ok(Some(submissions))
        })
        .await
    }

    /// A completed submission is seen, or goes. False when it is not the owner's.
    pub async fn mark_submission(&self, user_id: &str, request_id: &str, id: &str, delete: bool) -> Result<bool> {
        let (user_id, request_id, id) = (user_id.to_string(), request_id.to_string(), id.to_string());
        self.sqlite_write(move |tx| {
            let sql = if delete {
                "DELETE FROM file_request_submissions WHERE id = ?1 AND request_id = ?2 AND completed IS NOT NULL \
                 AND request_id IN (SELECT id FROM file_requests WHERE user_id = ?3)"
            } else {
                "UPDATE file_request_submissions SET seen = 1 WHERE id = ?1 AND request_id = ?2 \
                 AND completed IS NOT NULL AND request_id IN (SELECT id FROM file_requests WHERE user_id = ?3)"
            };
            Ok(tx.execute(sql, params![id, request_id, user_id])? == 1)
        })
        .await
    }

    /// A file of one of the owner's completed submissions.
    pub async fn submission_file(
        &self,
        user_id: &str,
        request_id: &str,
        submission_id: &str,
        file_id: &str,
    ) -> Result<Option<RequestFile>> {
        let user_id = user_id.to_string();
        let (request_id, submission_id, file_id) =
            (request_id.to_string(), submission_id.to_string(), file_id.to_string());
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT f.id, f.file_name, f.key, f.size, f.uploaded FROM file_request_files f \
                 JOIN file_request_submissions s ON s.id = f.submission_id \
                 JOIN file_requests r ON r.id = s.request_id \
                 WHERE f.id = ?1 AND s.id = ?2 AND r.id = ?3 AND r.user_id = ?4 AND s.completed IS NOT NULL",
                params![file_id, submission_id, request_id, user_id],
                |row| {
                    Ok(RequestFile {
                        id: row.get(0)?,
                        file_name: row.get(1)?,
                        key: row.get(2)?,
                        size: row.get(3)?,
                        uploaded: row.get(4)?,
                    })
                },
            )
            .optional()
        })
        .await
    }

    /// Takes a file of a submission into an item as an attachment — its file was moved into
    /// the item's folder already, under `attachment_id`. The item as it is afterwards; nothing
    /// when the item is not `owner`'s or the file not the user's.
    #[allow(clippy::too_many_arguments)]
    pub async fn take_request_file(
        &self,
        user_id: &str,
        submission_id: &str,
        file_id: &str,
        owner: &Owner,
        cipher_id: &str,
        attachment_id: &str,
        file_name: &str,
        key: &str,
    ) -> Result<Option<Cipher>> {
        let owned = owner.clone();
        let (user_id, submission_id, file_id) = (user_id.to_string(), submission_id.to_string(), file_id.to_string());
        let (cipher_id, attachment_id) = (cipher_id.to_string(), attachment_id.to_string());
        let (file_name, key) = (file_name.to_string(), key.to_string());
        let changed = self
            .sqlite_write(move |tx| {
                let size: Option<i64> = tx
                    .query_row(
                        "SELECT f.size FROM file_request_files f \
                         JOIN file_request_submissions s ON s.id = f.submission_id \
                         JOIN file_requests r ON r.id = s.request_id \
                         WHERE f.id = ?1 AND s.id = ?2 AND r.user_id = ?3 AND f.uploaded",
                        params![file_id, submission_id, user_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                let Some(size) = size else { return Ok(None) };
                let Some(changed) = touch_cipher(tx, &owned, &cipher_id)? else { return Ok(None) };
                tx.execute(
                    "INSERT INTO attachments (id, cipher_id, file_name, key, size, uploaded, created) \
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                    params![attachment_id, cipher_id, file_name, key, size, clock::now()],
                )?;
                tx.execute("DELETE FROM file_request_files WHERE id = ?1", [&file_id])?;
                Ok(Some(changed))
            })
            .await?;
        let Some((cipher, users)) = changed else { return Ok(None) };
        for user in &users {
            self.forget_session_of(user);
        }
        Ok(Some(cipher))
    }

    /// Submissions to the account's requests that arrived and were not looked at yet.
    pub async fn unseen_submissions(&self, user_id: &str) -> Result<i64> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            conn.prepare_cached(
                "SELECT count(*) FROM file_request_submissions s JOIN file_requests r ON r.id = s.request_id \
                 WHERE r.user_id = ?1 AND s.completed IS NOT NULL AND NOT s.seen",
            )?
            .query_row([user_id], |row| row.get(0))
        })
        .await
    }

    /// Bytes the account's attachments, Send files, file requests, versions and own icons take
    /// together.
    pub async fn storage_used(&self, user_id: &str) -> Result<i64> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| conn.query_row(USER_BYTES, [user_id], |row| row.get(0))).await
    }

    /// Bytes of every file-request file on the server, for the admin portal and the metrics.
    pub async fn file_request_bytes(&self) -> Result<i64> {
        self.sqlite_read(|conn| {
            conn.query_row("SELECT coalesce(sum(size), 0) FROM file_request_files WHERE uploaded", [], |row| row.get(0))
        })
        .await
    }

    // ── The uploader's side ────────────────────────────────

    /// A request by its id, as the public page sees it: only while it is open (not expired,
    /// disabled or full).
    pub async fn open_file_request(&self, id: &str) -> Result<Option<FileRequest>> {
        let id = id.to_string();
        let now = clock::now();
        self.sqlite_read(move |conn| {
            conn.query_row(
                &format!(
                    "SELECT {REQUEST_COLUMNS} FROM file_requests WHERE id = ?1 AND NOT disabled AND expiration > ?2 \
                     AND (max_submissions IS NULL OR submission_count < max_submissions)"
                ),
                params![id, now],
                request_from,
            )
            .optional()
        })
        .await
    }

    /// Starts a submission with its files announced, if the request still takes one: open, with
    /// submissions left (those on their way count), and room in the owner's storage (`limit`
    /// bytes, none for no limit).
    pub async fn start_submission(&self, submission: Submission, limit: Option<i64>) -> Result<Result<(), Refusal>> {
        let now = clock::now();
        self.sqlite_write(move |tx| {
            let request = tx
                .query_row(
                    &format!(
                        "SELECT {REQUEST_COLUMNS} FROM file_requests WHERE id = ?1 AND NOT disabled AND expiration > ?2"
                    ),
                    params![submission.request_id, now],
                    request_from,
                )
                .optional()?;
            let Some(request) = request else { return Ok(Err(Refusal::Gone)) };
            if let Some(most) = request.max_submissions {
                let started: i64 = tx.query_row(
                    "SELECT count(*) FROM file_request_submissions WHERE request_id = ?1",
                    [&request.id],
                    |row| row.get(0),
                )?;
                if started >= most {
                    return Ok(Err(Refusal::Gone));
                }
            }
            if let Some(limit) = limit {
                let used: i64 = tx.query_row(USER_BYTES, [&request.user_id], |row| row.get(0))?;
                let adding: i64 = submission.files.iter().map(|file| file.size).sum();
                if used + adding > limit {
                    return Ok(Err(Refusal::Quota));
                }
            }
            tx.execute(
                &format!("INSERT INTO file_request_submissions ({SUBMISSION_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0)"),
                params![submission.id, submission.request_id, submission.wrapped_key, submission.sender, submission.text, now],
            )?;
            let mut insert = tx.prepare_cached(
                "INSERT INTO file_request_files (id, submission_id, file_name, key, size, uploaded) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            )?;
            for file in &submission.files {
                insert.execute(params![file.id, submission.id, file.file_name, file.key, file.size])?;
            }
            Ok(Ok(()))
        })
        .await
    }

    /// A file of a submission still on its way, with its size: what an upload may bring. Not
    /// one that arrived already: it is never written again.
    pub async fn pending_file(&self, request_id: &str, submission_id: &str, file_id: &str) -> Result<Option<i64>> {
        let (request_id, submission_id, file_id) =
            (request_id.to_string(), submission_id.to_string(), file_id.to_string());
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT f.size FROM file_request_files f JOIN file_request_submissions s ON s.id = f.submission_id \
                 WHERE f.id = ?1 AND s.id = ?2 AND s.request_id = ?3 AND s.completed IS NULL AND NOT f.uploaded",
                params![file_id, submission_id, request_id],
                |row| row.get(0),
            )
            .optional()
        })
        .await
    }

    pub async fn request_file_uploaded(&self, submission_id: &str, file_id: &str) -> Result<()> {
        let (submission_id, file_id) = (submission_id.to_string(), file_id.to_string());
        self.sqlite_write(move |tx| {
            tx.execute(
                "UPDATE file_request_files SET uploaded = 1 WHERE id = ?1 AND submission_id = ?2",
                [file_id, submission_id],
            )
            .map(drop)
        })
        .await
    }

    /// The uploader is done. `Ok(Some((request, mail)))`: the request as it is now, and whether
    /// its owner should get a mail about it (the last one was long enough ago). `Ok(None)`: no
    /// such submission on its way. `Err(())` inside: a file is still missing.
    #[allow(clippy::type_complexity)]
    pub async fn complete_submission(
        &self,
        request_id: &str,
        id: &str,
    ) -> Result<Option<std::result::Result<(FileRequest, bool), ()>>> {
        let (request_id, id) = (request_id.to_string(), id.to_string());
        let now = clock::now();
        let mail_before = clock::in_seconds(-MAIL_SECONDS);
        self.sqlite_write(move |tx| {
            let pending: Option<i64> = tx
                .query_row(
                    "SELECT (SELECT count(*) FROM file_request_files WHERE submission_id = s.id AND NOT uploaded) \
                     FROM file_request_submissions s WHERE s.id = ?1 AND s.request_id = ?2 AND s.completed IS NULL",
                    [&id, &request_id],
                    |row| row.get(0),
                )
                .optional()?;
            match pending {
                None => return Ok(None),
                Some(missing) if missing > 0 => return Ok(Some(Err(()))),
                Some(_) => {}
            }
            tx.execute("UPDATE file_request_submissions SET completed = ?2 WHERE id = ?1", [&id, &now])?;
            let mail = tx.execute(
                "UPDATE file_requests SET mailed = ?2 WHERE id = ?1 AND (mailed IS NULL OR mailed < ?3)",
                params![request_id, now, mail_before],
            )? == 1;
            tx.execute(
                "UPDATE file_requests SET submission_count = submission_count + 1, revision = ?2 WHERE id = ?1",
                [&request_id, &now],
            )?;
            let request = tx.query_row(
                &format!("SELECT {REQUEST_COLUMNS} FROM file_requests WHERE id = ?1"),
                [&request_id],
                request_from,
            )?;
            crate::accounts::bump_revision(tx, &request.user_id)?;
            Ok(Some(Ok((request, mail))))
        })
        .await
    }

    /// What is past its time: requests after their deletion date, with everything in them, and
    /// submissions nobody completed within a day. The ids of the requests that went, and of the
    /// submissions, whose files are the caller's to remove.
    pub async fn sweep_file_requests(&self) -> Result<(Vec<String>, Vec<(String, Vec<String>)>)> {
        let now = clock::now();
        let stale = clock::in_seconds(-INCOMPLETE_SECONDS);
        self.sqlite_write(move |tx| {
            let requests: Vec<String> = tx
                .prepare("SELECT id FROM file_requests WHERE deletion <= ?1")?
                .query_map([&now], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            tx.execute("DELETE FROM file_requests WHERE deletion <= ?1", [&now])?;
            let submissions: Vec<(String, String)> = tx
                .prepare(
                    "SELECT request_id, id FROM file_request_submissions WHERE completed IS NULL AND created <= ?1",
                )?
                .query_map([&stale], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            let mut files = Vec::new();
            for (request_id, id) in submissions {
                files.push((request_id, files_of(tx, &id)?.into_iter().map(|file| file.id).collect()));
                tx.execute("DELETE FROM file_request_submissions WHERE id = ?1", [&id])?;
            }
            Ok((requests, files))
        })
        .await
    }

    /// Whether a file on disk still belongs to a submission of `request_id`, for the sweep.
    pub async fn request_file_exists(&self, request_id: &str, id: &str) -> Result<bool> {
        let (request_id, id) = (request_id.to_string(), id.to_string());
        self.sqlite_read(move |conn| {
            conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM file_request_files f JOIN file_request_submissions s \
                 ON s.id = f.submission_id WHERE f.id = ?1 AND s.request_id = ?2)",
                [id, request_id],
                |row| row.get(0),
            )
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Options, Store};

    async fn owner(store: &Store) -> String {
        store.create_user(crate::accounts::tests::new_user("nyu@example.com")).await.unwrap().id
    }

    fn request(user_id: &str, id: &str) -> FileRequest {
        FileRequest {
            id: id.into(),
            user_id: user_id.into(),
            name: Some("2.name".into()),
            link_secret: Some("2.secret".into()),
            public_info: "2.info".into(),
            expiration: clock::in_seconds(3600),
            deletion: clock::in_seconds(3600 + 30 * 86_400),
            max_submissions: Some(1),
            max_files: 2,
            max_file_bytes: 1000,
            text_allowed: true,
            created: clock::now(),
            revision: clock::now(),
            ..FileRequest::default()
        }
    }

    fn submission(request_id: &str, id: &str, size: i64) -> Submission {
        Submission {
            id: id.into(),
            request_id: request_id.into(),
            wrapped_key: "4.key".into(),
            files: vec![RequestFile {
                id: format!("{id}-f"),
                file_name: "2.f".into(),
                key: "2.k".into(),
                size,
                uploaded: false,
            }],
            ..Submission::default()
        }
    }

    #[tokio::test]
    async fn a_request_takes_what_it_allows_and_then_closes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("db"), &Options { readers: 1 }).unwrap();
        let user = owner(&store).await;
        assert!(store.create_file_request(request(&user, "r1"), 1).await.unwrap());
        assert!(!store.create_file_request(request(&user, "r2"), 1).await.unwrap(), "one per account here");

        assert_eq!(store.start_submission(submission("r1", "s1", 600), Some(500)).await.unwrap(), Err(Refusal::Quota));
        assert_eq!(store.start_submission(submission("r1", "s1", 600), None).await.unwrap(), Ok(()));
        assert_eq!(store.storage_used(&user).await.unwrap(), 600, "counted while on its way");
        assert_eq!(store.start_submission(submission("r1", "s2", 1), None).await.unwrap(), Err(Refusal::Gone), "full");
        assert_eq!(store.complete_submission("r1", "s1").await.unwrap(), Some(Err(())), "a file is missing");
        assert_eq!(store.pending_file("r1", "s1", "s1-f").await.unwrap(), Some(600));
        store.request_file_uploaded("s1", "s1-f").await.unwrap();
        let (done, mail) = store.complete_submission("r1", "s1").await.unwrap().unwrap().unwrap();
        assert!(mail && done.submission_count == 1);
        assert_eq!(store.complete_submission("r1", "s1").await.unwrap(), None, "once");
        assert!(store.open_file_request("r1").await.unwrap().is_none(), "closed when full");

        let listed = store.submissions(&user, "r1").await.unwrap().unwrap();
        assert_eq!(listed[0].files.len(), 1);
        assert!(store.submissions("somebody else", "r1").await.unwrap().is_none());
        let summary = store.file_request(&user, "r1").await.unwrap().unwrap();
        assert_eq!((summary.unseen, summary.bytes), (1, 600));
        assert!(store.mark_submission(&user, "r1", "s1", false).await.unwrap());
        assert_eq!(store.file_request(&user, "r1").await.unwrap().unwrap().unseen, 0);

        store.delete_extras_key(&user).await.unwrap();
        let labels = store.file_request(&user, "r1").await.unwrap().unwrap().request;
        assert!(labels.name.is_none() && labels.link_secret.is_none(), "the labels go with the extras key");
        assert!(store.delete_file_request(&user, "r1").await.unwrap());
        assert_eq!(store.storage_used(&user).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn the_extras_key_is_made_once_and_lost_with_the_key_pair() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_sqlite(&dir.path().join("db"), &Options { readers: 1 }).unwrap();
        let user = owner(&store).await;
        let public = store.user(&user).await.unwrap().unwrap().public_key.unwrap_or_default();
        let key = |wrapped: &str| ExtrasKey {
            user_key_wrapped: Some(wrapped.into()),
            public_key_wrapped: "4.x".into(),
            public_key: public.clone(),
            revision: clock::now(),
        };
        assert!(store.create_extras_key(&user, key("2.a")).await.unwrap());
        assert!(!store.create_extras_key(&user, key("2.b")).await.unwrap(), "the second client loses");
        assert!(!store.set_extras_user_wrap(&user, "2.c").await.unwrap(), "there is one");
        let (found, lost) = store.extras_key(&user).await.unwrap().unwrap();
        assert_eq!((found.user_key_wrapped.as_deref(), lost), (Some("2.a"), false));

        store.update_user(&user, |user| user.public_key = Some("another key".into())).await.unwrap();
        assert!(store.extras_key(&user).await.unwrap().unwrap().1, "lost");
        assert!(
            store.create_extras_key(&user, ExtrasKey { public_key: "another key".into(), ..key("2.d") }).await.unwrap()
        );
    }
}
