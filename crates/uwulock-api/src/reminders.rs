//! Reminders to renew a password (docs/uwu-api.md §10): set per item, after a number of months
//! or on a day. The server keeps only the item's id and the day, and the mail it sends when one is
//! due names no item — the web vault shows which.

use crate::auth::Session;
use crate::ciphers::{Found, visible};
use crate::errors::{ApiError, ApiResult};
use crate::{AppState, json as out};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uwulock_mail::{Language, Mail};
use uwulock_store::Reminder;
use uwulock_store::reminders::{add_months, day, today};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/reminders", get(list))
        .route("/uwu/v1/reminders/{cipher}", axum::routing::put(set).delete(remove))
}

fn reminder_json(reminder: &Reminder, today: &str) -> Value {
    json!({
        "object": "reminder",
        "cipherId": reminder.cipher_id,
        "due": reminder.due,
        "everyMonths": reminder.every_months,
        "isDue": reminder.due.as_str() <= today,
        "mailedDate": reminder.mailed,
    })
}

async fn list(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    Ok(Json(list_json(&state, &session.user.id).await?))
}

/// The account's reminders as `GET /uwu/v1/reminders` lists them; the delta sync gives the same.
pub(crate) async fn list_json(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let reminders = state.store.reminders(user_id).await?;
    let today = day(today());
    Ok(out::list(reminders.iter().map(|reminder| reminder_json(reminder, &today)).collect()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Set {
    #[serde(default)]
    due: Option<String>,
    #[serde(default)]
    every_months: Option<i64>,
}

fn parse_day(text: &str) -> Option<time::Date> {
    time::Date::parse(text, time::macros::format_description!("[year]-[month]-[day]")).ok()
}

/// The day a login's password was last changed, else the day the item was made.
fn base_day(found: &Found) -> Option<time::Date> {
    let cipher = match found {
        Found::Own(cipher) => cipher,
        Found::Org(item) => &item.cipher,
    };
    let changed = serde_json::from_str::<Value>(&cipher.data)
        .ok()
        .and_then(|data| data.get("passwordRevisionDate").and_then(Value::as_str).map(str::to_string));
    changed
        .as_deref()
        .and_then(uwulock_store::clock::parse)
        .or_else(|| uwulock_store::clock::parse(&cipher.created))
        .map(|when| when.date())
}

async fn set(
    State(state): State<AppState>,
    session: Session,
    Path(cipher): Path<String>,
    Json(body): Json<Set>,
) -> ApiResult<Json<Value>> {
    let found = visible(&state, &session, &cipher).await?;
    if body.every_months.is_some_and(|months| !(1..=60).contains(&months)) {
        return Err(ApiError::bad("A reminder repeats after 1 to 60 months.").code("invalid"));
    }
    let due = match (&body.due, body.every_months) {
        (Some(due), _) => {
            parse_day(due).ok_or_else(|| ApiError::bad("The day is written YYYY-MM-DD.").code("invalid"))?
        }
        (None, Some(months)) => {
            let base =
                base_day(&found).ok_or_else(|| ApiError::bad("The item has no date to count from.").code("invalid"))?;
            add_months(base, months as u32)
        }
        (None, None) => return Err(ApiError::bad("A reminder needs a day or a number of months.").code("invalid")),
    };
    let reminder = Reminder { cipher_id: cipher.clone(), due: day(due), every_months: body.every_months, mailed: None };
    state.store.set_reminder(&session.user.id, reminder).await?;
    crate::notify::live(&state, &session.user.id, Some(&session), uwulock_notify::realtime::Live::changed("uwu"));
    let saved = state
        .store
        .reminders(&session.user.id)
        .await?
        .into_iter()
        .find(|reminder| reminder.cipher_id == cipher)
        .ok_or_else(crate::ciphers::not_visible)?;
    Ok(Json(reminder_json(&saved, &day(today()))))
}

async fn remove(State(state): State<AppState>, session: Session, Path(cipher): Path<String>) -> ApiResult<StatusCode> {
    visible(&state, &session, &cipher).await?;
    state.store.delete_reminder(&session.user.id, &cipher).await?;
    crate::notify::live(&state, &session.user.id, Some(&session), uwulock_notify::realtime::Live::changed("uwu"));
    Ok(StatusCode::OK)
}

/// Every hour: one mail per account for the reminders that became due, once per due date, and
/// a realtime `reminderDue` notice to the account's devices. Without a mail server only the
/// notice. Hidden ones (travel mode) wait.
pub async fn tend(state: &AppState) {
    // Switched off, nothing is mailed; the reminders wait, and the ones due by then come when
    // it is on again.
    if !state.feature(crate::Feature::Reminders) {
        return;
    }
    let today = day(today());
    let due = match state.store.reminders_to_mail(&today).await {
        Ok(due) => due,
        Err(error) => {
            tracing::warn!(%error, "the reminders could not be read");
            return;
        }
    };
    for (user_id, ciphers) in due {
        let Ok(Some(user)) = state.store.user(&user_id).await else { continue };
        let notice = uwulock_notify::realtime::Live::Notice { kind: "reminderDue", id: None };
        crate::notify::live(state, &user_id, None, notice);
        if !state.mailer.enabled() {
            if let Err(error) = state.store.reminders_mailed(&user_id, ciphers, &today).await {
                tracing::warn!(%error, "a due reminder could not be noted");
            }
            continue;
        }
        let mail = Mail::ReminderDue {
            count: ciphers.len(),
            link: format!("{}/#/vault?due=1", state.config.public.trim_end_matches('/')),
        };
        match state.mailer.send(&user.email, &mail, Language::from_code(&user.language)).await {
            Ok(()) => {
                if let Err(error) = state.store.reminders_mailed(&user_id, ciphers, &today).await {
                    tracing::warn!(%error, "a reminder mail could not be noted");
                }
            }
            Err(error) => tracing::warn!(%error, "a reminder mail did not go out"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use axum::http::StatusCode;
    use serde_json::json;

    #[tokio::test]
    async fn reminders_are_set_listed_and_mailed_without_the_item() {
        let server = TestServer::new().await;
        let nyu = server.account("nyu@example.com").await;
        let other = server.account("other@example.com").await;
        let item = json!({"type": 1, "name": "2.secret-name|a|a", "login": {"password": "2.p|p|p", "passwordRevisionDate": "2026-01-31T10:00:00Z"}});
        let id = json(server.call("POST", "/api/ciphers", Some(&nyu.token), item).await).await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let path = format!("/uwu/v1/reminders/{id}");

        let months = json(server.call("PUT", &path, Some(&nyu.token), json!({"everyMonths": 1})).await).await;
        assert_eq!((months["due"].as_str(), months["everyMonths"].as_i64()), (Some("2026-02-28"), Some(1)));
        assert_eq!(months["isDue"], true);
        for bad in [json!({}), json!({"everyMonths": 61}), json!({"due": "31.01.2027"})] {
            let response = server.call("PUT", &path, Some(&nyu.token), bad).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        assert_eq!(
            server.call("PUT", &path, Some(&other.token), json!({"everyMonths": 3})).await.status(),
            StatusCode::NOT_FOUND,
            "not theirs"
        );

        let due = |server: &TestServer| {
            server.mails().into_iter().filter(|mail| mail.subject.contains("fällig")).collect::<Vec<_>>()
        };
        crate::reminders::tend(&server.state).await;
        let mails = due(&server);
        assert_eq!(mails.len(), 1);
        assert_eq!(mails[0].to, "nyu@example.com");
        assert!(mails[0].text.contains("/#/vault?due=1"));
        assert!(!mails[0].text.contains("secret-name"), "the mail names no item");
        crate::reminders::tend(&server.state).await;
        assert_eq!(due(&server).len(), 1, "once per due date");

        let listed = json(server.get_as(&nyu.token, "/uwu/v1/reminders").await).await;
        assert_eq!(listed["data"][0]["mailedDate"].as_str().map(str::len), Some(10));
        let later = json(server.call("PUT", &path, Some(&nyu.token), json!({"due": "2099-01-01"})).await).await;
        assert_eq!((later["isDue"].as_bool(), later["mailedDate"].is_null()), (Some(false), true));
        assert!(
            json(server.get_as(&other.token, "/uwu/v1/reminders").await).await["data"].as_array().unwrap().is_empty()
        );
        assert_eq!(server.call("DELETE", &path, Some(&nyu.token), json!({})).await.status(), StatusCode::OK);
        assert!(
            json(server.get_as(&nyu.token, "/uwu/v1/reminders").await).await["data"].as_array().unwrap().is_empty()
        );
    }
}
