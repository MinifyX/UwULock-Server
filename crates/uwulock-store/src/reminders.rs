//! Reminders to renew a password (docs/uwu-api.md §10): per account and item, the day it is due,
//! and, if it repeats, after how many months. Nothing else — the mail about it names no item.

use crate::{Cipher, Result, Store};
use rusqlite::{Transaction, params};
use time::{Date, Month};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reminder {
    pub cipher_id: String,
    /// `YYYY-MM-DD`, UTC.
    pub due: String,
    pub every_months: Option<i64>,
    /// The day the mail for this due date went out.
    pub mailed: Option<String>,
}

/// `date` plus `months`, on the same day of the month or the last one it has.
pub fn add_months(date: Date, months: u32) -> Date {
    let index = date.year() * 12 + i32::from(u8::from(date.month())) - 1 + months as i32;
    let (year, month) = (index.div_euclid(12), Month::try_from((index.rem_euclid(12) + 1) as u8).expect("1 to 12"));
    let day = date.day().min(time::util::days_in_month(month, year));
    Date::from_calendar_date(year, month, day).unwrap_or(date)
}

/// A day as the reminders write it.
pub fn day(date: Date) -> String {
    format!("{:04}-{:02}-{:02}", date.year(), u8::from(date.month()), date.day())
}

/// Today, UTC.
pub fn today() -> Date {
    time::OffsetDateTime::now_utc().date()
}

/// The day of a login's `passwordRevisionDate`, from the type object's JSON.
fn password_day(data: &str) -> Option<Date> {
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    let text = value.get("passwordRevisionDate")?.as_str()?;
    crate::clock::parse(text).map(|when| when.date())
}

/// A new password was saved into an item: its reminders move on. One that repeats is due again
/// that many months after the new password; one for a fixed day that has passed is done.
pub(crate) fn password_changed(tx: &Transaction<'_>, before: &Cipher, after: &Cipher) -> rusqlite::Result<()> {
    let Some(new) = password_day(&after.data) else { return Ok(()) };
    if password_day(&before.data).is_some_and(|old| old >= new) {
        return Ok(());
    }
    let reminders: Vec<(String, Option<i64>, String)> = tx
        .prepare_cached("SELECT user_id, every_months, due FROM reminders WHERE cipher_id = ?1")?
        .query_map([&after.id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let today = day(today());
    for (user, every, due) in reminders {
        match every {
            Some(months) => {
                tx.execute(
                    "UPDATE reminders SET due = ?3, mailed = NULL WHERE user_id = ?1 AND cipher_id = ?2",
                    params![user, after.id, day(add_months(new, months.clamp(1, 60) as u32))],
                )?;
            }
            None if due <= today => {
                tx.execute("DELETE FROM reminders WHERE user_id = ?1 AND cipher_id = ?2", params![user, after.id])?;
            }
            None => {}
        }
    }
    Ok(())
}

impl Store {
    /// The account's reminders, without those of items travel mode hides.
    pub async fn reminders(&self, user_id: &str) -> Result<Vec<Reminder>> {
        let user_id = user_id.to_string();
        self.sqlite_read(move |conn| {
            let reminders = conn
                .prepare_cached(
                    "SELECT cipher_id, due, every_months, mailed FROM reminders WHERE user_id = ?1 ORDER BY due, cipher_id",
                )?
                .query_map([&user_id], |row| {
                    Ok(Reminder { cipher_id: row.get(0)?, due: row.get(1)?, every_months: row.get(2)?, mailed: row.get(3)? })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut shown = Vec::with_capacity(reminders.len());
            for reminder in reminders {
                if !crate::travel::is_hidden(conn, &user_id, &reminder.cipher_id)? {
                    shown.push(reminder);
                }
            }
            Ok(shown)
        })
        .await
    }

    /// A reminder for an item, new or changed. The caller checked the item is the account's to
    /// see.
    pub async fn set_reminder(&self, user_id: &str, reminder: Reminder) -> Result<()> {
        let user_id = user_id.to_string();
        self.sqlite_write(move |tx| {
            tx.execute(
                "INSERT INTO reminders (user_id, cipher_id, due, every_months, mailed) VALUES (?1, ?2, ?3, ?4, NULL) \
                 ON CONFLICT (user_id, cipher_id) DO UPDATE SET every_months = excluded.every_months, \
                 mailed = CASE WHEN reminders.due = excluded.due THEN reminders.mailed END, due = excluded.due",
                params![user_id, reminder.cipher_id, reminder.due, reminder.every_months],
            )
            .map(drop)
        })
        .await
    }

    pub async fn delete_reminder(&self, user_id: &str, cipher_id: &str) -> Result<bool> {
        let (user_id, cipher_id) = (user_id.to_string(), cipher_id.to_string());
        self.sqlite_write(move |tx| {
            Ok(tx.execute("DELETE FROM reminders WHERE user_id = ?1 AND cipher_id = ?2", [user_id, cipher_id])? > 0)
        })
        .await
    }

    /// Accounts with reminders that became due by `today` and were not mailed for that day yet,
    /// with those reminders' items; the hidden ones (travel mode) wait.
    pub async fn reminders_to_mail(&self, today: &str) -> Result<Vec<(String, Vec<String>)>> {
        let today = today.to_string();
        self.sqlite_read(move |conn| {
            let due: Vec<(String, String)> = conn
                .prepare_cached(
                    "SELECT r.user_id, r.cipher_id FROM reminders r JOIN users u ON u.id = r.user_id \
                     WHERE r.due <= ?1 AND r.mailed IS NULL AND NOT u.disabled ORDER BY r.user_id, r.due",
                )?
                .query_map([&today], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            let mut by_user: Vec<(String, Vec<String>)> = Vec::new();
            for (user, cipher) in due {
                if crate::travel::is_hidden(conn, &user, &cipher)? {
                    continue;
                }
                match by_user.last_mut() {
                    Some((last, ciphers)) if *last == user => ciphers.push(cipher),
                    _ => by_user.push((user, vec![cipher])),
                }
            }
            Ok(by_user)
        })
        .await
    }

    /// The mail for these reminders went out on `today`.
    pub async fn reminders_mailed(&self, user_id: &str, cipher_ids: Vec<String>, today: &str) -> Result<()> {
        let (user_id, today) = (user_id.to_string(), today.to_string());
        self.sqlite_write(move |tx| {
            for id in cipher_ids {
                tx.execute(
                    "UPDATE reminders SET mailed = ?3 WHERE user_id = ?1 AND cipher_id = ?2",
                    params![user_id, id, today],
                )?;
            }
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
    use time::macros::date;

    #[test]
    fn months_on_end() {
        assert_eq!(add_months(date!(2026 - 01 - 31), 1), date!(2026 - 02 - 28));
        assert_eq!(add_months(date!(2026 - 11 - 15), 3), date!(2027 - 02 - 15));
        assert_eq!(add_months(date!(2028 - 02 - 29), 12), date!(2029 - 02 - 28));
        assert_eq!(day(date!(2027 - 01 - 05)), "2027-01-05");
    }

    #[tokio::test]
    async fn a_new_password_moves_the_reminder_on() {
        let (store, _dir) = store();
        let user = store.create_user(new_user("nyu@example.com")).await.unwrap();
        let mut item = cipher(&user.id, "c", None);
        item.data = r#"{"password":"2.p|p|p","passwordRevisionDate":"2026-01-10T00:00:00.000Z"}"#.into();
        let item = store.save_cipher(item).await.unwrap().unwrap();
        let fixed = cipher(&user.id, "d", None);
        let fixed = store.save_cipher(fixed).await.unwrap().unwrap();
        let repeat = Reminder { cipher_id: "c".into(), due: "2026-07-10".into(), every_months: Some(6), mailed: None };
        store.set_reminder(&user.id, repeat).await.unwrap();
        let past = Reminder { cipher_id: "d".into(), due: "2020-01-01".into(), every_months: None, mailed: None };
        store.set_reminder(&user.id, past).await.unwrap();

        assert_eq!(
            store.reminders_to_mail("2026-09-28").await.unwrap(),
            [(user.id.clone(), vec!["d".into(), "c".into()])]
        );
        store.reminders_mailed(&user.id, vec!["c".into(), "d".into()], "2026-09-28").await.unwrap();
        assert!(store.reminders_to_mail("2026-09-28").await.unwrap().is_empty(), "once per due date");

        let mut changed = item.clone();
        changed.data = r#"{"password":"2.n|n|n","passwordRevisionDate":"2026-09-01T00:00:00.000Z"}"#.into();
        store.save_cipher(changed).await.unwrap().unwrap();
        let mut again = fixed.clone();
        again.data = r#"{"password":"2.n|n|n","passwordRevisionDate":"2026-09-01T00:00:00.000Z"}"#.into();
        store.save_cipher(again).await.unwrap().unwrap();
        let reminders = store.reminders(&user.id).await.unwrap();
        assert_eq!(reminders.len(), 1, "the fixed one that had passed is done");
        assert_eq!((reminders[0].due.as_str(), reminders[0].mailed.as_deref()), ("2027-03-01", None));

        store.bulk(&user.id, vec!["c".into()], crate::Bulk::Delete).await.unwrap();
        assert!(store.reminders(&user.id).await.unwrap().is_empty(), "gone with the item");
    }
}
