//! The codes that open a Send only given addresses may open (docs/uwu-api.md §14.3): eight
//! digits, mailed to the address, good for five minutes and once, kept only as their hash and
//! only in memory — a restart just means asking for a new one.
//!
//! Beyond what Bitwarden does: five wrong codes per Send and address end the code, and twenty a
//! day end every code for that pair until the day is over. An address gets at most one mail a
//! minute, five an hour and ten a day per Send (SV-L24); a Send sends at most ten code mails an
//! hour, and one owner's Sends thirty an hour and a hundred a day (SV-L25).

use crate::auth;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a code works.
const VALID: Duration = Duration::from_secs(5 * 60);
/// Digits of a code.
pub const DIGITS: u32 = 8;
/// Wrong codes before the code is gone.
const WRONG: u32 = 5;
/// Wrong codes per Send and address in a day, whichever codes they were for.
const WRONG_PER_DAY: usize = 20;
/// Mails per Send and address: one a minute, five an hour, ten a day.
const GAP: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(60 * 60);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const PER_HOUR: usize = 5;
const PER_DAY: usize = 10;
/// Code mails per Send in an hour, whatever the address.
const SEND_PER_HOUR: usize = 10;
/// Code mails of one owner's Sends: thirty an hour, a hundred a day.
const OWNER_PER_HOUR: usize = 30;
const OWNER_PER_DAY: usize = 100;
/// Past this many pairs, the ones with nothing left to remember are forgotten.
const TIDY_AT: usize = 1000;

#[derive(Default)]
struct Pair {
    /// SHA-256 of the code, while there is one.
    hash: Option<Vec<u8>>,
    expires: Option<Instant>,
    wrong: u32,
    /// When mails went out, the last day.
    mailed: Vec<Instant>,
    /// When wrong codes came, the last day.
    wrong_at: Vec<Instant>,
}

#[derive(Default)]
struct Codes {
    pairs: HashMap<(String, String), Pair>,
    /// When code mails went out, per Send and per owner, the last day.
    sends: HashMap<String, Vec<Instant>>,
    owners: HashMap<String, Vec<Instant>>,
}

#[derive(Default)]
pub struct SendCodes {
    codes: Mutex<Codes>,
}

/// How many of `times` fall within `window` before `now`.
fn within(times: &[Instant], now: Instant, window: Duration) -> usize {
    times.iter().filter(|at| now.saturating_duration_since(**at) < window).count()
}

impl SendCodes {
    /// A new code for `email` and the Send `send_id` of `owner`, replacing the last one; `None`
    /// when the address, the Send or the owner had their mails for now.
    pub fn issue(&self, send_id: &str, owner: &str, email: &str) -> Option<String> {
        self.issue_at(send_id, owner, email, Instant::now())
    }

    fn issue_at(&self, send_id: &str, owner: &str, email: &str, now: Instant) -> Option<String> {
        let mut guard = self.codes.lock();
        let codes = &mut *guard;
        let recent = |at: &Instant| now.saturating_duration_since(*at) < DAY;
        if codes.pairs.len() > TIDY_AT {
            codes.pairs.retain(|_, pair| {
                pair.mailed.retain(recent);
                pair.wrong_at.retain(recent);
                !pair.mailed.is_empty()
                    || !pair.wrong_at.is_empty()
                    || pair.expires.is_some_and(|expires| expires > now)
            });
        }
        if codes.sends.len() > TIDY_AT || codes.owners.len() > TIDY_AT {
            for times in codes.sends.values_mut().chain(codes.owners.values_mut()) {
                times.retain(recent);
            }
            codes.sends.retain(|_, times| !times.is_empty());
            codes.owners.retain(|_, times| !times.is_empty());
        }
        let send = codes.sends.get(send_id).map_or(0, |times| within(times, now, HOUR));
        let owner_times = codes.owners.get(owner).map(Vec::as_slice).unwrap_or_default();
        if send >= SEND_PER_HOUR
            || within(owner_times, now, HOUR) >= OWNER_PER_HOUR
            || within(owner_times, now, DAY) >= OWNER_PER_DAY
        {
            return None;
        }
        let pair = codes.pairs.entry((send_id.to_string(), email.to_string())).or_default();
        pair.mailed.retain(recent);
        if within(&pair.mailed, now, HOUR) >= PER_HOUR
            || pair.mailed.len() >= PER_DAY
            || pair.mailed.last().is_some_and(|at| now.saturating_duration_since(*at) < GAP)
        {
            return None;
        }
        let code = auth::random_code(DIGITS);
        pair.hash = Some(auth::sha256(code.as_bytes()));
        pair.expires = Some(now + VALID);
        pair.wrong = 0;
        pair.mailed.push(now);
        for times in
            [codes.sends.entry(send_id.to_string()).or_default(), codes.owners.entry(owner.to_string()).or_default()]
        {
            times.retain(recent);
            times.push(now);
        }
        Some(code)
    }

    /// Whether `code` is the one mailed to `email` for the Send. Right, it is used up; wrong, it
    /// counts, and the fifth wrong one ends it.
    pub fn check(&self, send_id: &str, email: &str, code: &str) -> bool {
        self.check_at(send_id, email, code, Instant::now())
    }

    fn check_at(&self, send_id: &str, email: &str, code: &str, now: Instant) -> bool {
        let mut codes = self.codes.lock();
        let Some(pair) = codes.pairs.get_mut(&(send_id.to_string(), email.to_string())) else { return false };
        pair.wrong_at.retain(|at| now.saturating_duration_since(*at) < DAY);
        if pair.wrong_at.len() >= WRONG_PER_DAY {
            pair.hash = None;
            return false;
        }
        let (Some(hash), Some(expires)) = (&pair.hash, pair.expires) else { return false };
        if expires <= now {
            pair.hash = None;
            return false;
        }
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if auth::constant_time_eq(hash, &auth::sha256(code.as_bytes())) {
            pair.hash = None;
            pair.expires = None;
            return true;
        }
        pair.wrong += 1;
        pair.wrong_at.push(now);
        if pair.wrong >= WRONG {
            pair.hash = None;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_opens_once() {
        let codes = SendCodes::default();
        let code = codes.issue("s", "o", "a@example.com").unwrap();
        assert_eq!(code.len(), 8);
        assert!(!codes.check("s", "b@example.com", &code), "another address");
        assert!(!codes.check("t", "a@example.com", &code), "another Send");
        assert!(codes.check("s", "a@example.com", &format!(" {code} ")));
        assert!(!codes.check("s", "a@example.com", &code), "used up");
    }

    #[test]
    fn five_wrong_codes_end_it() {
        let codes = SendCodes::default();
        let code = codes.issue("s", "o", "a@example.com").unwrap();
        let wrong = if code == "00000000" { "11111111" } else { "00000000" };
        for _ in 0..WRONG {
            assert!(!codes.check("s", "a@example.com", wrong));
        }
        assert!(!codes.check("s", "a@example.com", &code), "gone after five wrong ones");
    }

    #[test]
    fn codes_run_out_and_mails_are_few() {
        let codes = SendCodes::default();
        let start = Instant::now();
        let code = codes.issue_at("s", "o", "a@example.com", start).unwrap();
        assert!(!codes.check_at("s", "a@example.com", &code, start + VALID), "five minutes later");
        assert!(codes.issue_at("s", "o", "a@example.com", start + Duration::from_secs(30)).is_none(), "one a minute");
        assert!(codes.issue_at("s", "o", "b@example.com", start + Duration::from_secs(30)).is_some(), "per address");
        let mut at = start;
        for _ in 1..PER_HOUR {
            at += GAP;
            assert!(codes.issue_at("s", "o", "a@example.com", at).is_some());
        }
        assert!(codes.issue_at("s", "o", "a@example.com", at + GAP).is_none(), "five an hour");
        assert!(codes.issue_at("s", "o", "a@example.com", start + HOUR + GAP).is_some(), "an hour on");
    }

    #[test]
    fn a_day_has_its_caps() {
        let codes = SendCodes::default();
        let start = Instant::now();
        // Ten mails a day per address, an hour apart so the hourly cap does not come first.
        let mut at = start;
        for _ in 0..PER_DAY {
            assert!(codes.issue_at("s", "o", "a@example.com", at).is_some());
            at += HOUR;
        }
        assert!(codes.issue_at("s", "o", "a@example.com", at).is_none(), "ten a day");
        assert!(codes.issue_at("s", "o", "a@example.com", start + DAY + GAP).is_some(), "a day on");

        // Twenty wrong codes a day end every code of the pair until the day is over.
        let codes = SendCodes::default();
        let mut at = start;
        let mut last = String::new();
        for _ in 0..(WRONG_PER_DAY / WRONG as usize) {
            last = codes.issue_at("s", "o", "b@example.com", at).unwrap();
            for _ in 0..WRONG {
                codes.check_at("s", "b@example.com", "not-it", at);
            }
            at += HOUR;
        }
        let code = codes.issue_at("s", "o", "b@example.com", at).unwrap();
        assert_ne!(code, last);
        assert!(!codes.check_at("s", "b@example.com", &code, at), "not today");
    }

    #[test]
    fn a_send_and_an_owner_mail_only_so_much() {
        let codes = SendCodes::default();
        let now = Instant::now();
        for n in 0..SEND_PER_HOUR {
            assert!(codes.issue_at("s", "o", &format!("{n}@example.com"), now).is_some());
        }
        assert!(codes.issue_at("s", "o", "more@example.com", now).is_none(), "ten an hour per Send");
        for n in SEND_PER_HOUR..OWNER_PER_HOUR {
            assert!(codes.issue_at(&format!("s{n}"), "o", "a@example.com", now).is_some());
        }
        assert!(codes.issue_at("another", "o", "a@example.com", now).is_none(), "thirty an hour per owner");
        assert!(codes.issue_at("another", "p", "a@example.com", now).is_some(), "another owner");
    }
}
