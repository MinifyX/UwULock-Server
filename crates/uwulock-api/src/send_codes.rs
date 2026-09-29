//! The codes that open a Send only given addresses may open (docs/uwu-api.md §14.3): six digits,
//! mailed to the address, good for five minutes and once, kept only as their hash and only in
//! memory — a restart just means asking for a new one.
//!
//! Beyond what Bitwarden does: five wrong codes per Send and address end the code, and an address
//! gets at most one mail a minute and five an hour per Send.

use crate::auth;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a code works.
const VALID: Duration = Duration::from_secs(5 * 60);
/// Wrong codes before the code is gone.
const WRONG: u32 = 5;
/// Mails per Send and address: one a minute, five an hour.
const GAP: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(60 * 60);
const PER_HOUR: usize = 5;
/// Past this many pairs, the ones with nothing left to remember are forgotten.
const TIDY_AT: usize = 1000;

#[derive(Default)]
struct Pair {
    /// SHA-256 of the code, while there is one.
    hash: Option<Vec<u8>>,
    expires: Option<Instant>,
    wrong: u32,
    /// When mails went out, the last hour.
    mailed: Vec<Instant>,
}

#[derive(Default)]
pub struct SendCodes {
    pairs: Mutex<HashMap<(String, String), Pair>>,
}

impl SendCodes {
    /// A new code for `email` and the Send `send_id`, replacing the last one; `None` when the
    /// address had its mails for now.
    pub fn issue(&self, send_id: &str, email: &str) -> Option<String> {
        self.issue_at(send_id, email, Instant::now())
    }

    fn issue_at(&self, send_id: &str, email: &str, now: Instant) -> Option<String> {
        let mut pairs = self.pairs.lock();
        if pairs.len() > TIDY_AT {
            pairs.retain(|_, pair| {
                pair.mailed.retain(|at| now.saturating_duration_since(*at) < HOUR);
                !pair.mailed.is_empty() || pair.expires.is_some_and(|expires| expires > now)
            });
        }
        let pair = pairs.entry((send_id.to_string(), email.to_string())).or_default();
        pair.mailed.retain(|at| now.saturating_duration_since(*at) < HOUR);
        if pair.mailed.len() >= PER_HOUR
            || pair.mailed.last().is_some_and(|at| now.saturating_duration_since(*at) < GAP)
        {
            return None;
        }
        let code = auth::random_code(6);
        pair.hash = Some(auth::sha256(code.as_bytes()));
        pair.expires = Some(now + VALID);
        pair.wrong = 0;
        pair.mailed.push(now);
        Some(code)
    }

    /// Whether `code` is the one mailed to `email` for the Send. Right, it is used up; wrong, it
    /// counts, and the fifth wrong one ends it.
    pub fn check(&self, send_id: &str, email: &str, code: &str) -> bool {
        self.check_at(send_id, email, code, Instant::now())
    }

    fn check_at(&self, send_id: &str, email: &str, code: &str, now: Instant) -> bool {
        let mut pairs = self.pairs.lock();
        let Some(pair) = pairs.get_mut(&(send_id.to_string(), email.to_string())) else { return false };
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
        let code = codes.issue("s", "a@example.com").unwrap();
        assert_eq!(code.len(), 6);
        assert!(!codes.check("s", "b@example.com", &code), "another address");
        assert!(!codes.check("t", "a@example.com", &code), "another Send");
        assert!(codes.check("s", "a@example.com", &format!(" {code} ")));
        assert!(!codes.check("s", "a@example.com", &code), "used up");
    }

    #[test]
    fn five_wrong_codes_end_it() {
        let codes = SendCodes::default();
        let code = codes.issue("s", "a@example.com").unwrap();
        let wrong = if code == "000000" { "111111" } else { "000000" };
        for _ in 0..WRONG {
            assert!(!codes.check("s", "a@example.com", wrong));
        }
        assert!(!codes.check("s", "a@example.com", &code), "gone after five wrong ones");
    }

    #[test]
    fn codes_run_out_and_mails_are_few() {
        let codes = SendCodes::default();
        let start = Instant::now();
        let code = codes.issue_at("s", "a@example.com", start).unwrap();
        assert!(!codes.check_at("s", "a@example.com", &code, start + VALID), "five minutes later");
        assert!(codes.issue_at("s", "a@example.com", start + Duration::from_secs(30)).is_none(), "one a minute");
        assert!(codes.issue_at("s", "b@example.com", start + Duration::from_secs(30)).is_some(), "per address");
        let mut at = start;
        for _ in 1..PER_HOUR {
            at += GAP;
            assert!(codes.issue_at("s", "a@example.com", at).is_some());
        }
        assert!(codes.issue_at("s", "a@example.com", at + GAP).is_none(), "five an hour");
        assert!(codes.issue_at("s", "a@example.com", start + HOUR + GAP).is_some(), "an hour on");
    }
}
