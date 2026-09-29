//! Rate limits: a bucket of tries that fills up again slowly, per address — and per account or
//! per mail address where an address alone is not enough.
//!
//! Logins get ten tries and one more a minute — enough for a person who mistypes, far too few to
//! guess a password. What anybody can ask without logging in (the prelogin, a hint, an
//! invitation) gets fifty. A bucket that is full again is forgotten, so the table stays small.
//!
//! An IPv6 address counts by its /64: that is what one line at home or one server gets, and
//! anybody with one has more addresses in it than there are buckets.
//!
//! The second step of a login is limited per account as well: whoever tries it knows the
//! password already, and could otherwise guess six digits from as many addresses as they have.
//! So is every mail somebody can make the server send to an address, so nobody fills an inbox.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Past this many buckets, the full ones are forgotten.
const TIDY_AT: usize = 10_000;
/// Past this many that are all in use, the tenth that was used longest ago is forgotten. Only
/// somebody with a great many addresses gets here; refusing every new one instead would lock
/// everybody else out.
const MOST: usize = 100_000;

pub struct Limiter<K = IpAddr> {
    burst: f64,
    /// One try comes back after this long.
    every: Duration,
    buckets: Mutex<Buckets<K>>,
}

struct Buckets<K> {
    map: HashMap<K, (f64, Instant)>,
    /// When the full buckets were last forgotten, so that is not done on every try.
    tidied: Option<Instant>,
}

impl<K: Hash + Eq> Limiter<K> {
    pub fn new(burst: u32, every: Duration) -> Self {
        Limiter { burst: f64::from(burst), every, buckets: Mutex::new(Buckets { map: HashMap::new(), tidied: None }) }
    }

    fn refilled(&self, tokens: f64, at: Instant, now: Instant) -> f64 {
        (tokens + now.saturating_duration_since(at).as_secs_f64() / self.every.as_secs_f64()).min(self.burst)
    }

    fn tidy(&self, buckets: &mut Buckets<K>, now: Instant) {
        if buckets.map.len() <= TIDY_AT
            || buckets.tidied.is_some_and(|at| now.saturating_duration_since(at) < self.every)
        {
            return;
        }
        buckets.map.retain(|_, (tokens, at)| self.refilled(*tokens, *at, now) < self.burst);
        buckets.tidied = Some(now);
    }

    /// Give back the try `take` took, when it turned out right. Taking first and giving back
    /// afterwards is what keeps tries that run at the same time from all getting through.
    pub fn give_back(&self, key: &K) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock();
        if let Some((tokens, at)) = buckets.map.get_mut(key) {
            *tokens = (self.refilled(*tokens, *at, now) + 1.0).min(self.burst);
            *at = now;
        }
    }

    /// Whether `key` has a try left, without taking it.
    pub fn allows(&self, key: &K) -> bool {
        let now = Instant::now();
        let buckets = self.buckets.lock();
        buckets.map.get(key).is_none_or(|(tokens, at)| self.refilled(*tokens, *at, now) >= 1.0)
    }

    /// Take one try for `key`. False when there is none left.
    pub fn take(&self, key: K) -> bool {
        self.take_at(key, Instant::now())
    }

    fn take_at(&self, key: K, now: Instant) -> bool {
        let mut buckets = self.buckets.lock();
        self.tidy(&mut buckets, now);
        if buckets.map.len() >= MOST && !buckets.map.contains_key(&key) {
            let mut times: Vec<Instant> = buckets.map.values().map(|(_, at)| *at).collect();
            let cut = MOST / 10;
            let (_, oldest, _) = times.select_nth_unstable(cut);
            let oldest = *oldest;
            buckets.map.retain(|_, (_, at)| *at > oldest);
        }
        let (tokens, at) = buckets.map.entry(key).or_insert((self.burst, now));
        let refilled = self.refilled(*tokens, *at, now);
        *at = now;
        if refilled >= 1.0 {
            *tokens = refilled - 1.0;
            true
        } else {
            *tokens = refilled;
            false
        }
    }
}

impl Limiter<IpAddr> {
    /// Take one try for `ip`. False when there is none left.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.take(network(ip))
    }
}

/// The key of `ip`'s bucket, for a limiter that is asked before it is taken from.
pub fn network_of(ip: IpAddr) -> IpAddr {
    network(ip)
}

/// The address a bucket belongs to: an IPv4 address as it is, an IPv6 address by its /64.
fn network(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::from(octets)
        }
    }
}

/// The server's limiters.
pub struct Limits {
    /// Logins, second steps of logins, and asking for a login code by mail.
    pub login: Limiter,
    /// What anybody can ask without logging in.
    pub anonymous: Limiter,
    /// Wrong second steps of a login, per account.
    pub two_factor: Limiter<String>,
    /// Wrong master passwords from a logged-in session, per account.
    pub password: Limiter<String>,
    /// Mails anybody can make the server send, per address they go to.
    pub mail: Limiter<String>,
    /// Questions to Have I Been Pwned, per account: a whole vault checked at once, but not a
    /// flood.
    pub hibp: Limiter<String>,
    /// What clients report themselves, like an export: ten an hour per account.
    pub reports: Limiter<String>,
    /// Submissions to file requests, per address: ten an hour.
    pub file_request_uploads: Limiter,
    /// Requests to `/scim/v2` with a wrong token, per address: 30, then one every 30 seconds.
    pub scim_refused: Limiter,
    /// Websites' icons the server has not fetched yet, per address: sixty, one back a second.
    pub icons: Limiter,
    /// Wrong tries to switch travel mode off, per account: five, one back every 3 minutes.
    pub travel: Limiter<String>,
    /// Invitations to organisations, per account: thirty, one back every two minutes.
    pub invites: Limiter<String>,
    /// Connecting to UwUMail for masked addresses, per account: ten, one back every six minutes.
    pub masked_connect: Limiter<String>,
    /// Codes from UwUMail that did not turn into tokens, per account: three, one back every 20
    /// minutes; and per UwUMail server: ten, one back every 90 seconds. UwUMail refuses every
    /// token request from this server's address after 30 failures in 15 minutes — other
    /// accounts' refreshes too — so one account must not be able to spend them.
    pub masked_codes_account: Limiter<String>,
    pub masked_codes_server: Limiter<String>,
    /// New masked addresses per account or API key: thirty a minute…
    pub masked_minute: Limiter<String>,
    /// …and five hundred a day.
    pub masked_day: Limiter<String>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            login: Limiter::new(10, Duration::from_secs(60)),
            anonymous: Limiter::new(50, Duration::from_secs(60)),
            two_factor: Limiter::new(10, Duration::from_secs(60)),
            password: Limiter::new(10, Duration::from_secs(60)),
            mail: Limiter::new(5, Duration::from_secs(5 * 60)),
            hibp: Limiter::new(2000, Duration::from_millis(200)),
            reports: Limiter::new(10, Duration::from_secs(6 * 60)),
            file_request_uploads: Limiter::new(10, Duration::from_secs(6 * 60)),
            scim_refused: Limiter::new(30, Duration::from_secs(30)),
            icons: Limiter::new(60, Duration::from_secs(1)),
            travel: Limiter::new(5, Duration::from_secs(3 * 60)),
            invites: Limiter::new(30, Duration::from_secs(2 * 60)),
            masked_connect: Limiter::new(10, Duration::from_secs(6 * 60)),
            masked_codes_account: Limiter::new(3, Duration::from_secs(20 * 60)),
            masked_codes_server: Limiter::new(10, Duration::from_secs(90)),
            masked_minute: Limiter::new(30, Duration::from_secs(2)),
            masked_day: Limiter::new(500, Duration::from_millis(172_800)),
        }
    }
}

impl Limits {
    /// The defaults, with `attempts` logins at once per address. Many people behind one address
    /// also make more requests without an account (prelogin, SSO, Sends), so that bucket grows
    /// with it: five for each login, never fewer than the default 50.
    pub fn with_login_attempts(attempts: u32) -> Self {
        Limits {
            login: Limiter::new(attempts, Duration::from_secs(60)),
            anonymous: Limiter::new(attempts.saturating_mul(5).max(50), Duration::from_secs(60)),
            ..Limits::default()
        }
    }

    /// Limits no test runs into.
    pub fn generous() -> Self {
        fn generous<K: Hash + Eq>() -> Limiter<K> {
            Limiter::new(10_000, Duration::from_millis(1))
        }
        Limits {
            login: generous(),
            anonymous: generous(),
            two_factor: generous(),
            password: generous(),
            mail: generous(),
            hibp: generous(),
            reports: generous(),
            file_request_uploads: generous(),
            scim_refused: generous(),
            icons: generous(),
            travel: generous(),
            invites: generous(),
            masked_connect: generous(),
            masked_codes_account: generous(),
            masked_codes_server: generous(),
            masked_minute: generous(),
            masked_day: generous(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tries_run_out_and_come_back() {
        let limiter = Limiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        let start = Instant::now();
        assert!((0..3).all(|_| limiter.take_at(ip, start)));
        assert!(!limiter.take_at(ip, start));
        assert!(limiter.take_at(other, start), "every address has its own");
        assert!(!limiter.take_at(ip, start + Duration::from_secs(59)));
        assert!(limiter.take_at(ip, start + Duration::from_secs(120)));
    }

    #[test]
    fn an_ipv6_network_shares_one_bucket() {
        let limiter = Limiter::new(2, Duration::from_secs(60));
        assert!(limiter.check("2001:db8:1:2::1".parse().unwrap()));
        assert!(limiter.check("2001:db8:1:2::2".parse().unwrap()));
        assert!(!limiter.check("2001:db8:1:2:ffff::3".parse().unwrap()), "the same /64");
        assert!(limiter.check("2001:db8:1:3::1".parse().unwrap()), "another /64");
    }

    #[test]
    fn a_full_table_forgets_what_was_used_longest_ago() {
        let limiter = Limiter::new(1, Duration::from_secs(3600));
        let start = Instant::now();
        for n in 0..MOST as u32 {
            assert!(limiter.take_at(n, start + Duration::from_millis(u64::from(n))));
        }
        let later = start + Duration::from_secs(1000);
        assert!(limiter.take_at(u32::MAX, later), "a newcomer still gets a try");
        assert!(!limiter.allows(&u32::MAX));
        assert!(!limiter.take_at(MOST as u32 - 1, later), "the recent ones are remembered");
        assert!(limiter.buckets.lock().map.len() < MOST);
    }

    #[test]
    fn a_try_that_was_right_comes_back() {
        let limiter = Limiter::new(2, Duration::from_secs(3600));
        assert!(limiter.take("a"));
        assert!(limiter.take("a"));
        assert!(!limiter.take("a"), "both tries are out at the same time");
        limiter.give_back(&"a");
        assert!(limiter.take("a"));
        limiter.give_back(&"a");
        limiter.give_back(&"a");
        limiter.give_back(&"a");
        assert!(limiter.take("a") && limiter.take("a") && !limiter.take("a"), "never more than the burst");
    }

    #[test]
    fn full_buckets_are_forgotten() {
        let limiter = Limiter::new(1, Duration::from_secs(1));
        let now = Instant::now();
        for n in 0..=TIDY_AT as u32 {
            limiter.take_at(n, now);
        }
        limiter.take_at(u32::MAX, now + Duration::from_secs(5));
        assert_eq!(limiter.buckets.lock().map.len(), 1);
    }
}
