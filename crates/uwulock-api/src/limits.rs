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
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            login: Limiter::new(10, Duration::from_secs(60)),
            anonymous: Limiter::new(50, Duration::from_secs(60)),
            two_factor: Limiter::new(10, Duration::from_secs(60)),
            password: Limiter::new(10, Duration::from_secs(60)),
            mail: Limiter::new(5, Duration::from_secs(5 * 60)),
        }
    }
}

impl Limits {
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
