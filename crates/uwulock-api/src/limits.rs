//! Rate limits, per address: a bucket of tries that fills up again slowly.
//!
//! Logins get ten tries and one more a minute — enough for a person who mistypes, far too few to
//! guess a password. What anybody can ask without logging in (the prelogin, a hint, an
//! invitation) gets fifty. A bucket that is full again is forgotten, so the table stays small.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub struct Limiter {
    burst: f64,
    /// One try comes back after this long.
    every: Duration,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl Limiter {
    pub fn new(burst: u32, every: Duration) -> Self {
        Limiter { burst: f64::from(burst), every, buckets: Mutex::new(HashMap::new()) }
    }

    /// Take one try for `ip`. False when there is none left.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut buckets = self.buckets.lock();
        if buckets.len() > 10_000 {
            let (burst, every) = (self.burst, self.every);
            buckets.retain(|_, (tokens, at)| {
                *tokens + now.duration_since(*at).as_secs_f64() / every.as_secs_f64() < burst
            });
        }
        let (tokens, at) = buckets.entry(ip).or_insert((self.burst, now));
        let refilled = (*tokens + now.duration_since(*at).as_secs_f64() / self.every.as_secs_f64()).min(self.burst);
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

/// The server's limiters.
pub struct Limits {
    /// Logins, second steps of logins, and asking for a login code by mail.
    pub login: Limiter,
    /// What anybody can ask without logging in.
    pub anonymous: Limiter,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            login: Limiter::new(10, Duration::from_secs(60)),
            anonymous: Limiter::new(50, Duration::from_secs(60)),
        }
    }
}

impl Limits {
    /// Limits no test runs into.
    pub fn generous() -> Self {
        Limits {
            login: Limiter::new(10_000, Duration::from_millis(1)),
            anonymous: Limiter::new(10_000, Duration::from_millis(1)),
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
        assert!((0..3).all(|_| limiter.check_at(ip, start)));
        assert!(!limiter.check_at(ip, start));
        assert!(limiter.check_at(other, start), "every address has its own");
        assert!(!limiter.check_at(ip, start + Duration::from_secs(59)));
        assert!(limiter.check_at(ip, start + Duration::from_secs(120)));
    }
}
