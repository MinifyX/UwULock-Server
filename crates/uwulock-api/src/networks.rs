//! Networks as CIDR, and the admin portal only from some of them (docs/uwu-api.md §21.4).
//!
//! With `adminNetworks` set, `/admin`, everything below it and `/uwu/v1/admin/**` answer 404 to
//! a client outside those networks — as if they did not exist. The client's address is the one
//! the rest of the server believes too: the connection's, or behind a trusted proxy what it
//! forwarded. The vault, Sends and the command line are not affected; the command line is also
//! the way back in: `uwulock-server settings set adminNetworks '[]'`.

use crate::AppState;
use crate::auth::client_ip;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::IpAddr;
use std::sync::atomic::Ordering;

/// An address with a prefix length: `192.0.2.0/24`, `2001:db8::/32`, or one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    pub fn parse(text: &str) -> Result<IpNetwork, String> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = address.trim().parse().map_err(|_| format!("{text} is not an address or network"))?;
        let most = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= most)
                .ok_or_else(|| format!("{text} has no valid prefix length"))?,
            None => most,
        };
        // An IPv4 network in IPv6 clothes (`::ffff:192.0.2.0/120`) is that IPv4 network, the
        // way the addresses it is compared with are; with a prefix shorter than the mapped
        // range it stays IPv6.
        Ok(match address {
            IpAddr::V6(v6) if prefix >= 96 && v6.to_ipv4_mapped().is_some() => {
                IpNetwork { address: canonical(address), prefix: prefix - 96 }
            }
            _ => IpNetwork { address, prefix },
        })
    }

    pub fn parse_list(list: &[String]) -> Result<Vec<IpNetwork>, String> {
        list.iter().filter(|entry| !entry.trim().is_empty()).map(|entry| IpNetwork::parse(entry)).collect()
    }

    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    /// The prefix length: 32 or 128 for one address.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, canonical(ip)) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(self.prefix)) };
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(self.prefix)) };
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// One address as itself, a network as `address/prefix` with the host bits cleared.
impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let most = if self.address.is_ipv4() { 32 } else { 128 };
        if self.prefix == most {
            return write!(f, "{}", self.address);
        }
        let network: IpAddr = match self.address {
            IpAddr::V4(v4) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(self.prefix)) };
                std::net::Ipv4Addr::from(u32::from(v4) & mask).into()
            }
            IpAddr::V6(v6) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(self.prefix)) };
                std::net::Ipv6Addr::from(u128::from(v6) & mask).into()
            }
        };
        write!(f, "{network}/{}", self.prefix)
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Whether `ip` may reach the admin portal with these networks: an empty list means everywhere.
/// A list that does not parse lets nobody in (it cannot be saved like that; only a hand-edited
/// database gets there).
pub fn allowed(networks: &[String], ip: IpAddr) -> bool {
    if networks.iter().all(|entry| entry.trim().is_empty()) {
        return true;
    }
    IpNetwork::parse_list(networks).is_ok_and(|parsed| parsed.iter().any(|network| network.contains(ip)))
}

/// Whether a path belongs to the admin portal.
pub fn is_admin_path(path: &str) -> bool {
    path == "/admin" || path.starts_with("/admin/") || path == "/uwu/v1/admin" || path.starts_with("/uwu/v1/admin/")
}

/// The middleware: 404 for the admin portal outside the admin networks.
pub(crate) async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if !is_admin_path(request.uri().path()) {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let ip = client_ip(&parts, &state.config);
    if !allowed(&state.settings.read().admin_networks, ip) && !reloaded_allows(&state, ip).await {
        tracing::info!(%ip, path = parts.uri.path(), "the admin portal was asked for from outside the admin networks");
        return crate::errors::not_found().await.into_response();
    }
    next.run(Request::from_parts(parts, body)).await
}

/// `uwulock-server settings set adminNetworks …` changes the database, not the running server:
/// a refused address makes the server look again, at most every few seconds.
async fn reloaded_allows(state: &AppState, ip: IpAddr) -> bool {
    let now = crate::auth::now_seconds();
    let last = state.admin_reloaded.load(Ordering::Relaxed);
    if now - last < 5 || state.admin_reloaded.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err()
    {
        return false;
    }
    let Ok(stored) = crate::Settings::load(&state.store, &state.config.start_settings, &state.secret).await else {
        return false;
    };
    let networks = stored.admin_networks.clone();
    if networks != state.settings.read().admin_networks {
        tracing::info!("the admin networks changed in the database; taking them over");
        state.settings.write().admin_networks = networks.clone();
    }
    allowed(&networks, ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use axum::http::StatusCode;
    use serde_json::json;

    #[tokio::test]
    async fn the_portal_is_not_there_outside_its_networks_and_nobody_shuts_themselves_out() {
        let server = TestServer::new().await.behind_proxy();
        let token = server.invite("admin@example.com", true).await;
        server
            .call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token))
            .await;
        let admin = server.login("admin@example.com", "admin-device").await;
        let lan = "192.0.2.10";
        let mut settings =
            json(server.call_from(lan, "GET", "/uwu/v1/admin/settings", &admin.token, json!({})).await).await;

        settings["adminNetworks"] = json!(["198.51.100.0/24"]);
        let refused = server.call_from(lan, "PUT", "/uwu/v1/admin/settings", &admin.token, settings.clone()).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(refused).await["code"], "would_lock_out");

        settings["adminNetworks"] = json!(["192.0.2.0/24", " ", "2001:db8::/32"]);
        let saved = server.call_from(lan, "PUT", "/uwu/v1/admin/settings", &admin.token, settings.clone()).await;
        assert_eq!(saved.status(), StatusCode::OK);
        assert_eq!(json(saved).await["adminNetworks"], json!(["192.0.2.0/24", "2001:db8::/32"]));

        let outside = server.call_from("203.0.113.5", "GET", "/uwu/v1/admin/users", &admin.token, json!({})).await;
        assert_eq!(outside.status(), StatusCode::NOT_FOUND, "as if there were no admin portal");
        assert_eq!(json(outside).await["message"], "Not found.");
        let page = server.call_from("203.0.113.5", "GET", "/admin", &admin.token, json!({})).await;
        assert_eq!(page.status(), StatusCode::NOT_FOUND);
        let vault = server.call_from("203.0.113.5", "GET", "/api/sync", &admin.token, json!({})).await;
        assert_eq!(vault.status(), StatusCode::OK, "the vault is not affected");
        let inside = server.call_from("2001:db8::7", "GET", "/uwu/v1/admin/users", &admin.token, json!({})).await;
        assert_eq!(inside.status(), StatusCode::OK);

        // The command line empties the list in the database; the refused address makes the
        // running server look again.
        let stored = crate::Settings::load(&server.state.store, &crate::Settings::default(), &server.state.secret)
            .await
            .unwrap();
        stored.with("adminNetworks", json!([])).unwrap().save(&server.state.store, &server.state.secret).await.unwrap();
        server.state.admin_reloaded.store(0, Ordering::Relaxed);
        let back = server.call_from("203.0.113.5", "GET", "/uwu/v1/admin/users", &admin.token, json!({})).await;
        assert_eq!(back.status(), StatusCode::OK);
        assert!(server.state.settings().admin_networks.is_empty());
    }

    #[test]
    fn networks_contain_their_addresses() {
        let lan = IpNetwork::parse("192.0.2.0/24").unwrap();
        assert!(lan.contains("192.0.2.77".parse().unwrap()));
        assert!(!lan.contains("198.51.100.1".parse().unwrap()));
        assert!(lan.contains("::ffff:192.0.2.5".parse().unwrap()), "an IPv4 address in IPv6 clothes");
        let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::5".parse().unwrap()));
        assert!(!v6.contains("2001:db9::5".parse().unwrap()));
        assert!(!v6.contains("192.0.2.1".parse().unwrap()));
        let one = IpNetwork::parse("203.0.113.7").unwrap();
        assert!(one.contains("203.0.113.7".parse().unwrap()) && !one.contains("203.0.113.8".parse().unwrap()));
        assert!(IpNetwork::parse("0.0.0.0/0").unwrap().contains("198.51.100.1".parse().unwrap()));
        assert_eq!(IpNetwork::parse("192.0.2.77/24").unwrap().to_string(), "192.0.2.0/24");
        assert_eq!(IpNetwork::parse("2001:db8::7/64").unwrap().to_string(), "2001:db8::/64");
        assert_eq!(IpNetwork::parse(" 203.0.113.7/32").unwrap().to_string(), "203.0.113.7");
        // IPv4 written as IPv6 is IPv4, with its prefix counted from the IPv4 part.
        let mapped = IpNetwork::parse("::ffff:203.0.113.0/120").unwrap();
        assert_eq!(mapped.to_string(), "203.0.113.0/24");
        assert!(mapped.contains("203.0.113.9".parse().unwrap()) && !mapped.contains("203.0.114.9".parse().unwrap()));
        assert_eq!(IpNetwork::parse("::ffff:192.0.2.1").unwrap().to_string(), "192.0.2.1");
        assert!(IpNetwork::parse("::ffff:192.0.2.1").unwrap().contains("::ffff:192.0.2.1".parse().unwrap()));
        assert_eq!(IpNetwork::parse("::/64").unwrap().to_string(), "::/64");
        for bad in ["192.0.2.0/33", "lan", "192.0.2.0/x", "2001:db8::/129"] {
            assert!(IpNetwork::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_empty_list_is_everywhere() {
        assert!(allowed(&[], "198.51.100.1".parse().unwrap()));
        let list = vec!["192.0.2.0/24".to_string()];
        assert!(allowed(&list, "192.0.2.1".parse().unwrap()));
        assert!(!allowed(&list, "198.51.100.1".parse().unwrap()));
        assert!(!allowed(&["nonsense".to_string()], "192.0.2.1".parse().unwrap()), "broken: nobody");
        assert!(is_admin_path("/admin") && is_admin_path("/uwu/v1/admin/users"));
        assert!(!is_admin_path("/administrator") && !is_admin_path("/uwu/v1/info"));
    }
}
