//! The diagnosis page of the admin portal (docs/uwu-api.md §21.5, docs/deployment.md): is the
//! server well set up? On demand, and by itself after every start with a new version.
//!
//! The server checks what it can see: the certificate clients get, its clock, the mail server,
//! the push relay, the backups, the disk, and what the admin's own request says about the proxy
//! in front. What only a browser can see — whether WebSockets get through the proxy, and whether
//! the proxy takes an upload as large as the largest allowed file — the portal tries from the
//! admin's browser against this server and hands in. Nothing here asks a third party from the
//! browser; the clock is compared with the `Date` of servers the server talks to anyway.
//!
//! Every check that is not fine says what to do, with an example for Caddy and nginx where a
//! proxy is the answer.

use crate::AppState;
use crate::alerts::Detail;
use crate::auth::{Admin, Session, client_ip};
use crate::errors::{ApiError, ApiResult};
use axum::body::Body;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::request::Parts;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use uwulock_mail::Language;
use uwulock_store::clock;

const KEY: &str = "diagnosis";
/// The version the last diagnosis after a start was for.
const VERSION_KEY: &str = "diagnosis_version";
/// A clock this far off makes two-step codes fail now and then.
const CLOCK_WARNING: i64 = 30;
const CLOCK_ERROR: i64 = 120;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Text {
    de: String,
    en: String,
}

impl From<Detail> for Text {
    fn from(detail: Detail) -> Self {
        Text { de: detail.de, en: detail.en }
    }
}

fn text(de: impl Into<String>, en: impl Into<String>) -> Text {
    Text { de: de.into(), en: en.into() }
}

impl Text {
    fn get(&self, language: Language) -> &str {
        match language {
            Language::De => &self.de,
            Language::En => &self.en,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Fix {
    text: Text,
    caddy: Option<String>,
    nginx: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Check {
    id: String,
    /// `ok`, `warning`, `error` or `skipped`.
    status: String,
    summary: Text,
    detail: Option<Text>,
    fix: Option<Fix>,
}

fn check(id: &str, status: &str, summary: Text) -> Check {
    Check { id: id.into(), status: status.into(), summary, detail: None, fix: None }
}

impl Check {
    fn detail(mut self, detail: Text) -> Self {
        self.detail = Some(detail);
        self
    }

    fn fix(mut self, text: Text, caddy: Option<&str>, nginx: Option<&str>) -> Self {
        self.fix = Some(Fix { text, caddy: caddy.map(str::to_string), nginx: nginx.map(str::to_string) });
        self
    }

    /// At least `status`: a check that was fine becomes a warning, one that failed stays failed.
    fn worst(mut self, status: &str) -> Self {
        if self.status == "ok" {
            self.status = status.into();
        }
        self
    }
}

/// A diagnosis as it is kept, in both languages.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    date: String,
    version: String,
    checks: Vec<Check>,
}

impl Stored {
    fn render(&self, language: Language) -> Value {
        json!({
            "object": "diagnosis",
            "date": self.date,
            "version": self.version,
            "checks": self.checks.iter().map(|check| json!({
                "id": check.id,
                "status": check.status,
                "summary": check.summary.get(language),
                "detail": check.detail.as_ref().map(|detail| detail.get(language)),
                "fix": check.fix.as_ref().map(|fix| json!({
                    "text": fix.text.get(language),
                    "caddy": fix.caddy,
                    "nginx": fix.nginx,
                })),
            })).collect::<Vec<_>>(),
        })
    }

    /// Put `new` in place of a check with the same id, or add it.
    fn merge(&mut self, new: Check) {
        match self.checks.iter_mut().find(|check| check.id == new.id) {
            Some(old) => *old = new,
            None => self.checks.push(new),
        }
    }
}

// ── The checks the server makes ───────────────────────────

fn date_of(seconds: i64) -> String {
    let when = time::OffsetDateTime::from_unix_timestamp(seconds).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    crate::identity::format_time(&clock::format(when))
}

async fn certificate(state: &AppState) -> Check {
    let Some(probe) = state.config.certificate_probe.clone() else {
        return check(
            "certificate",
            "skipped",
            text(
                "Der Server ist unter einer http-Adresse eingetragen, ohne Zertifikat.",
                "The server's address is http, without a certificate.",
            ),
        )
        .fix(
            text(
                "Die Apps von Bitwarden brauchen https: Trag die https-Adresse als UWULOCK_PUBLIC ein und lass den Server oder einen Proxy davor ein Zertifikat holen.",
                "Bitwarden's apps need https: set UWULOCK_PUBLIC to the https address, and let the server or a proxy in front of it get a certificate.",
            ),
            Some(CADDY_SITE),
            Some(NGINX_CERTBOT),
        );
    };
    let seen = crate::certificate::look(&probe).await;
    *state.certificate.write() = Some(seen.clone());
    judge("certificate", &probe, seen)
}

/// What `seen` at `probe` means for clients, as check `id`.
fn judge(id: &str, probe: &crate::certificate::Probe, seen: crate::certificate::Seen) -> Check {
    let fix = |check: Check| {
        check.fix(
            text(
                "Das Zertifikat erneuern. Mit UWULOCK_TLS=acme tut der Server das 30 Tage vor Ablauf selbst — Port 443 muss ihn dafür erreichen. Hinter einem Proxy erneuert der Proxy es.",
                "Renew the certificate. With UWULOCK_TLS=acme the server does it itself 30 days before it runs out — port 443 has to reach it for that. Behind a proxy, the proxy renews it.",
            ),
            Some(CADDY_SITE),
            Some(NGINX_CERTBOT),
        )
    };
    let Some(expires) = seen.expires else {
        let problem = seen.problem.unwrap_or_default();
        return fix(check(
            id,
            "error",
            text(
                format!("Kein Zertifikat von {}: {problem}", probe.connect),
                format!("No certificate from {}: {problem}", probe.connect),
            ),
        ));
    };
    let left = (expires - crate::auth::now_seconds()) / 86_400;
    let until = date_of(expires);
    if let Some(problem) = seen.problem {
        return fix(check(
            id,
            "error",
            text(
                format!("Clients trauen dem Zertifikat nicht: {problem}"),
                format!("Clients do not trust the certificate: {problem}"),
            ),
        )
        .detail(text(format!("Gültig bis {until}."), format!("Valid until {until}."))));
    }
    let status = if left < 7 {
        "error"
    } else if left < crate::alerts::CERTIFICATE_DAYS {
        "warning"
    } else {
        "ok"
    };
    let summary =
        text(format!("Gültig bis {until} (noch {left} Tage)"), format!("Valid until {until} ({left} days left)"));
    if status == "ok" { check(id, status, summary) } else { fix(check(id, status, summary)) }
}

/// An HTTP date: `Mon, 28 Sep 2026 12:00:00 GMT`.
fn http_date(value: &str) -> Option<i64> {
    let format = time::macros::format_description!(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
    );
    time::PrimitiveDateTime::parse(value.trim(), format).ok().map(|when| when.assume_utc().unix_timestamp())
}

async fn clock_check(state: &AppState) -> Check {
    let mut sources = state.config.time_sources.clone();
    if let Some(push) = state.settings().push {
        sources.push(push.endpoints().0);
    }
    let fix = |check: Check| {
        check.fix(
            text(
                "Die Uhr des Rechners stellen lassen: `timedatectl set-ntp true` (systemd-timesyncd) oder chrony. Codes der Zwei-Schritt-Anmeldung hängen an der Uhrzeit.",
                "Let the machine keep its time: `timedatectl set-ntp true` (systemd-timesyncd) or chrony. Two-step login codes depend on the time.",
            ),
            None,
            None,
        )
    };
    let Ok(client) = crate::outbound::client() else {
        return check("clock", "skipped", text("Kein HTTP-Client.", "No HTTP client."));
    };
    let mut offsets: Vec<(String, i64)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for source in &sources {
        let before = time::OffsetDateTime::now_utc();
        match client.head(source).send().await {
            Ok(response) => {
                let after = time::OffsetDateTime::now_utc();
                let middle = before + (after - before) / 2i32;
                match response.headers().get("date").and_then(|value| value.to_str().ok()).and_then(http_date) {
                    Some(theirs) => offsets.push((source.clone(), middle.unix_timestamp() - theirs)),
                    None => errors.push(format!("{source}: no Date")),
                }
            }
            Err(error) => errors.push(format!("{source}: {}", crate::outbound::error_text(&error))),
        }
    }
    let Some((source, offset)) = offsets.iter().min_by_key(|(_, offset)| offset.abs()).cloned() else {
        return check(
            "clock",
            "skipped",
            text(
                "Keine Zeitquelle erreichbar; die Uhr wurde nicht verglichen.",
                "No time source answered; the clock was not compared.",
            ),
        )
        .detail(text(errors.join("; "), errors.join("; ")));
    };
    let status = match offset.abs() {
        seconds if seconds > CLOCK_ERROR => "error",
        seconds if seconds > CLOCK_WARNING => "warning",
        _ => "ok",
    };
    let summary = if offset.abs() <= 1 {
        text(format!("Stimmt mit {source} überein"), format!("Agrees with {source}"))
    } else {
        text(
            format!("Geht {} s {} ({source})", offset.abs(), if offset > 0 { "vor" } else { "nach" }),
            format!("{} s {} ({source})", offset.abs(), if offset > 0 { "fast" } else { "slow" }),
        )
    };
    if status == "ok" { check("clock", status, summary) } else { fix(check("clock", status, summary)) }
}

async fn mail(state: &AppState) -> Check {
    if !state.mailer.enabled() {
        return check("mail", "skipped", text("Kein Mailserver eingerichtet.", "No mail server set up.")).detail(text(
            "Einladungen gehen dann nur als Link, Codes der Zwei-Schritt-Anmeldung nicht per Mail.",
            "Invitations then go as links only, and two-step login codes not by mail.",
        ));
    }
    match state.mailer.test_connection().await {
        Ok(()) => check("mail", "ok", text("Der Mailserver nimmt die Anmeldung an", "The mail server takes the login")),
        Err(error) => {
            check("mail", "error", text(format!("Der Mailserver: {error}"), format!("The mail server: {error}"))).fix(
                text(
                    "Server, Port, Verschlüsselung, Benutzer und Passwort unter Einstellungen → Mail prüfen.",
                    "Check host, port, encryption, user and password under Settings → Mail.",
                ),
                None,
                None,
            )
        }
    }
}

async fn push_relay(state: &AppState) -> Check {
    let Some(push) = state.settings().push else {
        return check(
            "pushRelay",
            "skipped",
            text(
                "Kein Push-Relay eingerichtet: Die Handy-Apps synchronisieren beim Öffnen.",
                "No push relay set up: the phone apps sync when opened.",
            ),
        );
    };
    match state.relay.check(&push).await {
        Ok(()) => check("pushRelay", "ok", text("Das Relay nimmt Installations-ID und Schlüssel an", "The relay takes the installation id and key")),
        Err(error) => check("pushRelay", "error", text(format!("Das Relay: {error}"), format!("The relay: {error}"))).fix(
            text(
                "Installations-ID, Schlüssel und Region von bitwarden.com/host unter Einstellungen → Push-Relay prüfen.",
                "Check the installation id, key and region from bitwarden.com/host under Settings → Push relay.",
            ),
            None,
            None,
        ),
    }
}

async fn backup(state: &AppState) -> Check {
    let now = crate::auth::now_seconds();
    let fix = |check: Check| {
        check.fix(
            text(
                "Im Log nachsehen, warum das nächtliche Backup fehlt (oft: die Platte ist zu voll), und unter Backups eines von Hand schreiben.",
                "Look in the log for why the nightly backup is missing (often: the disk is too full), and write one by hand under Backups.",
            ),
            None,
            None,
        )
    };
    // Off-site backups (Stufe 4b, part B) add their age here too.
    let offsite = state.alerts.offsite_success();
    let offsite_text = offsite.map(|when| date_of(when as i64));
    let local = uwulock_store::backups::newest(&state.config.backups);
    let mut result = match local {
        Some(newest) => {
            let hours = (now - newest as i64) / 3600;
            let when = date_of(newest as i64);
            let summary =
                text(format!("Das neueste Backup ist vom {when}"), format!("The newest backup is from {when}"));
            if hours > crate::alerts::BACKUP_STALE_HOURS as i64 {
                fix(check("backup", "error", summary))
            } else {
                check("backup", "ok", summary)
            }
        }
        None => fix(check("backup", "warning", text("Noch kein Backup", "No backup yet"))),
    };
    if let Some(when) = offsite_text {
        result = result.detail(text(format!("Außer Haus: {when}"), format!("Off-site: {when}")));
    }
    // The target out of the house: whether the last backup there worked.
    let settings = state.offsite.settings().await.ok().filter(|settings| settings.enabled);
    if let Some(settings) = settings {
        let status = state.offsite.status().await;
        if let Some(error) = &status.last_error {
            result = offsite_fix(
                result.detail(text(format!("Außer Haus: {error}"), format!("Off-site: {error}"))).worst("warning"),
            );
        } else if uwulock_backup::Offsite::stale_hours(&settings, &status, now).is_some() {
            result = offsite_fix(
                result
                    .detail(text("Das Backup außer Haus ist zu alt", "The off-site backup is too old"))
                    .worst("warning"),
            );
        }
    }
    result
}

fn offsite_fix(check: Check) -> Check {
    if check.fix.is_some() {
        return check;
    }
    check.fix(
        text(
            "Unter Backups → Außer Haus die Verbindung testen: Ist das Ziel erreichbar, die Anmeldung gültig, genug Platz frei?",
            "Test the connection under Backups → Off-site: is the target reachable, the login valid, enough space free?",
        ),
        None,
        None,
    )
}

fn disk(state: &AppState) -> Check {
    let Some((free, total)) = state.config.data.ancestors().find_map(uwulock_store::backups::disk_space) else {
        return check(
            "disk",
            "skipped",
            text("Der freie Platz lässt sich hier nicht abfragen.", "Free space cannot be asked for here."),
        );
    };
    let (gb, percent) = (free as f64 / 1e9, if total > 0 { free as f64 * 100.0 / total as f64 } else { 0.0 });
    let summary = text(format!("{gb:.1} GB frei ({percent:.0} %)"), format!("{gb:.1} GB free ({percent:.0} %)"));
    let status = if free < total / 50 || free < 500 * 1024 * 1024 {
        "error"
    } else if free < total / 10 || free < 2 * 1024 * 1024 * 1024 {
        "warning"
    } else {
        "ok"
    };
    let result = check("disk", status, summary);
    if status == "ok" {
        return result;
    }
    result.fix(
        text(
            "Platz schaffen: alte Backups unter backups/ woandershin kopieren und löschen, oder dem Volume mehr Platz geben. Ohne Platz schreibt der Server auch keine Backups mehr.",
            "Make room: copy old backups under backups/ elsewhere and delete them, or give the volume more space. Without room the server writes no more backups either.",
        ),
        None,
        None,
    )
}

/// Loopback, private, link-local, shared address space: where a proxy usually is.
fn nearby(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64)
        }
        IpAddr::V6(ip) => {
            ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn client_ip_check(state: &AppState, parts: &Parts) -> Check {
    let Some(peer) = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|info| info.0.ip()) else {
        return check(
            "proxy.clientIp",
            "skipped",
            text("Nur beim Aufruf aus dem Admin-Portal", "Only when run from the admin portal"),
        );
    };
    let peer = match peer {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(peer, IpAddr::V4),
        v4 => v4,
    };
    let forwarded = parts.headers.contains_key("x-forwarded-for") || parts.headers.contains_key("x-real-ip");
    let trust = state.config.trust_forwarded;
    let seen = client_ip(parts, trust);
    let sees = text(format!("Der Server sieht dich als {seen}"), format!("The server sees you as {seen}"));
    let fix_forward = |check: Check| {
        check.fix(
            text(
                "Den Proxy die Adresse des Clients weitergeben lassen und UWULOCK_TRUST_FORWARDED=on setzen. Sonst teilen sich alle eine Adresse — und ein Rate-Limit.",
                "Let the proxy pass the client's address on and set UWULOCK_TRUST_FORWARDED=on. Otherwise everybody shares one address — and one rate limit.",
            ),
            Some("reverse_proxy uwulock:8443  # Caddy sets X-Forwarded-For by itself"),
            Some("proxy_set_header X-Forwarded-For $remote_addr;"),
        )
    };
    match (trust, forwarded, nearby(peer)) {
        (true, true, _) => check("proxy.clientIp", "ok", sees),
        (true, false, true) => fix_forward(
            check(
                "proxy.clientIp",
                "warning",
                text(format!("Der Proxy {peer} gibt keine Client-Adresse weiter"), format!("The proxy {peer} passes no client address")),
            )
            .detail(sees),
        ),
        (true, false, false) => check(
            "proxy.clientIp",
            "error",
            text(
                format!("UWULOCK_TRUST_FORWARDED ist an, aber {peer} spricht direkt mit dem Server"),
                format!("UWULOCK_TRUST_FORWARDED is on, but {peer} talks to the server directly"),
            ),
        )
        .detail(text(
            "Ohne Proxy davor kann so jeder eine falsche Adresse angeben und die Rate-Limits umgehen.",
            "Without a proxy in front, anybody can claim any address this way and get around the rate limits.",
        ))
        .fix(
            text(
                "UWULOCK_TRUST_FORWARDED=off setzen, solange kein Proxy davor steht.",
                "Set UWULOCK_TRUST_FORWARDED=off while no proxy is in front.",
            ),
            None,
            None,
        ),
        (false, true, true) => fix_forward(
            check(
                "proxy.clientIp",
                "error",
                text(
                    format!("Der Proxy {peer} gibt die Client-Adresse weiter, aber der Server glaubt sie nicht"),
                    format!("The proxy {peer} passes the client's address, but the server does not believe it"),
                ),
            )
            .detail(sees),
        ),
        (false, false, true) => fix_forward(
            check(
                "proxy.clientIp",
                "warning",
                text(format!("Alle Anfragen scheinen von {peer} zu kommen"), format!("Every request seems to come from {peer}")),
            )
            .detail(text(
                "Stimmt das (du bist im selben Netz, ohne Proxy), ist alles in Ordnung. Steht ein Proxy davor, gibt er die Adresse nicht weiter.",
                "If that is right (you are in the same network, without a proxy), all is well. If a proxy is in front, it does not pass the address on.",
            )),
        ),
        (false, _, false) => check("proxy.clientIp", "ok", sees),
    }
}

/// `scheme://host[:port]` of an address, in lower case.
fn origin_of(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    Some(parsed.origin().ascii_serialization())
}

fn public_url_check(state: &AppState, parts: &Parts) -> Check {
    let origin = parts.headers.get("origin").and_then(|value| value.to_str().ok()).map(str::to_string).or_else(|| {
        let host = parts.headers.get("x-forwarded-host").or_else(|| parts.headers.get("host"))?.to_str().ok()?;
        let scheme = parts
            .headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .unwrap_or(if state.config.public.starts_with("https") { "https" } else { "http" });
        Some(format!("{scheme}://{host}"))
    });
    let Some(origin) = origin else {
        return check(
            "proxy.publicUrl",
            "skipped",
            text("Nur beim Aufruf aus dem Admin-Portal", "Only when run from the admin portal"),
        );
    };
    let public = &state.config.public;
    if origin_of(&origin) == origin_of(public) {
        return check("proxy.publicUrl", "ok", text(format!("{public} stimmt"), format!("{public} matches")));
    }
    check(
        "proxy.publicUrl",
        "warning",
        text(
            format!("Das Portal ist als {origin} geöffnet, eingetragen ist {public}"),
            format!("The portal is open as {origin}, but the server is set up as {public}"),
        ),
    )
    .detail(text(
        "Links in Mails, Passkeys und die Apps nutzen die eingetragene Adresse.",
        "Links in mails, passkeys and the apps use the address that is set up.",
    ))
    .fix(
        text(
            "UWULOCK_PUBLIC auf die Adresse setzen, unter der der Server erreichbar ist, und den Host-Header am Proxy weitergeben.",
            "Set UWULOCK_PUBLIC to the address the server is reached at, and pass the Host header on at the proxy.",
        ),
        Some("lock.example.com {\n    reverse_proxy uwulock:8443  # passes Host on by itself\n}"),
        Some("proxy_set_header Host $host;\nproxy_set_header X-Forwarded-Proto $scheme;"),
    )
}

/// Each send domain: does its name lead somewhere, and is the certificate there one clients
/// trust? Its own ACME certificate is looked at on this server's listener, one from a proxy
/// where the name leads.
async fn send_domains(state: &AppState) -> Vec<Check> {
    let domains = state.send_domains.all();
    let tasks: Vec<_> =
        domains.iter().cloned().map(|domain| tokio::spawn(send_domain(state.clone(), domain))).collect();
    let mut checks = Vec::with_capacity(tasks.len());
    for task in tasks {
        if let Ok(check) = task.await {
            checks.push(check);
        }
    }
    checks
}

async fn send_domain(state: AppState, domain: uwulock_store::send_domains::SendDomain) -> Check {
    {
        let id = format!("certificate.{}", domain.host);
        if let Err(error) = tokio::net::lookup_host((domain.host.as_str(), 443)).await {
            return check(
                &id,
                "error",
                text(
                    format!("{} führt nirgendwohin: {error}", domain.host),
                    format!("{} leads nowhere: {error}", domain.host),
                ),
            )
            .fix(
                text(
                    format!("Leg im DNS einen A- oder AAAA-Eintrag für {} an, der auf diesen Server zeigt (oder auf den Proxy davor).", domain.host),
                    format!("Add an A or AAAA record for {} in DNS that points to this server (or to the proxy in front of it).", domain.host),
                ),
                None,
                None,
            );
        }
        let own = domain.tls == "acme" && state.send_domains.own_tls();
        let connect = match state.config.certificate_probe.as_ref() {
            Some(main) if own => main.connect.clone(),
            _ => format!("{}:443", domain.host),
        };
        let probe = crate::certificate::Probe { connect, name: domain.host.clone() };
        let seen = crate::certificate::look(&probe).await;
        judge(&id, &probe, seen)
    }
}

fn browser_pending(id: &str) -> Check {
    check(id, "skipped", text("Prüft der Browser im Admin-Portal", "Checked by the browser in the admin portal"))
}

async fn within<T>(check: impl std::future::Future<Output = T>) -> Option<T> {
    tokio::time::timeout(Duration::from_secs(25), check).await.ok()
}

/// Everything the server checks itself; the proxy checks from `parts`, the admin's request.
async fn run(state: &AppState, parts: Option<&Parts>) -> Stored {
    let (certificate, clock, mail, relay, backup, domains) = tokio::join!(
        within(certificate(state)),
        within(clock_check(state)),
        within(mail(state)),
        within(push_relay(state)),
        within(backup(state)),
        within(send_domains(state)),
    );
    let late =
        |id: &str| check(id, "error", text("Keine Antwort innerhalb von 25 Sekunden", "No answer within 25 seconds"));
    let mut checks = vec![
        certificate.unwrap_or_else(|| late("certificate")),
        clock.unwrap_or_else(|| late("clock")),
        mail.unwrap_or_else(|| late("mail")),
        relay.unwrap_or_else(|| late("pushRelay")),
        backup.unwrap_or_else(|| late("backup")),
        disk(state),
    ];
    match domains {
        Some(domains) => checks.extend(domains),
        None => {
            checks.extend(state.send_domains.all().iter().map(|domain| late(&format!("certificate.{}", domain.host))))
        }
    }
    match parts {
        Some(parts) => {
            checks.push(client_ip_check(state, parts));
            checks.push(public_url_check(state, parts));
        }
        None => {
            checks.push(browser_pending("proxy.clientIp"));
            checks.push(browser_pending("proxy.publicUrl"));
        }
    }
    checks.push(browser_pending("proxy.websocket"));
    checks.push(browser_pending("proxy.uploadLimit"));
    Stored { date: clock::now(), version: state.version.to_string(), checks }
}

async fn stored(state: &AppState) -> ApiResult<Option<Stored>> {
    Ok(state.store.setting(KEY).await?.and_then(|json| serde_json::from_str(&json).ok()))
}

async fn keep(state: &AppState, diagnosis: &Stored) -> ApiResult<()> {
    state.store.set_setting(KEY, &serde_json::to_string(diagnosis).expect("a diagnosis serializes")).await?;
    Ok(())
}

/// After a start with a version the server was not diagnosed with yet: the checks that need no
/// browser, kept for the portal.
pub async fn after_update(state: &AppState) {
    let last = state.store.setting(VERSION_KEY).await.ok().flatten();
    if last.as_deref() == Some(state.version) {
        return;
    }
    let diagnosis = run(state, None).await;
    let problems = diagnosis.checks.iter().filter(|check| check.status == "error").count();
    if let Err(error) = keep(state, &diagnosis).await {
        tracing::warn!(error = %error.message(), "the diagnosis could not be kept");
        return;
    }
    let _ = state.store.set_setting(VERSION_KEY, state.version).await;
    if problems > 0 {
        tracing::warn!(problems, "the diagnosis after the update found problems; see the admin portal");
    } else {
        tracing::info!("diagnosis after the update: nothing wrong");
    }
}

/// How the last diagnosis went, for the overview: its date, errors and warnings.
pub async fn summary(state: &AppState) -> Value {
    match stored(state).await.ok().flatten() {
        Some(diagnosis) => json!({
            "date": diagnosis.date,
            "errors": diagnosis.checks.iter().filter(|check| check.status == "error").count(),
            "warnings": diagnosis.checks.iter().filter(|check| check.status == "warning").count(),
        }),
        None => Value::Null,
    }
}

// ── The admin portal ──────────────────────────────────────

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/uwu/v1/admin/diagnosis", get(last).post(start))
        .route("/uwu/v1/admin/diagnosis/websocket", get(websocket))
        .route("/uwu/v1/admin/diagnosis/client", post(client))
}

/// The upload check takes bodies as large as the largest allowed file, so it is not under the
/// usual body limit.
pub(crate) fn upload_routes() -> Router<AppState> {
    Router::new().route("/uwu/v1/admin/diagnosis/upload", post(upload))
}

fn language(admin: &Admin) -> Language {
    Language::from_code(&admin.0.user.language)
}

async fn last(State(state): State<AppState>, admin: Admin) -> ApiResult<Json<Value>> {
    Ok(Json(match stored(&state).await? {
        Some(diagnosis) => diagnosis.render(language(&admin)),
        None => json!({ "object": "diagnosis", "date": null, "version": state.version, "checks": [] }),
    }))
}

async fn start(State(state): State<AppState>, admin: Admin, parts: Parts) -> ApiResult<Json<Value>> {
    let diagnosis = run(&state, Some(&parts)).await;
    keep(&state, &diagnosis).await?;
    Ok(Json(diagnosis.render(language(&admin))))
}

#[derive(Deserialize)]
struct SocketQuery {
    #[serde(default)]
    access_token: Option<String>,
}

/// A WebSocket that echoes one message: whether they get through the proxy. The browser cannot
/// set a header on a WebSocket, so the token comes in the query, as for the live-update hub.
async fn websocket(
    State(state): State<AppState>,
    Query(query): Query<SocketQuery>,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let session = Session::from_token(&state, query.access_token.as_deref().unwrap_or_default()).await?;
    if !session.user.admin {
        return Err(ApiError::forbidden("Only admins can do this."));
    }
    Ok(upgrade.max_message_size(1024).on_upgrade(|mut socket| async move {
        let echo = tokio::time::timeout(Duration::from_secs(10), socket.recv()).await;
        if let Ok(Some(Ok(Message::Text(message)))) = echo {
            let _ = socket.send(Message::Text(message)).await;
        }
        let _ = socket.send(Message::Close(None)).await;
    }))
}

/// Counts what comes and drops it, up to the largest allowed file.
async fn upload(State(state): State<AppState>, _admin: Admin, body: Body) -> ApiResult<Json<Value>> {
    use tokio_stream::StreamExt as _;
    let limit = crate::files::limit(&state);
    let mut stream = body.into_data_stream();
    let mut bytes: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ApiError::bad("The upload broke off."))?;
        bytes += chunk.len() as u64;
        if bytes > limit + 1024 * 1024 {
            return Err(ApiError::new(
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "More than the largest allowed file.",
            )
            .code("too_large"));
        }
    }
    Ok(Json(json!({ "object": "diagnosisUpload", "bytes": bytes })))
}

#[derive(Deserialize)]
struct SocketResult {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct UploadResult {
    ok: bool,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    bytes: u64,
}

#[derive(Deserialize)]
struct BrowserResults {
    #[serde(default)]
    websocket: Option<SocketResult>,
    #[serde(default)]
    upload: Option<UploadResult>,
}

/// What the browser found: merged into the kept diagnosis.
async fn client(
    State(state): State<AppState>,
    admin: Admin,
    Json(results): Json<BrowserResults>,
) -> ApiResult<Json<Value>> {
    let mut diagnosis = stored(&state).await?.unwrap_or_else(|| Stored {
        date: clock::now(),
        version: state.version.to_string(),
        checks: Vec::new(),
    });
    if let Some(socket) = results.websocket {
        diagnosis.merge(if socket.ok {
            check("proxy.websocket", "ok", text("WebSockets kommen durch", "WebSockets get through"))
        } else {
            let error: String = socket.error.unwrap_or_default().chars().take(200).collect();
            check("proxy.websocket", "error", text("WebSockets kommen nicht durch", "WebSockets do not get through"))
                .detail(text(error.clone(), error))
                .fix(
                    text(
                        "Den Proxy die Upgrade-Header weitergeben lassen. Ohne WebSockets erfahren Apps und Erweiterung erst beim nächsten Sync von Änderungen, und „Mit Gerät anmelden“ wartet.",
                        "Let the proxy pass the Upgrade headers on. Without WebSockets, apps and extension only hear of changes at their next sync, and \"log in with a device\" waits.",
                    ),
                    Some("lock.example.com {\n    reverse_proxy uwulock:8443  # WebSockets pass by themselves\n}"),
                    Some(NGINX_WEBSOCKET),
                )
        });
    }
    if let Some(upload) = results.upload {
        let largest = u64::from(state.settings().max_file_mb);
        let mb = upload.bytes / (1024 * 1024);
        let with_room = largest + largest / 20 + 1;
        let caddy = format!("request_body {{\n    max_size {with_room}MB\n}}");
        let nginx = format!("client_max_body_size {with_room}m;");
        diagnosis.merge(if upload.ok {
            let passed = check(
                "proxy.uploadLimit",
                "ok",
                text(format!("{mb} MB kamen durch (größte erlaubte Datei: {largest} MB)"), format!("{mb} MB got through (largest allowed file: {largest} MB)")),
            );
            if upload.bytes + 1024 * 1024 >= largest * 1024 * 1024 {
                passed
            } else {
                passed.detail(text(
                    "Geprüft wurde ein Teil der größten Datei; „Volle Größe prüfen“ schickt so viel wie die größte.",
                    "A part of the largest file was tried; \"Try the full size\" sends as much as the largest.",
                ))
            }
        } else {
            let status = upload.status.map_or_else(|| "?".to_string(), |status| status.to_string());
            check(
                "proxy.uploadLimit",
                "error",
                text(
                    format!("{mb} MB kamen nicht durch (Antwort {status}); erlaubt sind Dateien bis {largest} MB"),
                    format!("{mb} MB did not get through (answer {status}); files up to {largest} MB are allowed"),
                ),
            )
            .fix(
                text(
                    "Das Upload-Limit des Proxys über die größte erlaubte Datei heben, oder die größte Datei unter Einstellungen senken.",
                    "Raise the proxy's upload limit above the largest allowed file, or lower the largest file under Settings.",
                ),
                Some(&caddy),
                Some(&nginx),
            )
        });
    }
    keep(&state, &diagnosis).await?;
    Ok(Json(diagnosis.render(language(&admin))))
}

const CADDY_SITE: &str =
    "lock.example.com {\n    reverse_proxy uwulock:8443  # Caddy gets and renews the certificate itself\n}";
const NGINX_CERTBOT: &str =
    "certbot --nginx -d lock.example.com\nsystemctl enable --now certbot.timer  # renews in time";
const NGINX_WEBSOCKET: &str = "# in http { }:\nmap $http_upgrade $connection_upgrade { default upgrade; '' close; }\n\n# in the server's location / { }:\nproxy_http_version 1.1;\nproxy_set_header Upgrade $http_upgrade;\nproxy_set_header Connection $connection_upgrade;\nproxy_read_timeout 1h;";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use axum::http::StatusCode;

    async fn admin(server: &TestServer) -> Account {
        let token = server.invite("admin@example.com", true).await;
        server
            .call("POST", "/identity/accounts/register/finish", None, register_body("admin@example.com", &token))
            .await;
        server.login("admin@example.com", "admin-device").await
    }

    #[test]
    fn http_dates_are_read() {
        assert_eq!(
            http_date("Mon, 28 Sep 2026 12:00:00 GMT"),
            Some(time::macros::datetime!(2026-09-28 12:00 UTC).unix_timestamp())
        );
        assert_eq!(http_date("yesterday"), None);
    }

    #[tokio::test]
    async fn the_server_checks_what_it_can_and_the_browser_adds_the_rest() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let empty = json(server.get_as(&admin.token, "/uwu/v1/admin/diagnosis").await).await;
        assert_eq!(empty["checks"], json!([]));

        let request = axum::http::Request::post("/uwu/v1/admin/diagnosis")
            .header("authorization", format!("Bearer {}", admin.token))
            .header("origin", "https://other.example.com")
            .body(Body::empty())
            .unwrap();
        let ran = json(server.send(request).await).await;
        let find = |value: &Value, id: &str| {
            value["checks"].as_array().unwrap().iter().find(|check| check["id"] == id).cloned().unwrap()
        };
        assert_eq!(find(&ran, "certificate")["status"], "skipped", "no probe in tests");
        assert_eq!(find(&ran, "mail")["status"], "ok", "the test mailer takes everything");
        assert_eq!(find(&ran, "pushRelay")["status"], "skipped");
        assert_eq!(find(&ran, "backup")["status"], "warning");
        let public = find(&ran, "proxy.publicUrl");
        assert_eq!(public["status"], "warning");
        assert!(public["summary"].as_str().unwrap().contains("https://other.example.com"), "{public}");
        assert!(public["fix"]["nginx"].as_str().unwrap().contains("proxy_set_header Host"));
        assert_eq!(find(&ran, "proxy.websocket")["status"], "skipped");

        let results = json!({"websocket": {"ok": false, "error": "closed 1006"}, "upload": {"ok": false, "status": 413, "bytes": 16777216}});
        let merged =
            json(server.call("POST", "/uwu/v1/admin/diagnosis/client", Some(&admin.token), results).await).await;
        let socket = find(&merged, "proxy.websocket");
        assert_eq!(socket["status"], "error");
        assert!(socket["fix"]["nginx"].as_str().unwrap().contains("Upgrade"));
        let upload = find(&merged, "proxy.uploadLimit");
        assert_eq!(upload["status"], "error");
        assert!(upload["fix"]["nginx"].as_str().unwrap().contains("client_max_body_size 526m"), "{upload}");
        let again = json(server.get_as(&admin.token, "/uwu/v1/admin/diagnosis").await).await;
        assert_eq!(find(&again, "proxy.uploadLimit")["status"], "error", "kept");

        // In the admin's language.
        server.call("PUT", "/uwu/v1/account/language", Some(&admin.token), json!({"language": "de"})).await;
        let german = json(server.get_as(&admin.token, "/uwu/v1/admin/diagnosis").await).await;
        assert!(find(&german, "proxy.websocket")["summary"].as_str().unwrap().contains("kommen nicht durch"));
    }

    #[tokio::test]
    async fn an_upload_is_counted_and_dropped() {
        let server = TestServer::new().await;
        let admin = admin(&server).await;
        let request = axum::http::Request::post("/uwu/v1/admin/diagnosis/upload")
            .header("authorization", format!("Bearer {}", admin.token))
            .body(Body::from(vec![0u8; 3 * 1024 * 1024]))
            .unwrap();
        let answer = json(server.send(request).await).await;
        assert_eq!(answer["bytes"], 3 * 1024 * 1024);
        let user = server.account("nyu@example.com").await;
        let request = axum::http::Request::post("/uwu/v1/admin/diagnosis/upload")
            .header("authorization", format!("Bearer {}", user.token))
            .body(Body::from(vec![0u8; 16]))
            .unwrap();
        assert_eq!(server.send(request).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn after_an_update_it_runs_once_by_itself() {
        let server = TestServer::new().await;
        after_update(&server.state).await;
        let kept = stored(&server.state).await.unwrap().unwrap();
        assert_eq!(kept.version, "0.0.0-test");
        assert_eq!(server.state.store.setting(VERSION_KEY).await.unwrap().as_deref(), Some("0.0.0-test"));
        server.state.store.set_setting(KEY, "{}").await.unwrap();
        after_update(&server.state).await;
        assert_eq!(
            server.state.store.setting(KEY).await.unwrap().as_deref(),
            Some("{}"),
            "not again for the same version"
        );
    }
}
