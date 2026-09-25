//! `uwulock-bench` — the same load against any Bitwarden-compatible server.
//!
//! "Faster than Vaultwarden" is only worth saying with numbers next to it. This sends one kind
//! of request as fast as a number of workers can for a while, and reports throughput and
//! latencies. It knows nothing about UwULock Server, so pointed at a Vaultwarden it measures that
//! one the same way; `.github/workflows/bench.yml` runs both on the same machine.
//!
//! Scenarios grow with the server: `alive` today; prelogin, login and sync with a seeded vault
//! once accounts and vaults are there.
//!
//! ```sh
//! uwulock-bench --target http://127.0.0.1:8443 --scenario alive --workers 32 --seconds 10
//! ```

use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "uwulock-bench", version, about = "Load for a Bitwarden-compatible server")]
struct Cli {
    /// The server, as a client would type it: http://127.0.0.1:8443
    #[arg(long)]
    target: String,
    #[arg(long, value_enum, default_value = "alive")]
    scenario: Scenario,
    /// Requests in flight at once.
    #[arg(long, default_value_t = 32)]
    workers: usize,
    /// How long to send, after a second of warming up.
    #[arg(long, default_value_t = 10)]
    seconds: u64,
    /// A name for the report: "uwulock", "vaultwarden".
    #[arg(long, default_value = "server")]
    label: String,
    /// Print the report as one line of JSON instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Scenario {
    /// `GET /alive`: what the server costs before it does anything — routing, middleware, HTTP.
    Alive,
}

impl Scenario {
    fn path(self) -> &'static str {
        match self {
            Scenario::Alive => "/alive",
        }
    }
}

#[derive(Serialize)]
struct Report {
    label: String,
    scenario: Scenario,
    workers: usize,
    seconds: f64,
    requests: u64,
    errors: u64,
    per_second: f64,
    p50_ms: f64,
    p90_ms: f64,
    p99_ms: f64,
    max_ms: f64,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = client()?;
    let url = format!("{}{}", cli.target.trim_end_matches('/'), cli.scenario.path());

    // Is anybody there at all, before the numbers mean anything.
    let first = client.get(&url).send().await.map_err(|error| format!("{url}: {error}"))?;
    if !first.status().is_success() {
        return Err(format!("{url} answered {}", first.status()));
    }

    // A second of warming up: connections opened, caches filled.
    run(&client, &url, cli.workers, Duration::from_secs(1)).await;
    let (latencies, errors, took) = run(&client, &url, cli.workers, Duration::from_secs(cli.seconds)).await;

    let report = report(&cli, latencies, errors, took);
    if cli.json {
        println!("{}", serde_json::to_string(&report).map_err(|error| error.to_string())?);
    } else {
        println!(
            "{label}  {scenario}  {per_second:.0} req/s  p50 {p50:.2} ms  p90 {p90:.2} ms  p99 {p99:.2} ms  max {max:.2} ms  ({requests} requests, {errors} errors, {workers} workers)",
            label = report.label,
            scenario = cli.scenario.path(),
            per_second = report.per_second,
            p50 = report.p50_ms,
            p90 = report.p90_ms,
            p99 = report.p99_ms,
            max = report.max_ms,
            requests = report.requests,
            errors = report.errors,
            workers = report.workers,
        );
    }
    Ok(())
}

/// `workers` loops sending requests until `duration` is up. Each keeps its latencies to itself,
/// so measuring costs no lock.
async fn run(
    client: &reqwest::Client,
    url: &str,
    workers: usize,
    duration: Duration,
) -> (Vec<Duration>, u64, Duration) {
    let url: Arc<str> = url.into();
    let started = Instant::now();
    let until = started + duration;
    let tasks: Vec<_> = (0..workers.max(1))
        .map(|_| {
            let client = client.clone();
            let url = url.clone();
            tokio::spawn(async move {
                let mut latencies = Vec::with_capacity(4096);
                let mut errors = 0u64;
                while Instant::now() < until {
                    let sent = Instant::now();
                    match client.get(&*url).send().await {
                        Ok(response) if response.status().is_success() => match response.bytes().await {
                            Ok(_) => latencies.push(sent.elapsed()),
                            Err(_) => errors += 1,
                        },
                        _ => errors += 1,
                    }
                }
                (latencies, errors)
            })
        })
        .collect();
    let mut all = Vec::new();
    let mut errors = 0;
    for task in tasks {
        if let Ok((latencies, failed)) = task.await {
            all.extend(latencies);
            errors += failed;
        }
    }
    (all, errors, started.elapsed())
}

fn report(cli: &Cli, mut latencies: Vec<Duration>, errors: u64, took: Duration) -> Report {
    latencies.sort_unstable();
    let at = |fraction: f64| -> f64 {
        if latencies.is_empty() {
            return 0.0;
        }
        let index = ((latencies.len() as f64 * fraction).ceil() as usize).clamp(1, latencies.len()) - 1;
        latencies[index].as_secs_f64() * 1000.0
    };
    Report {
        label: cli.label.clone(),
        scenario: cli.scenario,
        workers: cli.workers,
        seconds: took.as_secs_f64(),
        requests: latencies.len() as u64,
        errors,
        per_second: latencies.len() as f64 / took.as_secs_f64(),
        p50_ms: at(0.50),
        p90_ms: at(0.90),
        p99_ms: at(0.99),
        max_ms: latencies.last().map_or(0.0, |max| max.as_secs_f64() * 1000.0),
    }
}

fn client() -> Result<reqwest::Client, String> {
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .user_agent(concat!("uwulock-bench/", env!("CARGO_PKG_VERSION")))
        .pool_max_idle_per_host(1024)
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .build()
        .map_err(|error| error.to_string())
}
