//! `uwulock-server` — run it, or ask it something.
//!
//! With no arguments it serves. The other commands are the ones you reach for from a shell on
//! the box: take a backup, put one back, ask whether it is well.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use uwulock_server::{Config, backups, health, updates};
use uwulock_store::with_suffix;

#[derive(Parser)]
#[command(name = "uwulock-server", version, about = "A Bitwarden-compatible password server for UwULock")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve. The default.
    Serve,
    /// Write a consistent copy of the database, while the server runs.
    Backup {
        /// Where to write it. The default is a dated file under `backups`.
        #[arg(long)]
        to: Option<PathBuf>,
    },
    /// Put a backup back. Without a name, list the backups there are. Only while the server is
    /// stopped: `docker compose stop && docker compose run --rm uwulock restore <name>`
    Restore {
        /// A file under `backups`, or a path.
        backup: Option<PathBuf>,
    },
    /// Ask the running server whether it is well. The container's health check: the image has no
    /// shell and no curl, so the server asks itself.
    Health,
}

fn main() -> Result<(), String> {
    use std::io::IsTerminal;
    // Everything this server writes is its own: the database, the backups, the certificate key.
    // Nobody else on the machine reads them.
    #[cfg(unix)]
    // SAFETY: umask only sets this process's file mode mask; it cannot fail and touches no memory.
    unsafe {
        libc::umask(0o077);
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "uwulock_server=info,uwulock_api=info,uwulock_store=info,warn".into()),
        )
        // The log goes to stderr, so what a command prints on stdout is only that.
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let config = Config::from_env()?;
    match cli.command.unwrap_or(Command::Serve) {
        // Asked every half minute, so it touches nothing but the network — not even the database.
        Command::Health => health::probe(&config),
        // Opening the database would be using it, and a restore needs it unused.
        Command::Restore { backup } => restore(&config, backup),
        Command::Backup { to } => runtime()?.block_on(async {
            let store = uwulock_server::open_store(&config)?;
            let path = backups::write(&store, &config, to).await?;
            println!("Written to {}", path.display());
            Ok(())
        }),
        Command::Serve => runtime()?.block_on(serve(config)),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|error| error.to_string())
}

async fn serve(config: Config) -> Result<(), String> {
    let build = updates::build();
    tracing::info!(version = build.version, commit = build.commit.unwrap_or("-"), "UwULock Server");
    let store = uwulock_server::open_store(&config)?;
    uwulock_server::spawn_maintenance(config.clone(), store.clone());
    updates::spawn(std::sync::Arc::new(config.clone()));
    uwulock_server::run(config, store, uwulock_server::shutdown_signal(), None).await
}

/// `uwulock-server restore [name]`.
fn restore(config: &Config, backup: Option<PathBuf>) -> Result<(), String> {
    let Some(backup) = backup else {
        let found = backups::list(&config.backups());
        if found.is_empty() {
            println!("No backups in {} yet.", config.backups().display());
        }
        for (name, bytes) in found {
            println!("{name}  {} KiB", bytes.div_ceil(1024));
        }
        return Ok(());
    };
    // A bare name means one of the backups; anything else is a path.
    let path =
        if backup.components().count() == 1 && !backup.exists() { config.backups().join(&backup) } else { backup };
    let database = config.database();
    let aside = with_suffix(&database, &format!(".before-restore-{}", backups::stamp(backups::now_ms())));
    uwulock_store::restore(&path, &database, &aside)?;
    println!("Restored from {}.", path.display());
    if aside.exists() {
        println!("What was there before is kept as {}.", aside.display());
    }
    println!("Start the server again: docker compose up -d");
    Ok(())
}
