//! `uwulock-server` — run it, or ask it something.
//!
//! With no arguments it serves. The other commands are the ones you reach for from a shell on
//! the box: invite the first admin, take a backup, put one back, ask whether it is well — and
//! get back in when the only admin lost their second factor.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uwulock_server::{Config, health, updates};
use uwulock_store::backups;
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
    /// Invite somebody: prints the link to register with, and mails it if the server can.
    /// `docker compose exec uwulock uwulock-server invite --admin you@example.com` makes the first
    /// admin.
    Invite {
        email: String,
        /// The account will be an admin.
        #[arg(long)]
        admin: bool,
    },
    /// Make an account an admin, or (`--remove`) no longer one.
    Admin {
        email: String,
        #[arg(long)]
        remove: bool,
    },
    /// Turn off two-step login for an account whose owner lost their phone and recovery code.
    ResetTwoFactor { email: String },
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
    // The newest lines also stay in memory, for the admin portal.
    let logs = uwulock_api::LogBuffer::new(5000);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "uwulock_server=info,uwulock_api=info,uwulock_store=info,warn".into()),
        )
        // The log goes to stderr, so what a command prints on stdout is only that.
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_ansi(std::io::stderr().is_terminal()))
        .with(logs.layer())
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
            let path = backups::write(&store, &config.backups(), to).await?;
            println!("Written to {}", path.display());
            Ok(())
        }),
        Command::Invite { email, admin } => runtime()?.block_on(invite(config, email, admin, logs)),
        Command::Admin { email, remove } => runtime()?.block_on(async {
            let store = uwulock_server::open_store(&config)?;
            let user = store
                .user_by_email(&email)
                .await
                .map_err(|error| error.to_string())?
                .ok_or("There is no account for this address.")?;
            store.update_user(&user.id, move |user| user.admin = !remove).await.map_err(|error| error.to_string())?;
            println!("{} is {} an admin.", user.email, if remove { "no longer" } else { "now" });
            Ok(())
        }),
        Command::ResetTwoFactor { email } => runtime()?.block_on(async {
            let store = uwulock_server::open_store(&config)?;
            let user = store
                .user_by_email(&email)
                .await
                .map_err(|error| error.to_string())?
                .ok_or("There is no account for this address.")?;
            store.remove_two_factor(&user.id, None).await.map_err(|error| error.to_string())?;
            println!("Two-step login is off for {}. It can be set up again in the web vault.", user.email);
            Ok(())
        }),
        Command::Serve => runtime()?.block_on(serve(config, logs)),
    }
}

/// `uwulock-server invite [--admin] <email>`.
async fn invite(
    config: Config,
    email: String,
    admin: bool,
    logs: std::sync::Arc<uwulock_api::LogBuffer>,
) -> Result<(), String> {
    if config.public.is_none() {
        eprintln!("UWULOCK_PUBLIC is not set, so the link below points at this machine's own address.");
    }
    let store = uwulock_server::open_store(&config)?;
    let state = uwulock_server::app_state(&config, store, logs).await?;
    let invited = uwulock_api::invite(&state, &email, admin, None).await.map_err(|error| error.message())?;
    println!("Invited {}{}.", invited.email, if admin { " as an admin" } else { "" });
    if invited.mailed {
        println!("The invitation went out by mail. The link, in case it does not arrive:");
    } else {
        println!("Pass this link on — it is the only way to register with this invitation:");
    }
    println!("{}", invited.link);
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|error| error.to_string())
}

async fn serve(config: Config, logs: std::sync::Arc<uwulock_api::LogBuffer>) -> Result<(), String> {
    let build = updates::build();
    tracing::info!(version = build.version, commit = build.commit.unwrap_or("-"), "UwULock Server");
    let store = uwulock_server::open_store(&config)?;
    uwulock_server::run(config, store, logs, uwulock_server::shutdown_signal(), None).await
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
