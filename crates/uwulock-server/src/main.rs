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
enum SettingsAction {
    /// Everything, as the admin portal shows it (passwords and tokens only as whether there is one).
    List,
    /// One setting, like `adminNetworks` or `policies.requireTwoFactor`.
    Get { key: String },
    /// Change one setting: the value is JSON (`'[]'`, `true`, `'"text"'`); `-` reads it from
    /// standard input, for secrets that should not be in the shell's history. A running server
    /// takes admin networks over at once, everything else when it starts again.
    Set { key: String, value: String },
}

#[derive(Subcommand)]
enum FeaturesAction {
    /// Every switch, and whether it is on.
    List,
    /// Switch these on, like `families file-requests` (or `all`).
    On { names: Vec<String> },
    /// Switch these off. Nothing of them is deleted; switched on again, everything is back.
    Off { names: Vec<String> },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Back up to the other system now, with the settings of the admin portal.
    Offsite,
    /// The snapshots on the other system, with the settings of the admin portal.
    List,
    /// Put a snapshot from the other system into an empty data directory: for a new machine,
    /// before its server starts the first time. The recovery key comes from
    /// UWULOCK_BACKUP_KEY or is asked for; an SFTP password from UWULOCK_BACKUP_SFTP_PASSWORD;
    /// S3 keys from UWULOCK_BACKUP_S3_ACCESS_KEY and UWULOCK_BACKUP_S3_SECRET_KEY.
    Restore(Box<OffsiteRestore>),
}

#[derive(clap::Args)]
struct OffsiteRestore {
    /// An SFTP server: `user@host:path`.
    #[arg(long, group = "target")]
    sftp: Option<String>,
    /// The SFTP server's port.
    #[arg(long, default_value_t = 22)]
    port: u16,
    /// The SSH key to log in with (OpenSSH format); without it, the password from the
    /// environment.
    #[arg(long)]
    ssh_key: Option<PathBuf>,
    /// The SFTP server's host key as `SHA256:…`. Needed for SFTP: without it, the server is
    /// only asked for its key, which is then shown.
    #[arg(long)]
    host_key: Option<String>,
    /// An S3 bucket: `s3://bucket/folder`.
    #[arg(long, group = "target")]
    s3: Option<String>,
    /// The S3 address without the bucket, like https://s3.eu-central-1.amazonaws.com.
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long, default_value = "us-east-1")]
    region: String,
    /// `https://server/bucket/…` instead of `https://bucket.server/…` (MinIO and the like).
    #[arg(long)]
    path_style: bool,
    /// A folder on this machine, like a mounted disk.
    #[arg(long, group = "target")]
    folder: Option<PathBuf>,
    /// The snapshot to put back; without it, the newest, shown and confirmed first.
    #[arg(long)]
    snapshot: Option<String>,
    /// Only list the snapshots there.
    #[arg(long)]
    list: bool,
    /// The data directory to restore into, empty; the server's own without it.
    #[arg(long)]
    into: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve. The default.
    Serve,
    /// Write a consistent copy of the database, while the server runs. `backup offsite`,
    /// `backup list` and `backup restore` are the backups on another system.
    #[command(args_conflicts_with_subcommands = true)]
    Backup {
        /// Where to write it. The default is a dated file under `backups`.
        #[arg(long)]
        to: Option<PathBuf>,
        #[command(subcommand)]
        action: Option<BackupAction>,
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
    /// Read or change the settings of the admin portal. `settings set adminNetworks '[]'` lets the
    /// admin portal answer from everywhere again.
    Settings {
        #[command(subcommand)]
        action: SettingsAction,
    },
    /// Show the feature switches, or switch extras on or off (docs/features.md). A running server
    /// takes them over when it starts again; the admin portal does it at once.
    Features {
        #[command(subcommand)]
        action: Option<FeaturesAction>,
    },
    /// Move in from Vaultwarden: accounts, vaults, devices, two-step login, attachments, Sends,
    /// emergency access and organisations, from its data directory (`db.sqlite3` and the files
    /// next to it). Stop Vaultwarden first. A backup of this server's database is written before.
    ImportVaultwarden {
        /// Vaultwarden's data directory, the one with `db.sqlite3`.
        path: PathBuf,
        /// Only read, and tell what would come over.
        #[arg(long)]
        dry_run: bool,
        /// Make this account an admin here. Repeat for more.
        #[arg(long = "admin", value_name = "EMAIL")]
        admins: Vec<String>,
    },
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
    // `UWULOCK_LOG_FORMAT=json`: one JSON object a line, the same the server sends to Loki.
    let json = std::env::var("UWULOCK_LOG_FORMAT").is_ok_and(|format| format.trim().eq_ignore_ascii_case("json"));
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "uwulock_server=info,uwulock_api=info,uwulock_store=info,warn".into());
    // The log goes to stderr, so what a command prints on stdout is only that.
    let (text, json) = if json {
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .with_writer(std::io::stderr);
        (None, Some(layer))
    } else {
        (
            Some(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_ansi(std::io::stderr().is_terminal()),
            ),
            None,
        )
    };
    tracing_subscriber::registry().with(filter).with(text).with(json).with(logs.layer()).init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let config = Config::from_env()?;
    match cli.command.unwrap_or(Command::Serve) {
        // Asked every half minute, so it touches nothing but the network — not even the database.
        Command::Health => health::probe(&config),
        // Opening the database would be using it, and a restore needs it unused.
        Command::Restore { backup } => restore(&config, backup),
        Command::Backup { to, action: None } => runtime()?.block_on(async {
            let store = uwulock_server::open_store(&config)?;
            let path = backups::write(&store, &config.backups(), to).await?;
            println!("Written to {}", path.display());
            Ok(())
        }),
        Command::Backup { action: Some(action), .. } => runtime()?.block_on(offsite(config, action, logs)),
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
        Command::Settings { action } => runtime()?.block_on(settings(config, action)),
        Command::Features { action } => runtime()?.block_on(features(config, action.unwrap_or(FeaturesAction::List))),
        Command::ImportVaultwarden { path, dry_run, admins } => {
            runtime()?.block_on(import_vaultwarden(config, path, dry_run, admins))
        }
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

/// `uwulock-server settings list | get <key> | set <key> <value>`.
async fn settings(config: Config, action: SettingsAction) -> Result<(), String> {
    let store = uwulock_server::open_store(&config)?;
    let secret = uwulock_api::secret::ServerSecret::new(&config.data_dir);
    uwulock_api::secret::check_key(&store, &secret).await?;
    let current = uwulock_api::Settings::load(&store, &config.start_settings, &secret).await?;
    let find = |value: &serde_json::Value, key: &str| {
        key.split('.').filter(|part| !part.is_empty()).try_fold(value.clone(), |value, part| value.get(part).cloned())
    };
    match action {
        SettingsAction::List => {
            println!("{}", serde_json::to_string_pretty(&current.for_portal()).map_err(|error| error.to_string())?);
        }
        SettingsAction::Get { key } => {
            let value = find(&current.for_portal(), &key).ok_or_else(|| format!("There is no setting {key}."))?;
            println!("{}", serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?);
        }
        SettingsAction::Set { key, value } => {
            let text = if value == "-" {
                let mut text = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut text).map_err(|error| error.to_string())?;
                text.trim_end_matches(['\r', '\n']).to_string()
            } else {
                value
            };
            // JSON, or else the text as it is.
            let parsed = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
            let new = current.with(&key, parsed)?;
            new.save(&store, &secret).await?;
            let shown = find(&new.for_portal(), &key).unwrap_or(serde_json::Value::Null);
            println!("{key} is now {shown}.");
            if key != "adminNetworks" {
                println!("A running server takes it over when it starts again: docker compose restart uwulock");
            }
        }
    }
    Ok(())
}

/// `uwulock-server features [list | on <name>… | off <name>…]`.
async fn features(config: Config, action: FeaturesAction) -> Result<(), String> {
    use uwulock_api::{Feature, Features};
    let store = uwulock_server::open_store(&config)?;
    let mut current = Features::load(&store, &config.start_features).await?;
    let (names, on) = match action {
        FeaturesAction::List => {
            for feature in Feature::ALL {
                let state = if current.on(feature) { "on" } else { "off" };
                println!("{:<20} {state}", feature.id());
            }
            return Ok(());
        }
        FeaturesAction::On { names } => (names, true),
        FeaturesAction::Off { names } => (names, false),
    };
    if names.is_empty() {
        return Err(format!("Which? {}", Feature::ALL.map(Feature::id).join(", ")));
    }
    let named = Features::parse_list(&names.join(","))?;
    for feature in Feature::ALL.into_iter().filter(|feature| named.switched_on(*feature)) {
        current.set(feature, on);
    }
    current.save(&store).await.map_err(|error| error.to_string())?;
    println!("On now: {}", current.names().join(", "));
    println!("A running server takes it over when it starts again: docker compose restart uwulock");
    Ok(())
}

/// `uwulock-server import-vaultwarden <path> [--dry-run] [--admin <email>]…`.
async fn import_vaultwarden(config: Config, path: PathBuf, dry_run: bool, admins: Vec<String>) -> Result<(), String> {
    let store = uwulock_server::open_store(&config)?;
    let secret = uwulock_api::secret::ServerSecret::new(&config.data_dir);
    let settings = uwulock_api::Settings::load(&store, &config.start_settings, &secret).await?;
    if !dry_run {
        let backup = backups::write(&store, &config.backups(), None).await?;
        println!("Backup of this server first: {}", backup.display());
    }
    let summary = uwulock_server::vaultwarden::import(
        &store,
        &path,
        &config.data_dir,
        &admins,
        settings.default_language.code(),
        dry_run,
    )
    .await?;
    print!("{summary}");
    if dry_run {
        println!("Nothing was imported (--dry-run).");
        return Ok(());
    }
    println!("Imported. Point the clients at this server; they stay logged in.");
    // Organisations are managed with what families bring: that switch has to be on for them.
    if summary.organizations > 0 {
        let mut features = uwulock_api::Features::load(&store, &config.start_features).await?;
        if !features.switched_on(uwulock_api::Feature::Families) {
            features.set(uwulock_api::Feature::Families, true);
            features.save(&store).await.map_err(|error| error.to_string())?;
            println!("Families are switched on, for the organisations that came over.");
        }
    }
    // Whoever lost their only second step hears it from the server, not by surprise.
    if !summary.lost_two_factor.is_empty() {
        let mailer = uwulock_mail::Mailer::new(settings.smtp.as_ref()).map_err(|error| format!("mail: {error}"))?;
        for (email, language, method) in &summary.lost_two_factor {
            let mail = uwulock_mail::Mail::TwoFactorNotMoved { method: method.clone() };
            match mailer.send(email, &mail, uwulock_mail::Language::from_code(language)).await {
                Ok(()) => println!("Told {email} by mail that two-step login with {method} did not come over."),
                Err(_) if !mailer.enabled() => {
                    println!("Tell {email}: two-step login with {method} did not come over (no mail server set up).");
                }
                Err(error) => println!("Could not tell {email} by mail ({error}): tell them yourself."),
            }
        }
    }
    Ok(())
}

/// `uwulock-server backup offsite | list | restore …`.
async fn offsite(
    config: Config,
    action: BackupAction,
    logs: std::sync::Arc<uwulock_api::LogBuffer>,
) -> Result<(), String> {
    use uwulock_server::offsite as cli;
    match action {
        BackupAction::Offsite => {
            let store = uwulock_server::open_store(&config)?;
            let state = uwulock_server::app_state(&config, store, logs).await?;
            let report = uwulock_api::offsite::run_now(&state).await.map_err(|error| error.to_string())?;
            println!(
                "Snapshot {}: {} of {} uploaded; {} old snapshots removed.",
                report.snapshot,
                cli::size(report.uploaded),
                cli::size(report.total),
                report.removed_snapshots
            );
            Ok(())
        }
        BackupAction::List => {
            let store = uwulock_server::open_store(&config)?;
            let state = uwulock_server::app_state(&config, store, logs).await?;
            let snapshots = state.offsite.snapshots().await.map_err(|error| error.to_string())?;
            cli::print_snapshots(&snapshots);
            Ok(())
        }
        BackupAction::Restore(args) => {
            let env = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
            let target = if let Some(spec) = args.sftp {
                let private_key = match &args.ssh_key {
                    Some(path) => {
                        Some(std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?)
                    }
                    None => None,
                };
                cli::sftp_target(&spec, args.port, private_key, env("UWULOCK_BACKUP_SFTP_PASSWORD"), args.host_key)?
            } else if let Some(spec) = args.s3 {
                let endpoint = args.endpoint.ok_or("--s3 needs --endpoint, the S3 address without the bucket")?;
                let access = env("UWULOCK_BACKUP_S3_ACCESS_KEY").ok_or("set UWULOCK_BACKUP_S3_ACCESS_KEY")?;
                let secret = env("UWULOCK_BACKUP_S3_SECRET_KEY").ok_or("set UWULOCK_BACKUP_S3_SECRET_KEY")?;
                cli::s3_target(&spec, &endpoint, &args.region, access, secret, args.path_style)?
            } else if let Some(folder) = args.folder {
                cli::folder_target(&folder)
            } else {
                return Err("Say where the backups are: --sftp, --s3 or --folder.".into());
            };
            let key = match env("UWULOCK_BACKUP_KEY") {
                Some(key) => Some(key),
                None => cli::ask("Recovery key (empty for backups without encryption): ")?,
            };
            if args.list {
                let snapshots = cli::list(&target, key.as_deref()).await?;
                cli::print_snapshots(&snapshots);
                return Ok(());
            }
            let into = args.into.unwrap_or_else(|| config.data_dir.clone());
            // The newest one there, said with its date and confirmed: whoever keeps the storage
            // could have hidden newer ones (SV-L31).
            let snapshot = match args.snapshot {
                Some(name) => name,
                None => {
                    let snapshots = cli::list(&target, key.as_deref()).await?;
                    let newest = snapshots.first().ok_or("There are no snapshots there.")?;
                    println!("The newest snapshot there ({} in all):", snapshots.len());
                    cli::print_snapshots(std::slice::from_ref(newest));
                    if !cli::confirm("Put this one back? If newer ones should be there, answer no.")? {
                        return Err("Nothing restored. Pick one with --snapshot <name> (--list shows them).".into());
                    }
                    newest.name.clone()
                }
            };
            let manifest = cli::restore(&target, key.as_deref(), Some(&snapshot), &into).await?;
            println!(
                "Restored the snapshot {} of {} (UwULock Server {}) into {}.",
                manifest.name,
                manifest.hostname,
                manifest.version,
                into.display()
            );
            println!("Everybody logs in again. Backups to the other system are switched off on this machine:");
            println!("turn them on in the admin portal once the target is the right one.");
            println!("Start the server: docker compose up -d");
            Ok(())
        }
    }
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
