use std::{
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::sync::{mpsc, oneshot};
use watermelon_pgp_core::{
    audit::Actor,
    crypto::{self, Algorithm, Container, RevocationReason},
    envelope::MasterKey,
    jobs::{Job, JobKind, JobSpec, VerifyPolicy},
    store::{KeyOwner, KeyRecord},
    vault::{self, Vault},
};
use watermelon_pgp_jobs::{Engine, PassReport, scan::Scanner};

mod service;

/// Manage OpenPGP keys and folder encrypt/decrypt jobs.
#[derive(Parser)]
#[command(name = "watermelonpgp", version)]
struct Cli {
    /// Directory holding the database.
    #[arg(
        long,
        global = true,
        env = "WATERMELONPGP_DATA_DIR",
        default_value = "data"
    )]
    data_dir: PathBuf,
    /// Master keyfile [default: <data-dir>/master.key]. Ignored when WATERMELONPGP_MASTER_KEY is set.
    #[arg(long, global = true, env = "WATERMELONPGP_MASTER_KEY_FILE")]
    master_key: Option<PathBuf>,
    /// Read the password or passphrase from the first line of stdin instead of prompting.
    #[arg(long, global = true)]
    passphrase_stdin: bool,
    /// Log format for `serve` and `run`. Levels are set with WATERMELONPGP_LOG (default: info).
    #[arg(long, global = true, env = "WATERMELONPGP_LOG_FORMAT", value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    /// Append the log of `serve` and `run` to this file instead of writing it to stderr
    /// [Windows service default: <data-dir>\watermelonpgp.log].
    #[arg(long, global = true, env = "WATERMELONPGP_LOG_FILE")]
    log_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    /// One JSON object per line, for log collectors.
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Create the database, master keyfile and admin password.
    Init,
    /// Manage customers.
    #[command(subcommand)]
    Customer(CustomerCommand),
    /// Manage keys.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Show the most recent audit log entries, newest first.
    Audit {
        /// How many entries to show.
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Write a consistent snapshot of the database. Does NOT include the master key.
    Backup {
        /// File to write; must not exist yet.
        dest: PathBuf,
    },
    /// Change the admin password.
    Passwd,
    /// Manage folder jobs.
    #[command(subcommand)]
    Job(JobCommand),
    /// Serve the web UI and run all enabled jobs until stopped (Ctrl-C or SIGTERM).
    Serve(ServeArgs),
    /// Run all enabled jobs until stopped (Ctrl-C or SIGTERM), without the web UI.
    Run {
        /// Jobs processed in parallel [default: number of CPUs].
        #[arg(long)]
        workers: Option<usize>,
    },
    /// Install or remove the Windows service (Windows only).
    #[command(subcommand, hide = !cfg!(windows))]
    Service(ServiceCommand),
}

#[derive(clap::Args, Clone, Debug, PartialEq)]
struct ServeArgs {
    /// Address and port to listen on. For anything but loopback, use --tls-cert/--tls-key or
    /// a TLS-terminating reverse proxy.
    #[arg(long, env = "WATERMELONPGP_BIND", default_value = "127.0.0.1:8080")]
    bind: std::net::SocketAddr,
    /// Jobs processed in parallel [default: number of CPUs].
    #[arg(long)]
    workers: Option<usize>,
    /// Mark the session cookie Secure. Set this when a reverse proxy terminates HTTPS;
    /// implied by --tls-cert.
    #[arg(long, env = "WATERMELONPGP_SECURE_COOKIES")]
    secure_cookies: bool,
    /// Serve HTTPS with this PEM certificate chain. Reloaded on SIGHUP (Unix) or
    /// `sc.exe control <service> paramchange` (Windows service).
    #[arg(long, env = "WATERMELONPGP_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// PEM private key for --tls-cert.
    #[arg(long, env = "WATERMELONPGP_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Install `serve` as a Windows service running as NT SERVICE\<name>, with these options
    /// and the global ones. Run `init` first, from an elevated prompt. The data directory and
    /// master keyfile are handed over to the service's account.
    Install {
        /// Service name; the service runs as NT SERVICE\<name>.
        #[arg(long, default_value = service::DEFAULT_NAME)]
        name: String,
        #[command(flatten)]
        serve: ServeArgs,
    },
    /// Stop the service if it runs (jobs finish their current file) and remove it. The data
    /// directory and master key are kept.
    Uninstall {
        /// Service name.
        #[arg(long, default_value = service::DEFAULT_NAME)]
        name: String,
    },
    /// The service's entry point, started by Windows.
    #[command(hide = true)]
    Run {
        #[arg(long, default_value = service::DEFAULT_NAME)]
        name: String,
        #[command(flatten)]
        serve: ServeArgs,
    },
}

const LOG_FILE: &str = "watermelonpgp.log";

/// What a running `serve` is asked to do: by signals in a console, by the service manager in a
/// Windows service.
#[derive(Debug)]
enum Control {
    /// Stop serving; running jobs finish their current file.
    Stop,
    /// Reload the TLS certificate and key.
    ReloadTls,
}

#[derive(Subcommand)]
enum JobCommand {
    /// Create a job.
    // Boxed: a PathBuf is larger on Windows, which makes this variant too big for clippy.
    #[command(subcommand)]
    Add(Box<AddJob>),
    /// List jobs with their state and folders.
    List,
    /// Show one job's settings and state.
    Show {
        /// Job ID or name.
        job: String,
    },
    /// Enable a job, or resume a paused one (its keys are checked again).
    Enable {
        /// Job ID or name.
        job: String,
    },
    /// Stop a job from running; it keeps its settings.
    Disable {
        /// Job ID or name.
        job: String,
    },
    /// Delete a job. Its folders and files are left alone; the audit log keeps its history.
    Delete {
        /// Job ID or name.
        job: String,
    },
    /// Run one polling pass now, waiting for files to settle first. Useful for testing a job
    /// or running it from cron instead of `serve`/`run`.
    RunOnce {
        /// Job ID or name.
        job: String,
        /// Seconds a file must stay unchanged before it is processed.
        #[arg(long, default_value_t = 2)]
        settle: u64,
    },
}

#[derive(Subcommand)]
enum AddJob {
    /// Encrypt every file dropped into the input folder.
    Encrypt {
        #[command(flatten)]
        common: CommonJobArgs,
        /// Recipient key (fingerprint or key ID). Repeat for several recipients.
        #[arg(long = "recipient", required = true)]
        recipients: Vec<String>,
        /// Sign with this secret key.
        #[arg(long)]
        sign_with: Option<String>,
        /// ASCII-armored output (.asc).
        #[arg(long)]
        armor: bool,
        /// Output extension, e.g. ".gpg" [default: .pgp, or .asc with --armor].
        #[arg(long)]
        extension: Option<String>,
        /// Use the RFC 9580 SEIPD v2 format; only for partners known to support it.
        #[arg(long)]
        seipd_v2: bool,
    },
    /// Decrypt every file dropped into the input folder.
    Decrypt {
        #[command(flatten)]
        common: CommonJobArgs,
        /// Secret key to decrypt with. Repeat to try several.
        #[arg(long = "key", required = true)]
        keys: Vec<String>,
        /// Sender key whose signatures are accepted. Repeat for several.
        #[arg(long = "verify-with")]
        verifiers: Vec<String>,
        /// What to do with unsigned or unverifiable files.
        #[arg(long, value_enum, default_value_t = PolicyArg::Ignore)]
        verify: PolicyArg,
    },
}

#[derive(clap::Args)]
struct CommonJobArgs {
    /// Customer the job belongs to.
    #[arg(long)]
    customer: String,
    /// Job name, unique per customer.
    #[arg(long)]
    name: String,
    /// Folder to watch. Must exist.
    #[arg(long)]
    input: PathBuf,
    /// Folder the results are written to. Must exist.
    #[arg(long)]
    output: PathBuf,
    /// Where processed source files go [default: <input>/processed].
    #[arg(long, conflicts_with = "delete_processed")]
    processed: Option<PathBuf>,
    /// Delete source files after successful processing instead of archiving them.
    #[arg(long)]
    delete_processed: bool,
    /// Where failed source files go [default: <input>/failed].
    #[arg(long)]
    failed: Option<PathBuf>,
    /// Seconds between scans of the input folder (at least 5). A file is processed once it is
    /// unchanged across two scans.
    #[arg(long, default_value_t = 30)]
    interval: u32,
}

#[derive(Clone, Copy, ValueEnum)]
enum PolicyArg {
    Ignore,
    Warn,
    Require,
}

#[derive(Subcommand)]
enum CustomerCommand {
    /// Create a customer.
    Add {
        /// Unique name, e.g. "ACME".
        name: String,
    },
    /// List customers with their number of keys.
    List,
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Generate a new key pair.
    Gen {
        /// Customer the key belongs to. Without it, the key is anonymous: it belongs to no
        /// customer.
        #[arg(long)]
        customer: Option<String>,
        /// User ID, e.g. "ACME Exports <exports@acme.example>".
        #[arg(long)]
        uid: String,
        /// curve25519 (Ed25519 + Cv25519) is recommended; rsa4096 for partners whose software
        /// can't handle it. Both are readable by GnuPG 2.2 and later.
        #[arg(long, value_enum, default_value_t = AlgorithmArg::Curve25519)]
        algorithm: AlgorithmArg,
    },
    /// Import public and/or secret keys from a file (armored or binary).
    Import {
        /// Customer the keys belong to. Without it, they are anonymous keys.
        #[arg(long)]
        customer: Option<String>,
        /// Key file. Protected secret keys prompt for their passphrase.
        file: PathBuf,
    },
    /// List keys.
    List {
        /// Only this customer's keys.
        #[arg(long)]
        customer: Option<String>,
    },
    /// Export a key, armored. Secret exports are protected with a new passphrase.
    Export {
        /// Fingerprint or key ID.
        key: String,
        /// Export the secret key; prompts for a new passphrase to protect it.
        #[arg(long)]
        secret: bool,
        /// Output file [default: stdout].
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Delete a key (it stays in the database for the audit trail). Refused while jobs use it.
    Delete {
        /// Fingerprint or key ID.
        key: String,
    },
    /// Revoke one of our keys. Give partners the new public key (`key export`) afterwards.
    Revoke {
        /// Fingerprint or key ID.
        key: String,
        /// Why the key is revoked; recorded in the revocation.
        #[arg(long, value_enum, default_value_t = ReasonArg::Unspecified)]
        reason: ReasonArg,
        /// Free-text explanation stored in the revocation.
        #[arg(long, default_value = "")]
        comment: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ReasonArg {
    /// No reason given.
    Unspecified,
    /// Replaced by a new key.
    Superseded,
    /// The secret key may have leaked.
    Compromised,
    /// No longer used.
    Retired,
}

#[derive(Clone, Copy, ValueEnum)]
enum AlgorithmArg {
    Curve25519,
    Rsa4096,
}

fn main() -> Result<()> {
    check_legacy_env(std::env::vars_os())?;
    let Cli {
        data_dir,
        master_key,
        passphrase_stdin,
        log_format,
        log_file,
        command,
    } = Cli::parse();
    let prompt = Prompt {
        stdin: passphrase_stdin,
    };
    let master_key_path = master_key.unwrap_or_else(|| data_dir.join(vault::MASTER_KEY_FILE));

    let command = match command {
        Command::Init => return init(&data_dir, &master_key_path, prompt),
        Command::Service(_) if !cfg!(windows) => bail!(service::NOT_WINDOWS),
        Command::Service(command) => {
            let log_file = log_file.unwrap_or_else(|| data_dir.join(LOG_FILE));
            return match command {
                ServiceCommand::Install { name, serve } => service::install(
                    &name,
                    &service::Settings {
                        data_dir: &data_dir,
                        master_key: &master_key_path,
                        log_format,
                        log_file: &log_file,
                        serve: &serve,
                    },
                ),
                ServiceCommand::Uninstall { name } => service::uninstall(&name),
                ServiceCommand::Run { name, serve } => {
                    let work = move |controls, ready: &dyn Fn()| {
                        if let Err(e) = init_logging(log_format, Some(&log_file)) {
                            // Leave a trace where an administrator will look: the default log
                            // in the data directory.
                            let fallback = data_dir.join(LOG_FILE);
                            if fallback != log_file
                                && init_logging(log_format, Some(&fallback)).is_ok()
                            {
                                tracing::error!(error = format!("{e:#}"), "not starting");
                            }
                            return Err(e);
                        }
                        let vault = open_vault(&data_dir, &master_key_path)?;
                        let runtime =
                            tokio::runtime::Runtime::new().context("starting the async runtime")?;
                        serve_with(&runtime, vault, serve, controls, ready)
                    };
                    service::run(name, work)
                }
            };
        }
        command => command,
    };
    if matches!(command, Command::Serve { .. } | Command::Run { .. }) {
        init_logging(log_format, log_file.as_deref())?;
    }
    let vault = open_vault(&data_dir, &master_key_path)?;
    match command {
        Command::Serve(args) => serve(vault, args),
        Command::Run { workers } => run_engine(vault, workers),
        Command::Job(JobCommand::RunOnce { job, settle }) => run_once(vault, &job, settle),
        command => run(&vault, command, prompt),
    }
}

fn open_vault(data_dir: &Path, master_key: &Path) -> Result<Vault> {
    Ok(Vault::open(
        &vault::db_path(data_dir)?,
        MasterKey::load(master_key)?,
    )?)
}

/// The prefix of the environment variables up to 0.3, when the command was `watermelon`.
const LEGACY_ENV_PREFIX: &str = "WATERMELON_";
const ENV_PREFIX: &str = "WATERMELONPGP_";

/// Refuse to start while a `WATERMELON_*` variable from before the rename is set: ignoring it
/// would quietly change what runs (no TLS, another data directory, the keyfile instead of the
/// key in the environment).
fn check_legacy_env(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Result<()> {
    let mut renamed: Vec<String> = vars
        .into_iter()
        .filter_map(|(name, _)| {
            let name = name.into_string().ok()?;
            // Windows reads environment variables in any case.
            let matches = if cfg!(windows) {
                name.get(..LEGACY_ENV_PREFIX.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(LEGACY_ENV_PREFIX))
            } else {
                name.starts_with(LEGACY_ENV_PREFIX)
            };
            matches.then(|| {
                format!(
                    "{name} is now {ENV_PREFIX}{}",
                    &name[LEGACY_ENV_PREFIX.len()..]
                )
            })
        })
        .collect();
    if renamed.is_empty() {
        return Ok(());
    }
    renamed.sort();
    bail!(
        "the environment variables were renamed along with the command; set the new names \
         and unset the old ones:\n  {}",
        renamed.join("\n  ")
    )
}

/// Log to stderr, or append to `file`.
fn init_logging(format: LogFormat, file: Option<&Path>) -> Result<()> {
    use tracing_subscriber::fmt::writer::BoxMakeWriter;
    let filter = tracing_subscriber::EnvFilter::try_from_env("WATERMELONPGP_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let (writer, ansi) = match file {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("opening the log file {}", path.display()))?;
            (BoxMakeWriter::new(Mutex::new(file)), false)
        }
        None => (
            BoxMakeWriter::new(std::io::stderr),
            std::io::IsTerminal::is_terminal(&std::io::stderr()),
        ),
    };
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(ansi)
        .with_target(false);
    match format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().flatten_event(true).init(),
    }
    Ok(())
}

/// Log a job pass that did something or went wrong; quiet passes stay quiet.
fn log_pass(job: &str, report: &PassReport) {
    let PassReport {
        processed,
        failed,
        error,
        paused,
        removed_temp_files,
    } = report;
    if *removed_temp_files > 0 {
        tracing::warn!(
            job,
            removed_temp_files,
            "removed temp files left behind by an earlier crash"
        );
    }
    if let Some(reason) = paused {
        tracing::warn!(job, reason, "job paused");
    } else if let Some(error) = error {
        tracing::error!(job, processed, failed, error, "job pass failed");
    } else if *failed > 0 {
        tracing::warn!(job, processed, failed, "files failed");
    } else if *processed > 0 {
        tracing::info!(job, processed, "files processed");
    }
}

fn run_engine(vault: Vault, workers: Option<usize>) -> Result<()> {
    let active = vault.jobs()?.iter().filter(|job| job.is_active()).count();
    let workers = workers.unwrap_or_else(Engine::default_workers);
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("installing Ctrl-C handler")?;
    }
    tracing::info!(active, workers, "running jobs; Ctrl-C to stop");
    Engine::new(Arc::new(Mutex::new(vault)), workers).run(&stop, log_pass);
    tracing::info!("stopped");
    Ok(())
}

/// `serve` in a console: Ctrl-C and SIGTERM stop it, SIGHUP reloads the TLS certificate.
fn serve(vault: Vault, args: ServeArgs) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    let (controls, received) = mpsc::unbounded_channel();
    runtime.spawn(forward_signals(controls));
    serve_with(&runtime, vault, args, received, &|| {})
}

/// Serve the web UI and run the job engine until told to stop by `controls` (or until every
/// sender is gone). Calls `ready` once listening.
fn serve_with(
    runtime: &tokio::runtime::Runtime,
    vault: Vault,
    args: ServeArgs,
    controls: mpsc::UnboundedReceiver<Control>,
    ready: &dyn Fn(),
) -> Result<()> {
    let ServeArgs {
        bind,
        workers,
        secure_cookies,
        tls_cert,
        tls_key,
    } = args;
    let tls_files = tls_cert.zip(tls_key);
    let workers = workers.unwrap_or_else(Engine::default_workers);
    let vault = Arc::new(Mutex::new(vault));
    let stop = Arc::new(AtomicBool::new(false));
    let tls = match &tls_files {
        Some((cert, key)) => Some(
            runtime
                .block_on(watermelon_pgp_web::Tls::load(cert, key))
                .with_context(|| {
                    format!(
                        "loading TLS certificate {} and key {}",
                        cert.display(),
                        key.display()
                    )
                })?,
        ),
        None => None,
    };
    let listener =
        std::net::TcpListener::bind(bind).with_context(|| format!("listening on {bind}"))?;

    let engine = {
        let engine = Engine::new(Arc::clone(&vault), workers);
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("jobs".into())
            .spawn(move || engine.run(&stop, log_pass))
            .context("starting the job engine")?
    };

    let scheme = if tls.is_some() { "https" } else { "http" };
    tracing::info!(url = format!("{scheme}://{bind}"), workers, "serving");
    if tls.is_none() && !bind.ip().is_loopback() && !secure_cookies {
        tracing::warn!(
            "listening on a non-loopback address over plain HTTP: use --tls-cert/--tls-key, or \
             put a TLS-terminating reverse proxy in front and pass --secure-cookies"
        );
    }
    let (request_stop, stop_requested) = oneshot::channel();
    runtime.spawn(handle_controls(
        controls,
        tls.clone().zip(tls_files),
        request_stop,
    ));
    let state = watermelon_pgp_web::AppState::new(
        Arc::clone(&vault),
        watermelon_pgp_web::Config {
            secure_cookies: secure_cookies || tls.is_some(),
            hsts: tls.is_some(),
        },
    );
    ready();
    let served = runtime.block_on(watermelon_pgp_web::serve(state, listener, tls, async {
        let _ = stop_requested.await;
    }));

    tracing::info!("stopping; running jobs finish their current file first");
    stop.store(true, Ordering::Relaxed);
    if engine.join().is_err() {
        bail!("the job engine panicked");
    }
    tracing::info!("stopped");
    Ok(served?)
}

/// Act on `controls` until told to stop, then fire `request_stop`.
async fn handle_controls(
    mut controls: mpsc::UnboundedReceiver<Control>,
    tls: Option<(watermelon_pgp_web::Tls, (PathBuf, PathBuf))>,
    request_stop: oneshot::Sender<()>,
) {
    while let Some(control) = controls.recv().await {
        match control {
            Control::Stop => break,
            Control::ReloadTls => {
                let Some((tls, (cert, key))) = &tls else {
                    tracing::info!("no TLS certificate to reload");
                    continue;
                };
                match tls.reload(cert, key).await {
                    Ok(()) => tracing::info!("TLS certificate reloaded"),
                    Err(e) => {
                        tracing::error!(error = %e, "TLS certificate reload failed; keeping the old one")
                    }
                }
            }
        }
    }
    let _ = request_stop.send(());
}

/// Ctrl-C, or SIGTERM (systemd, Docker), stop; SIGHUP (systemctl reload) reloads the TLS
/// certificate.
async fn forward_signals(controls: mpsc::UnboundedSender<Control>) {
    // Always handle SIGHUP: its default action would end the process.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut hangups) = signal(SignalKind::hangup()) {
            let controls = controls.clone();
            tokio::spawn(async move {
                while hangups.recv().await.is_some() {
                    let _ = controls.send(Control::ReloadTls);
                }
            });
        }
    }
    shutdown_signal().await;
    let _ = controls.send(Control::Stop);
}

/// Resolves on Ctrl-C, or SIGTERM (systemd, Docker).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = term => {}
    }
}

fn run_once(vault: Vault, query: &str, settle: u64) -> Result<()> {
    let job = vault.find_job(query)?;
    if !job.is_active() {
        bail!(
            "job {:?} is not active ({})",
            job.spec.name,
            job_state(&job)
        );
    }
    let vault = Mutex::new(vault);
    let mut scanner = Scanner::default();
    // The first scan only observes; files unchanged at the second scan are processed.
    scanner.scan(&job.spec.input_dir)?;
    std::thread::sleep(Duration::from_secs(settle));
    let report = watermelon_pgp_jobs::run_pass(&vault, job.id, &mut scanner);
    println!("{}", describe_pass(&report));
    if report.error.is_some() || report.paused.is_some() || report.failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn describe_pass(report: &PassReport) -> String {
    let mut parts = vec![format!(
        "{} processed, {} failed",
        report.processed, report.failed
    )];
    if let Some(error) = &report.error {
        parts.push(format!("error: {error}"));
    }
    if let Some(reason) = &report.paused {
        parts.push(format!("PAUSED: {reason}"));
    }
    parts.join("; ")
}

fn init(data_dir: &Path, master_key_path: &Path, prompt: Prompt) -> Result<()> {
    let password = prompt.new_secret("Admin password", vault::MIN_ADMIN_PASSWORD_LEN)?;
    let report = Vault::init(data_dir, master_key_path, &password)?;
    println!("Created {}", report.db_path.display());
    println!("Created {}", report.master_key_path.display());
    eprintln!();
    eprintln!("IMPORTANT: back up the master key now and store it separately from the database.");
    eprintln!("Without it, every secret key in the database is unrecoverable, and");
    eprintln!("`watermelonpgp backup` deliberately does not include it.");
    Ok(())
}

fn run(vault: &Vault, command: Command, prompt: Prompt) -> Result<()> {
    match command {
        Command::Init => unreachable!("handled before opening the vault"),
        Command::Customer(CustomerCommand::Add { name }) => {
            let customer = vault.create_customer(Actor::Cli, &name)?;
            println!("Created customer {:?}", customer.name);
        }
        Command::Customer(CustomerCommand::List) => {
            for customer in vault.customers()? {
                let keys = vault.keys(Some(customer.id))?.len();
                println!("{:<30} {keys} key(s)", customer.name);
            }
        }
        Command::Key(KeyCommand::Gen {
            customer,
            uid,
            algorithm,
        }) => {
            let customer = customer.map(|name| vault.customer(&name)).transpose()?;
            let algorithm = match algorithm {
                AlgorithmArg::Curve25519 => Algorithm::Curve25519,
                AlgorithmArg::Rsa4096 => Algorithm::Rsa4096,
            };
            let key = vault.generate_key(Actor::Cli, customer.map(|c| c.id), &uid, algorithm)?;
            println!("Generated {}", key.fingerprint);
        }
        Command::Key(KeyCommand::Import { customer, file }) => {
            let customer = customer.map(|name| vault.customer(&name)).transpose()?;
            let data =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let locked = crypto::parse_certs(&data)?
                .iter()
                .any(crypto::Cert::is_locked);
            let passphrase = if locked {
                Some(prompt.secret("Passphrase of the secret key(s)")?)
            } else {
                None
            };
            for key in vault.import_keys(
                Actor::Cli,
                customer.map(|c| c.id),
                &data,
                passphrase.as_deref(),
            )? {
                println!(
                    "Imported or updated {} {} ({})",
                    key.fingerprint,
                    key.label(),
                    if key.has_secret { "secret" } else { "public" }
                );
            }
        }
        Command::Key(KeyCommand::List { customer }) => {
            let customer_id = customer.map(|name| vault.customer(&name)).transpose()?;
            print_keys(&vault.keys(customer_id.map(|c| c.id))?);
        }
        Command::Key(KeyCommand::Export {
            key,
            secret,
            output,
        }) => {
            let armored = if secret {
                let passphrase = prompt.new_secret("Passphrase for the exported key", 8)?;
                vault.export_secret(Actor::Cli, &key, &passphrase)?
            } else {
                vault.export_public(Actor::Cli, &key)?
            };
            match output {
                Some(path) => write_new_file(&path, armored.as_bytes(), secret)?,
                None => std::io::stdout().write_all(armored.as_bytes())?,
            }
        }
        Command::Key(KeyCommand::Revoke {
            key,
            reason,
            comment,
        }) => {
            let reason = match reason {
                ReasonArg::Unspecified => RevocationReason::Unspecified,
                ReasonArg::Superseded => RevocationReason::Superseded,
                ReasonArg::Compromised => RevocationReason::Compromised,
                ReasonArg::Retired => RevocationReason::Retired,
            };
            let key = vault.revoke_key(Actor::Cli, &key, reason, &comment)?;
            println!("Revoked {} {}", key.fingerprint, key.label());
            eprintln!(
                "Send partners the updated public key: watermelonpgp key export {}",
                key.fingerprint
            );
        }
        Command::Key(KeyCommand::Delete { key }) => {
            let key = vault.delete_key(Actor::Cli, &key)?;
            println!("Deleted {} {}", key.fingerprint, key.label());
        }
        Command::Audit { limit } => {
            for event in vault.audit_events(limit)? {
                println!(
                    "{}  {:<6} {:<18} {} {}",
                    format_time(event.at),
                    event.actor,
                    event.action,
                    event.key_fingerprint.unwrap_or_default(),
                    event.detail
                );
            }
        }
        Command::Backup { dest } => {
            vault.backup(Actor::Cli, &dest)?;
            println!("Wrote {}", dest.display());
            eprintln!("Reminder: the master key is not part of the backup.");
        }
        Command::Serve { .. }
        | Command::Run { .. }
        | Command::Service(_)
        | Command::Job(JobCommand::RunOnce { .. }) => {
            unreachable!("handled before")
        }
        Command::Job(JobCommand::Add(add)) => {
            let (customer, spec) = job_spec(*add)?;
            let customer = vault.customer(&customer)?;
            let job = vault.create_job(Actor::Cli, customer.id, &spec)?;
            println!("Created job {} {:?}", job.id, job.spec.name);
        }
        Command::Job(JobCommand::List) => {
            for job in vault.jobs()? {
                println!(
                    "{:>4}  {:<20} {:<20} {:<8} {:<10} {} -> {}",
                    job.id,
                    job.customer_name,
                    job.spec.name,
                    kind_name(job.spec.kind),
                    job_state(&job),
                    job.spec.input_dir.display(),
                    job.spec.output_dir.display()
                );
            }
        }
        Command::Job(JobCommand::Show { job }) => print_job(&vault.find_job(&job)?),
        Command::Job(JobCommand::Enable { job }) => {
            let job = vault.enable_job(Actor::Cli, vault.find_job(&job)?.id)?;
            println!("Enabled job {:?}", job.spec.name);
        }
        Command::Job(JobCommand::Disable { job }) => {
            let job = vault.disable_job(Actor::Cli, vault.find_job(&job)?.id)?;
            println!("Disabled job {:?}", job.spec.name);
        }
        Command::Job(JobCommand::Delete { job }) => {
            let job = vault.delete_job(Actor::Cli, vault.find_job(&job)?.id)?;
            println!("Deleted job {:?}", job.spec.name);
        }
        Command::Passwd => {
            let password =
                prompt.new_secret("New admin password", vault::MIN_ADMIN_PASSWORD_LEN)?;
            vault.set_admin_password(Actor::Cli, &password)?;
            println!("Admin password changed");
        }
    }
    Ok(())
}

fn job_spec(add: AddJob) -> Result<(String, JobSpec)> {
    let (common, kind) = match &add {
        AddJob::Encrypt { common, .. } => (common, JobKind::Encrypt),
        AddJob::Decrypt { common, .. } => (common, JobKind::Decrypt),
    };
    let input = std::path::absolute(&common.input)?;
    let mut spec = JobSpec::new(
        &common.name,
        kind,
        &input,
        &std::path::absolute(&common.output)?,
    );
    if common.delete_processed {
        spec.processed_dir = None;
    } else if let Some(dir) = &common.processed {
        spec.processed_dir = Some(std::path::absolute(dir)?);
    }
    if let Some(dir) = &common.failed {
        spec.failed_dir = std::path::absolute(dir)?;
    }
    spec.poll_interval_secs = common.interval;
    let customer = common.customer.clone();
    match add {
        AddJob::Encrypt {
            recipients,
            sign_with,
            armor,
            extension,
            seipd_v2,
            ..
        } => {
            spec.recipients = recipients;
            spec.signer = sign_with;
            spec.armor = armor;
            spec.extension = extension;
            if seipd_v2 {
                spec.container = Container::SeipdV2;
            }
        }
        AddJob::Decrypt {
            keys,
            verifiers,
            verify,
            ..
        } => {
            spec.decrypt_keys = keys;
            spec.verifiers = verifiers;
            spec.verify_policy = match verify {
                PolicyArg::Ignore => VerifyPolicy::Ignore,
                PolicyArg::Warn => VerifyPolicy::Warn,
                PolicyArg::Require => VerifyPolicy::Require,
            };
        }
    }
    Ok((customer, spec))
}

fn print_job(job: &Job) {
    let spec = &job.spec;
    println!("Job {} {:?} ({})", job.id, spec.name, job.customer_name);
    println!("  kind:       {}", kind_name(spec.kind));
    println!("  state:      {}", job_state(job));
    println!("  input:      {}", spec.input_dir.display());
    println!("  output:     {}", spec.output_dir.display());
    match &spec.processed_dir {
        Some(dir) => println!("  processed:  {}", dir.display()),
        None => println!("  processed:  (deleted)"),
    }
    println!("  failed:     {}", spec.failed_dir.display());
    println!("  interval:   {}s", spec.poll_interval_secs);
    match spec.kind {
        JobKind::Encrypt => {
            for key in &spec.recipients {
                println!("  recipient:  {key}");
            }
            if let Some(key) = &spec.signer {
                println!("  sign with:  {key}");
            }
            println!(
                "  format:     {:?}, {}, extension {}",
                spec.container,
                if spec.armor { "armored" } else { "binary" },
                spec.output_extension()
            );
        }
        JobKind::Decrypt => {
            for key in &spec.decrypt_keys {
                println!("  key:        {key}");
            }
            for key in &spec.verifiers {
                println!("  verify:     {key}");
            }
            println!("  signatures: {:?}", spec.verify_policy);
        }
    }
    if let Some(at) = job.last_run_at {
        println!("  last run:   {}", format_time(at));
    }
    if let Some(error) = &job.last_error {
        println!("  last error: {error}");
    }
}

fn kind_name(kind: JobKind) -> &'static str {
    match kind {
        JobKind::Encrypt => "encrypt",
        JobKind::Decrypt => "decrypt",
    }
}

fn job_state(job: &Job) -> String {
    match (&job.paused_reason, job.enabled) {
        (Some(reason), _) => format!("PAUSED: {reason}"),
        (None, true) => "enabled".into(),
        (None, false) => "disabled".into(),
    }
}

fn print_keys(keys: &[KeyRecord]) {
    for key in keys {
        let mut flags = Vec::new();
        if key.has_secret {
            flags.push("secret");
        }
        if key.revoked {
            flags.push("REVOKED");
        }
        let expires = key
            .expires_at
            .map(|at| format!("expires {}", format_date(at)))
            .unwrap_or_else(|| "no expiry".into());
        println!(
            "{}  {:<10} {:<20} {}  [{}] {}",
            key.fingerprint,
            key.algorithm,
            match &key.owner {
                KeyOwner::Customer { name, .. } => name.as_str(),
                KeyOwner::Anonymous => "(anonymous)",
            },
            expires,
            flags.join(", "),
            key.label(),
        );
    }
}

/// Where passwords and passphrases come from.
#[derive(Clone, Copy)]
struct Prompt {
    stdin: bool,
}

impl Prompt {
    fn secret(self, prompt: &str) -> Result<String> {
        if self.stdin {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok(line.trim_end_matches(['\r', '\n']).to_owned())
        } else {
            Ok(rpassword::prompt_password(format!("{prompt}: "))?)
        }
    }

    /// Ask for a new secret (twice, when interactive) and check its length.
    fn new_secret(self, prompt: &str, min_len: usize) -> Result<String> {
        let first = self.secret(prompt)?;
        if first.chars().count() < min_len {
            bail!("must be at least {min_len} characters");
        }
        if !self.stdin && first != self.secret(&format!("{prompt} (again)"))? {
            bail!("the two entries do not match");
        }
        Ok(first)
    }
}

fn write_new_file(path: &Path, contents: &[u8], private: bool) -> Result<()> {
    let written = if private {
        watermelon_pgp_core::write_private_file(path, contents)
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut file| file.write_all(contents))
    };
    written.with_context(|| format!("creating {}", path.display()))
}

fn format_time(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| unix.to_string())
}

fn format_date(unix: i64) -> String {
    format_time(unix).chars().take(10).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn vars(names: &[&str]) -> Vec<(OsString, OsString)> {
        names.iter().map(|n| (n.into(), "x".into())).collect()
    }

    /// A variable from before the rename would otherwise be ignored without a word: the TLS
    /// settings, say, leaving the UI on plain HTTP.
    #[test]
    fn refuses_watermelon_variables_from_before_the_rename() {
        let error = check_legacy_env(vars(&["PATH", "WATERMELON_TLS_CERT", "WATERMELON_LOG"]))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("WATERMELON_TLS_CERT is now WATERMELONPGP_TLS_CERT"),
            "{error}"
        );
        assert!(
            error.contains("WATERMELON_LOG is now WATERMELONPGP_LOG"),
            "{error}"
        );
    }

    #[test]
    fn accepts_the_new_variables() {
        check_legacy_env(vars(&["WATERMELONPGP_DATA_DIR", "WATERMELON", "HOME"])).unwrap();
    }

    #[test]
    fn usage_names_the_watermelonpgp_command() {
        let help = Cli::command().render_usage().to_string();
        assert!(help.starts_with("Usage: watermelonpgp "), "{help}");
    }

    /// The service's command line, parsed back, gives `service run` the installer's settings.
    #[test]
    fn service_arguments_round_trip() {
        let serve = ServeArgs {
            bind: "0.0.0.0:8443".parse().unwrap(),
            workers: Some(3),
            secure_cookies: true,
            tls_cert: Some("certs/cert pem".into()),
            tls_key: Some("certs/key.pem".into()),
        };
        let arguments = service::arguments(
            "wm-test",
            &service::Settings {
                data_dir: Path::new("data dir"),
                master_key: Path::new("keys/master.key"),
                log_format: LogFormat::Json,
                log_file: Path::new("data dir/watermelonpgp.log"),
                serve: &serve,
            },
        )
        .unwrap();
        let cli =
            Cli::try_parse_from(std::iter::once("watermelonpgp".into()).chain(arguments)).unwrap();
        let absolute = |path: &str| std::path::absolute(path).unwrap();
        assert_eq!(cli.data_dir, absolute("data dir"));
        assert!(cli.data_dir.is_absolute());
        assert_eq!(cli.master_key, Some(absolute("keys/master.key")));
        assert!(matches!(cli.log_format, LogFormat::Json));
        assert_eq!(cli.log_file, Some(absolute("data dir/watermelonpgp.log")));
        let Command::Service(ServiceCommand::Run {
            name,
            serve: parsed,
        }) = cli.command
        else {
            panic!("not `service run`");
        };
        assert_eq!(name, "wm-test");
        assert_eq!(
            parsed,
            ServeArgs {
                tls_cert: Some(absolute("certs/cert pem")),
                tls_key: Some(absolute("certs/key.pem")),
                ..serve
            }
        );
    }

    #[test]
    fn service_arguments_leave_out_unset_options() {
        let serve = ServeArgs {
            bind: "127.0.0.1:8080".parse().unwrap(),
            workers: None,
            secure_cookies: false,
            tls_cert: None,
            tls_key: None,
        };
        let arguments = service::arguments(
            service::DEFAULT_NAME,
            &service::Settings {
                data_dir: Path::new("/data"),
                master_key: Path::new("/data/master.key"),
                log_format: LogFormat::Text,
                log_file: Path::new("/data/watermelonpgp.log"),
                serve: &serve,
            },
        )
        .unwrap();
        for absent in ["--workers", "--secure-cookies", "--tls-cert", "--tls-key"] {
            assert!(!arguments.iter().any(|a| a == absent), "{absent}");
        }
    }

    /// A stop request ends `handle_controls`, and so does losing every sender.
    #[tokio::test]
    async fn controls_stop_serving() {
        let (controls, received) = mpsc::unbounded_channel();
        let (request_stop, stop_requested) = oneshot::channel();
        let handler = tokio::spawn(handle_controls(received, None, request_stop));
        controls.send(Control::ReloadTls).unwrap();
        controls.send(Control::Stop).unwrap();
        stop_requested.await.unwrap();
        handler.await.unwrap();

        let (controls, received) = mpsc::unbounded_channel::<Control>();
        let (request_stop, stop_requested) = oneshot::channel();
        tokio::spawn(handle_controls(received, None, request_stop));
        drop(controls);
        stop_requested.await.unwrap();
    }

    #[test]
    fn cli_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
