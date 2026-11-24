use std::{
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
use watermelon_pgp_core::{
    audit::Actor,
    crypto::{self, Algorithm, Container},
    envelope::MasterKey,
    jobs::{Job, JobKind, JobSpec, VerifyPolicy},
    store::KeyRecord,
    vault::{self, Vault},
};
use watermelon_pgp_jobs::{Engine, PassReport, scan::Scanner};

/// Manage OpenPGP keys and folder encrypt/decrypt jobs.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Directory holding the database.
    #[arg(
        long,
        global = true,
        env = "WATERMELON_DATA_DIR",
        default_value = "data"
    )]
    data_dir: PathBuf,
    /// Master keyfile [default: <data-dir>/master.key]. Ignored when WATERMELON_MASTER_KEY is set.
    #[arg(long, global = true, env = "WATERMELON_MASTER_KEY_FILE")]
    master_key: Option<PathBuf>,
    /// Read the password or passphrase from the first line of stdin instead of prompting.
    #[arg(long, global = true)]
    passphrase_stdin: bool,
    #[command(subcommand)]
    command: Command,
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
    /// Show the most recent audit log entries.
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Write a consistent snapshot of the database. Does NOT include the master key.
    Backup { dest: PathBuf },
    /// Change the admin password.
    Passwd,
    /// Manage folder jobs.
    #[command(subcommand)]
    Job(JobCommand),
    /// Serve the web UI and run all enabled jobs until stopped (Ctrl-C or SIGTERM).
    Serve {
        /// Address to listen on. Anything but loopback should sit behind a TLS reverse proxy.
        #[arg(long, env = "WATERMELON_BIND", default_value = "127.0.0.1:8080")]
        bind: std::net::SocketAddr,
        /// Jobs processed in parallel [default: number of CPUs].
        #[arg(long)]
        workers: Option<usize>,
        /// Mark the session cookie Secure. Set this when users reach the UI over HTTPS.
        #[arg(long, env = "WATERMELON_SECURE_COOKIES")]
        secure_cookies: bool,
    },
    /// Run all enabled jobs until interrupted (Ctrl-C), without the web UI.
    Run {
        /// Jobs processed in parallel [default: number of CPUs].
        #[arg(long)]
        workers: Option<usize>,
    },
}

#[derive(Subcommand)]
enum JobCommand {
    /// Create a job.
    #[command(subcommand)]
    Add(AddJob),
    /// List jobs.
    List,
    /// Show one job (by ID or name).
    Show {
        job: String,
    },
    /// Enable a job, or resume a paused one.
    Enable {
        job: String,
    },
    Disable {
        job: String,
    },
    Delete {
        job: String,
    },
    /// Run one polling pass now, waiting for files to settle first.
    RunOnce {
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
    #[arg(long)]
    customer: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    input: PathBuf,
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
    /// Seconds between scans of the input folder.
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
    Add { name: String },
    List,
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Generate a new key pair.
    Gen {
        #[arg(long)]
        customer: String,
        /// User ID, e.g. "ACME Exports <exports@acme.example>".
        #[arg(long)]
        uid: String,
        #[arg(long, value_enum, default_value_t = AlgorithmArg::Curve25519)]
        algorithm: AlgorithmArg,
    },
    /// Import public and/or secret keys from a file (armored or binary).
    Import {
        #[arg(long)]
        customer: String,
        file: PathBuf,
    },
    /// List keys.
    List {
        #[arg(long)]
        customer: Option<String>,
    },
    /// Export a key, armored. Secret exports are protected with a new passphrase.
    Export {
        /// Fingerprint or key ID.
        key: String,
        #[arg(long)]
        secret: bool,
        /// Output file [default: stdout].
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Delete a key (it stays in the database for the audit trail).
    Delete { key: String },
}

#[derive(Clone, Copy, ValueEnum)]
enum AlgorithmArg {
    Curve25519,
    Rsa4096,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let prompt = Prompt {
        stdin: cli.passphrase_stdin,
    };
    let master_key_path = cli
        .master_key
        .clone()
        .unwrap_or_else(|| cli.data_dir.join(vault::MASTER_KEY_FILE));

    if let Command::Init = cli.command {
        return init(&cli.data_dir, &master_key_path, prompt);
    }
    let vault = Vault::open(
        &cli.data_dir.join(vault::DB_FILE),
        MasterKey::load(&master_key_path)?,
    )?;
    match cli.command {
        Command::Serve {
            bind,
            workers,
            secure_cookies,
        } => serve(vault, bind, workers, secure_cookies),
        Command::Run { workers } => run_engine(vault, workers),
        Command::Job(JobCommand::RunOnce { job, settle }) => run_once(vault, &job, settle),
        command => run(&vault, command, prompt),
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
    eprintln!("Running {active} active job(s) with {workers} worker(s). Ctrl-C to stop.");
    Engine::new(Arc::new(Mutex::new(vault)), workers).run(&stop, |job, report| {
        eprintln!("{}  {job}: {}", format_time(now()), describe_pass(report));
    });
    eprintln!("Stopped.");
    Ok(())
}

fn serve(
    vault: Vault,
    bind: std::net::SocketAddr,
    workers: Option<usize>,
    secure_cookies: bool,
) -> Result<()> {
    let workers = workers.unwrap_or_else(Engine::default_workers);
    let vault = Arc::new(Mutex::new(vault));
    let stop = Arc::new(AtomicBool::new(false));
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind(bind))
        .with_context(|| format!("listening on {bind}"))?;

    let engine = {
        let engine = Engine::new(Arc::clone(&vault), workers);
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("jobs".into())
            .spawn(move || {
                engine.run(&stop, |job, report| {
                    eprintln!("{}  {job}: {}", format_time(now()), describe_pass(report));
                });
            })
            .context("starting the job engine")?
    };

    eprintln!("Serving http://{bind} with {workers} job worker(s). Ctrl-C to stop.");
    if !bind.ip().is_loopback() {
        eprintln!(
            "WARNING: listening on a non-loopback address. Put a TLS-terminating reverse proxy \
             in front and pass --secure-cookies; the UI itself speaks plain HTTP."
        );
    }
    let state = watermelon_pgp_web::AppState::new(
        Arc::clone(&vault),
        watermelon_pgp_web::Config { secure_cookies },
    );
    let served = runtime.block_on(watermelon_pgp_web::serve(
        state,
        listener,
        shutdown_signal(),
    ));

    eprintln!("Stopping; waiting for running jobs to finish their current file…");
    stop.store(true, Ordering::Relaxed);
    if engine.join().is_err() {
        bail!("the job engine panicked");
    }
    eprintln!("Stopped.");
    Ok(served?)
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
    eprintln!("`watermelon backup` deliberately does not include it.");
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
            let customer = vault.customer(&customer)?;
            let algorithm = match algorithm {
                AlgorithmArg::Curve25519 => Algorithm::Curve25519,
                AlgorithmArg::Rsa4096 => Algorithm::Rsa4096,
            };
            let key = vault.generate_key(Actor::Cli, customer.id, &uid, algorithm)?;
            println!("Generated {}", key.fingerprint);
        }
        Command::Key(KeyCommand::Import { customer, file }) => {
            let customer = vault.customer(&customer)?;
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
            for key in vault.import_keys(Actor::Cli, customer.id, &data, passphrase.as_deref())? {
                println!(
                    "Imported {} {} ({})",
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
        Command::Serve { .. } | Command::Run { .. } | Command::Job(JobCommand::RunOnce { .. }) => {
            unreachable!("handled before")
        }
        Command::Job(JobCommand::Add(add)) => {
            let (customer, spec) = job_spec(add)?;
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

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
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
            key.customer_name,
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
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)?;
    Ok(())
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
