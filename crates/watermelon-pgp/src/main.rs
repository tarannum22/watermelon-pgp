use std::{
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use watermelon_pgp_core::{
    audit::Actor,
    crypto::{self, Algorithm},
    envelope::MasterKey,
    store::KeyRecord,
    vault::{self, Vault},
};

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

    match cli.command {
        Command::Init => init(&cli.data_dir, &master_key_path, prompt),
        command => {
            let vault = Vault::open(
                &cli.data_dir.join(vault::DB_FILE),
                MasterKey::load(&master_key_path)?,
            )?;
            run(&vault, command, prompt)
        }
    }
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
        Command::Passwd => {
            let password =
                prompt.new_secret("New admin password", vault::MIN_ADMIN_PASSWORD_LEN)?;
            vault.set_admin_password(Actor::Cli, &password)?;
            println!("Admin password changed");
        }
    }
    Ok(())
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
