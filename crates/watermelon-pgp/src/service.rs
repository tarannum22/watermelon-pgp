//! `watermelon service`: running `serve` as a Windows service.
//!
//! The service's command line is built here, on every platform, so it is tested everywhere. The
//! Windows-only parts (the service manager, access lists) are in [`windows`]; elsewhere `main`
//! refuses `watermelon service` before calling into this module.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use tokio::sync::mpsc;
use watermelon_pgp_core::{envelope, vault};

use crate::{Control, LogFormat, ServeArgs};

#[cfg(windows)]
mod windows;

pub const DEFAULT_NAME: &str = "watermelon";

pub const NOT_WINDOWS: &str = "`watermelon service` installs a Windows service; elsewhere, run \
                               `watermelon serve` under systemd or Docker (docs/deployment.md)";

/// The settings the service runs with.
pub struct Settings<'a> {
    pub data_dir: &'a Path,
    pub master_key: &'a Path,
    pub log_format: LogFormat,
    pub log_file: &'a Path,
    pub serve: &'a ServeArgs,
}

/// The service's command line after the executable: absolute paths, every setting spelled out,
/// so the service doesn't depend on the installer's working directory or environment.
pub fn arguments(name: &str, settings: &Settings) -> Result<Vec<OsString>> {
    let serve = settings.serve;
    let format = settings
        .log_format
        .to_possible_value()
        .expect("no skipped values")
        .get_name()
        .to_owned();
    let mut arguments: Vec<OsString> = vec![
        "--data-dir".into(),
        absolute(settings.data_dir)?.into(),
        "--master-key".into(),
        absolute(settings.master_key)?.into(),
        "--log-format".into(),
        format.into(),
        "--log-file".into(),
        absolute(settings.log_file)?.into(),
        "service".into(),
        "run".into(),
        "--name".into(),
        name.into(),
        "--bind".into(),
        serve.bind.to_string().into(),
    ];
    if let Some(workers) = serve.workers {
        arguments.extend(["--workers".into(), workers.to_string().into()]);
    }
    if serve.secure_cookies {
        arguments.push("--secure-cookies".into());
    }
    if let (Some(cert), Some(key)) = (&serve.tls_cert, &serve.tls_key) {
        arguments.extend([
            "--tls-cert".into(),
            absolute(cert)?.into(),
            "--tls-key".into(),
            absolute(key)?.into(),
        ]);
    }
    Ok(arguments)
}

/// Files outside the data directory the service account must be able to use: a log file
/// elsewhere (read and write) and the TLS certificate and key (read).
pub fn files_to_allow(settings: &Settings) -> Result<Vec<(PathBuf, bool)>> {
    let mut allow = Vec::new();
    let log_file = absolute(settings.log_file)?;
    if !log_file.starts_with(absolute(settings.data_dir)?) {
        allow.push((log_file, true));
    }
    let serve = settings.serve;
    for path in [&serve.tls_cert, &serve.tls_key].into_iter().flatten() {
        allow.push((absolute(path)?, false));
    }
    Ok(allow)
}

fn absolute(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))
}

/// Install the service `name` (Windows only).
pub fn install(name: &str, settings: &Settings) -> Result<()> {
    if std::env::var_os(envelope::ENV_VAR).is_some() {
        bail!(
            "the service reads the master key from its file; unset {} and use --master-key",
            envelope::ENV_VAR
        );
    }
    for (what, path) in [
        ("database", settings.data_dir.join(vault::DB_FILE)),
        ("master keyfile", settings.master_key.to_owned()),
    ] {
        if !path.is_file() {
            bail!(
                "no {what} at {}: run `watermelon init` first",
                path.display()
            );
        }
    }
    let arguments = arguments(name, settings)?;
    let allow = files_to_allow(settings)?;
    #[cfg(windows)]
    {
        let account = windows::account(name);
        windows::install(
            name,
            arguments,
            &[settings.data_dir, settings.master_key],
            &allow,
        )?;
        println!("Installed the service {name}, running as {account}.");
        println!(
            "{} and the master key now belong to {account}; only it, LocalSystem and \
             Administrators can access them.",
            settings.data_dir.display()
        );
        for (path, write) in &allow {
            let access = if *write { "read and write" } else { "read" };
            println!("Allowed {account} to {access} {}.", path.display());
        }
        println!("Start it with `Start-Service {name}`.");
        eprintln!();
        eprintln!("Give {account} access to the job folders.");
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (arguments, allow);
        unreachable!("main refuses `service` outside Windows")
    }
}

/// Stop the service `name` if it runs and remove it (Windows only).
pub fn uninstall(name: &str) -> Result<()> {
    #[cfg(windows)]
    {
        windows::uninstall(name)?;
        println!("Removed the service {name}. Its data directory and master key are kept.");
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        unreachable!("main refuses `service` outside Windows")
    }
}

/// Hand this process to the Windows service manager, which runs `work` (Windows only).
pub fn run(
    name: String,
    work: impl FnOnce(mpsc::UnboundedReceiver<Control>, &dyn Fn()) -> Result<()> + Send + 'static,
) -> Result<()> {
    #[cfg(windows)]
    {
        windows::run(
            name,
            watermelon_pgp_jobs::process::bytes_read,
            Box::new(work),
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (name, work);
        unreachable!("main refuses `service` outside Windows")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_files_outside_the_data_dir() {
        let serve = ServeArgs {
            bind: "127.0.0.1:8080".parse().unwrap(),
            workers: None,
            secure_cookies: false,
            tls_cert: Some("tls/cert.pem".into()),
            tls_key: Some("tls/key.pem".into()),
        };
        let settings = |log_file| Settings {
            data_dir: Path::new("data"),
            master_key: Path::new("data/master.key"),
            log_format: LogFormat::Text,
            log_file,
            serve: &serve,
        };
        let a = |path: &str| std::path::absolute(path).unwrap();
        assert_eq!(
            files_to_allow(&settings(Path::new("data/watermelon.log"))).unwrap(),
            [(a("tls/cert.pem"), false), (a("tls/key.pem"), false)]
        );
        assert_eq!(
            files_to_allow(&settings(Path::new("logs/watermelon.log"))).unwrap(),
            [
                (a("logs/watermelon.log"), true),
                (a("tls/cert.pem"), false),
                (a("tls/key.pem"), false)
            ]
        );
    }
}
