//! The Windows service manager: installing and removing the service, and the entry point it
//! starts.
//!
//! The service runs `serve` as the virtual account `NT SERVICE\<name>`. Stop, Preshutdown and
//! Shutdown take the same path as Ctrl-C: the web server stops and running jobs finish their
//! current file.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tokio::sync::mpsc;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::Control;

/// How long starting may take before the service manager should hear from us again.
const START_WAIT_HINT: Duration = Duration::from_secs(30);

/// While stopping, how often the service reports to the service manager, and how long the
/// manager should wait for the next report. Each report advances the checkpoint while jobs are
/// still reading input (see `bytes_read`); a file in progress may take minutes and gets the
/// time it needs.
const STOP_HEARTBEAT: Duration = Duration::from_secs(5);
const STOP_WAIT_HINT: Duration = Duration::from_secs(30);

/// After this long without progress, the checkpoint stops advancing, so the service manager
/// (and `service uninstall`) can tell the service is hung. Covers the gaps between reads:
/// finishing a response, writing and verifying an output file.
const STOP_IDLE_LIMIT: Duration = Duration::from_secs(90);

/// How long Windows waits for the service to stop at shutdown (Preshutdown). Like
/// `TimeoutStopSec` in the systemd unit.
const PRESHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// `service uninstall` gives up waiting for a stop after this long, even with progress.
const UNINSTALL_STOP_LIMIT: Duration = Duration::from_secs(30 * 60);

/// The account a service runs as: its virtual account.
pub fn account(name: &str) -> String {
    format!(r"NT SERVICE\{name}")
}

/// Create the service, running this executable with `arguments`. Make its account the owner of
/// `private` (the data directory and master keyfile), with access for it, LocalSystem and
/// Administrators only. Add an entry for it to each of `allow` (read, or read and write),
/// creating a missing file to write. Removes the service again if any step fails.
pub fn install(
    name: &str,
    arguments: Vec<OsString>,
    private: &[&Path],
    allow: &[(PathBuf, bool)],
) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("connecting to the service manager (run this from an elevated prompt)")?;
    let info = ServiceInfo {
        name: name.into(),
        display_name: if name == super::DEFAULT_NAME {
            "WatermelonPGP".into()
        } else {
            format!("WatermelonPGP ({name})").into()
        },
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().context("finding watermelonpgp.exe")?,
        launch_arguments: arguments,
        dependencies: vec![],
        account_name: Some(account(name).into()),
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::DELETE,
        )
        .with_context(|| format!("creating the service {name}"))?;
    let configure = || -> Result<()> {
        service
            .set_description("OpenPGP keys and folder encryption jobs: web UI and job engine")?;
        // Like Restart=on-failure in the systemd unit, then slower if it keeps failing.
        let restart = |secs| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(secs),
        };
        service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(5), restart(5), restart(60)]),
        })?;
        // Also when it stops with an error, not only when the process crashes.
        service.set_failure_actions_on_non_crash_failures(true)?;
        // Time for running jobs to finish their current file when Windows shuts down.
        service.set_preshutdown_timeout(PRESHUTDOWN_TIMEOUT)?;
        let account = account(name);
        for path in private {
            watermelon_pgp_core::set_owner_and_restrict_to(path, &account)
                .with_context(|| format!("making {account} the owner of {}", path.display()))?;
        }
        for (path, write) in allow {
            if *write && !path.exists() {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .with_context(|| format!("creating {}", path.display()))?;
            }
            watermelon_pgp_core::allow_account(path, &account, *write)
                .with_context(|| format!("allowing {account} to use {}", path.display()))?;
        }
        Ok(())
    };
    if let Err(e) = configure() {
        let _ = service.delete();
        return Err(e);
    }
    Ok(())
}

/// Stop the service if it is running, waiting while jobs finish their current file, and
/// remove it.
pub fn uninstall(name: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("connecting to the service manager (run this from an elevated prompt)")?;
    let service = manager
        .open_service(
            name,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .with_context(|| format!("opening the service {name}"))?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        eprintln!("Stopping {name}; running jobs finish their current file first");
        if let Err(e) = service.stop()
            && service.query_status()?.current_state == ServiceState::Running
        {
            return Err(e).with_context(|| format!("stopping the service {name}"));
        }
        // Give up when the service stops making progress, or after a long time anyway.
        let started = Instant::now();
        let mut last = Checkpoint {
            value: u32::MAX,
            since: started,
        };
        loop {
            let status = service.query_status()?;
            if status.current_state == ServiceState::Stopped {
                break;
            }
            if status.checkpoint != last.value {
                last = Checkpoint {
                    value: status.checkpoint,
                    since: Instant::now(),
                };
            } else if last.since.elapsed() > status.wait_hint.max(STOP_WAIT_HINT) {
                bail!(
                    "the service {name} isn't stopping: no progress for {}s (state {:?})",
                    last.since.elapsed().as_secs(),
                    status.current_state
                );
            }
            if started.elapsed() > UNINSTALL_STOP_LIMIT {
                bail!(
                    "the service {name} hasn't stopped after {} minutes",
                    UNINSTALL_STOP_LIMIT.as_secs() / 60
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    service
        .delete()
        .with_context(|| format!("removing the service {name}"))
}

/// The last checkpoint a stopping service reported, and since when.
struct Checkpoint {
    value: u32,
    since: Instant,
}

/// What the service runs: `serve`, told to stop or reload by `controls`, calling `ready` once
/// it is serving.
pub type Work = Box<dyn FnOnce(mpsc::UnboundedReceiver<Control>, &dyn Fn()) -> Result<()> + Send>;

struct Service {
    name: String,
    progress: fn() -> u64,
    work: Work,
}

static WORK: Mutex<Option<Service>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

/// Hand this process over to the service manager, which runs `work` as the service `name`.
/// While stopping, `progress` (a counter that grows while jobs work) tells progress from a
/// hang. Returns once the service has stopped.
pub fn run(name: String, progress: fn() -> u64, work: Work) -> Result<()> {
    *WORK.lock().unwrap() = Some(Service {
        name: name.clone(),
        progress,
        work,
    });
    service_dispatcher::start(&name, ffi_service_main).context(
        "connecting to the service manager: `service run` is for Windows to start; to run in a \
         console, use `watermelonpgp serve`",
    )
}

fn service_main(_arguments: Vec<OsString>) {
    let Some(Service {
        name,
        progress,
        work,
    }) = WORK.lock().unwrap().take()
    else {
        return;
    };
    let status = Arc::new(Status::default());
    let (controls, received) = mpsc::unbounded_channel();
    let handler = {
        let status = Arc::clone(&status);
        move |control| match control {
            ServiceControl::Stop | ServiceControl::Preshutdown | ServiceControl::Shutdown => {
                status.stopping(progress);
                let _ = controls.send(Control::Stop);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::ParamChange => {
                let _ = controls.send(Control::ReloadTls);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let handle = match service_control_handler::register(&name, handler) {
        Ok(handle) => handle,
        Err(e) => {
            tracing::error!(error = %e, "registering with the service manager");
            return;
        }
    };
    let _ = status.handle.set(handle);
    status.set(ServiceState::StartPending, ServiceExitCode::NO_ERROR, true);
    let result = work(received, &|| {
        status.set(ServiceState::Running, ServiceExitCode::NO_ERROR, false);
    });
    if let Err(e) = &result {
        tracing::error!(error = format!("{e:#}"), "stopped with an error");
    }
    status.stopped(result.is_ok());
}

/// What the service last told the service manager. Nothing is reported after Stopped.
#[derive(Default)]
struct Status {
    handle: OnceLock<ServiceStatusHandle>,
    reported: Mutex<Reported>,
    stopping: AtomicBool,
}

#[derive(Default)]
struct Reported {
    stopped: bool,
    checkpoint: u32,
}

impl Status {
    /// Report StopPending now and every few seconds until the service has stopped, advancing
    /// the checkpoint while `progress` changes, and for a while after.
    fn stopping(self: &Arc<Self>, progress: fn() -> u64) {
        if self.stopping.swap(true, Ordering::Relaxed) {
            return;
        }
        let status = Arc::clone(self);
        std::thread::spawn(move || {
            let mut seen = progress();
            let mut last_progress = Instant::now();
            loop {
                let now = progress();
                if now != seen {
                    seen = now;
                    last_progress = Instant::now();
                }
                let advance = last_progress.elapsed() < STOP_IDLE_LIMIT;
                if !status.set(
                    ServiceState::StopPending,
                    ServiceExitCode::NO_ERROR,
                    advance,
                ) {
                    break;
                }
                std::thread::sleep(STOP_HEARTBEAT);
            }
        });
    }

    fn stopped(&self, clean: bool) {
        let exit_code = if clean {
            ServiceExitCode::NO_ERROR
        } else {
            ServiceExitCode::ServiceSpecific(1)
        };
        self.set(ServiceState::Stopped, exit_code, false);
    }

    /// Report `state`; for a pending state, `advance` the checkpoint. False once stopped.
    fn set(&self, state: ServiceState, exit_code: ServiceExitCode, advance: bool) -> bool {
        let Some(handle) = self.handle.get() else {
            return false;
        };
        let mut reported = self.reported.lock().unwrap();
        if reported.stopped {
            return false;
        }
        let pending = matches!(
            state,
            ServiceState::StartPending | ServiceState::StopPending
        );
        if !pending {
            reported.checkpoint = 0;
        } else if advance {
            reported.checkpoint += 1;
        }
        reported.stopped = state == ServiceState::Stopped;
        let status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP
                    | ServiceControlAccept::PRESHUTDOWN
                    | ServiceControlAccept::SHUTDOWN
                    | ServiceControlAccept::PARAM_CHANGE
            } else {
                ServiceControlAccept::empty()
            },
            exit_code,
            checkpoint: reported.checkpoint,
            wait_hint: match state {
                ServiceState::StartPending => START_WAIT_HINT,
                ServiceState::StopPending => STOP_WAIT_HINT,
                _ => Duration::ZERO,
            },
            process_id: None,
        };
        if let Err(e) = handle.set_service_status(status) {
            tracing::warn!(error = %e, "reporting the service status");
        }
        true
    }
}
