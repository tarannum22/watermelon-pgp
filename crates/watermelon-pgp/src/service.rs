//! Running as a Windows service: installing and removing it, and the entry point the service
//! manager starts.
//!
//! The service runs `serve` as the virtual account `NT SERVICE\<name>`. Stop and Shutdown take
//! the same path as Ctrl-C: the web server stops and running jobs finish their current file.

use std::{
    ffi::OsString,
    path::Path,
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

/// While stopping, how often the service tells the service manager it is still making progress,
/// and how long the manager should wait for the next sign of it. A file in progress may take
/// minutes; it gets all the time it needs as long as these keep coming.
const STOP_HEARTBEAT: Duration = Duration::from_secs(5);
const STOP_WAIT_HINT: Duration = Duration::from_secs(30);

/// The account a service runs as: its virtual account.
pub fn account(name: &str) -> String {
    format!(r"NT SERVICE\{name}")
}

/// Create the service, running this executable with `arguments`, and give `private` (the data
/// directory and master keyfile) to its account. Removes the service again if any step fails.
pub fn install(name: &str, arguments: Vec<OsString>, private: &[&Path]) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("connecting to the service manager (run this from an elevated prompt)")?;
    let info = ServiceInfo {
        name: name.into(),
        display_name: if name == "watermelon" {
            "WatermelonPGP".into()
        } else {
            format!("WatermelonPGP ({name})").into()
        },
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().context("finding watermelon.exe")?,
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
        for path in private {
            watermelon_pgp_core::give_to_account(path, &account(name))
                .with_context(|| format!("giving {} to {}", path.display(), account(name)))?;
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
        // Give up only when the service stops making progress, not after a fixed time.
        let mut progress = (u32::MAX, Instant::now());
        loop {
            let status = service.query_status()?;
            if status.current_state == ServiceState::Stopped {
                break;
            }
            if status.checkpoint != progress.0 {
                progress = (status.checkpoint, Instant::now());
            } else if progress.1.elapsed() > status.wait_hint.max(STOP_WAIT_HINT) {
                bail!(
                    "the service {name} isn't stopping (state {:?})",
                    status.current_state
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    service
        .delete()
        .with_context(|| format!("removing the service {name}"))
}

/// What the service runs: `serve`, told to stop or reload by `controls`, calling `ready` once
/// it is serving.
pub type Work = Box<dyn FnOnce(mpsc::UnboundedReceiver<Control>, &dyn Fn()) -> Result<()> + Send>;

static WORK: Mutex<Option<(String, Work)>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

/// Hand this process over to the service manager, which runs `work` as the service `name`.
/// Returns once the service has stopped.
pub fn run(name: String, work: Work) -> Result<()> {
    *WORK.lock().unwrap() = Some((name.clone(), work));
    service_dispatcher::start(&name, ffi_service_main).context(
        "connecting to the service manager: `service run` is for Windows to start; to run in a \
         console, use `watermelon serve`",
    )
}

fn service_main(_arguments: Vec<OsString>) {
    let Some((name, work)) = WORK.lock().unwrap().take() else {
        return;
    };
    let status = Arc::new(Status::default());
    let (controls, received) = mpsc::unbounded_channel();
    let handler = {
        let status = Arc::clone(&status);
        move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                status.stopping();
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
    status.report(ServiceState::StartPending);
    let result = work(received, &|| {
        status.report(ServiceState::Running);
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
    /// Report `state`; false once the service has stopped.
    fn report(&self, state: ServiceState) -> bool {
        self.set(state, ServiceExitCode::NO_ERROR)
    }

    /// Report StopPending now and every few seconds until the service has stopped.
    fn stopping(self: &Arc<Self>) {
        if self.stopping.swap(true, Ordering::Relaxed) {
            return;
        }
        let status = Arc::clone(self);
        std::thread::spawn(move || {
            while status.report(ServiceState::StopPending) {
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
        self.set(ServiceState::Stopped, exit_code);
    }

    fn set(&self, state: ServiceState, exit_code: ServiceExitCode) -> bool {
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
        reported.checkpoint = if pending { reported.checkpoint + 1 } else { 0 };
        reported.stopped = state == ServiceState::Stopped;
        let status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP
                    | ServiceControlAccept::SHUTDOWN
                    | ServiceControlAccept::PARAM_CHANGE
            } else {
                ServiceControlAccept::empty()
            },
            exit_code,
            checkpoint: reported.checkpoint,
            wait_hint: if pending {
                STOP_WAIT_HINT
            } else {
                Duration::ZERO
            },
            process_id: None,
        };
        if let Err(e) = handle.set_service_status(status) {
            tracing::warn!(error = %e, "reporting the service status");
        }
        true
    }
}
