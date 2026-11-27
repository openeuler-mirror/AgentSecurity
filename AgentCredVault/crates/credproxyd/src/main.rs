//! credproxyd binary: startup, listeners, shutdown.

use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use tokio::net::TcpListener;

use credproxyd::bootstrap::{self, Settings};
use credproxyd::capture::{self, CaptureConfig, Iptables};
use credproxyd::config::{self, CaMaterial};
use credproxyd::control::{self, Ctx};
use credproxyd::ingress;
use credproxyd::mgmt;
use credproxyd::runtime::{self, Runtime};
use credproxyd::store_client::StoreClient;
use credproxyd::trust;

#[derive(Parser)]
#[command(name = "credproxyd", version, about = "credential-isolation daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon (one instance per machine)
    Run(RunArgs),
    /// Remove the netfilter capture rules installed by the daemon
    ///
    /// This is the only operation that removes the rules: stop and crash keep
    /// them so traffic cannot bypass the proxy while it is down.
    UninstallCapture,
}

/// Every bootstrap parameter is optional here so the config file can supply
/// it; `bootstrap::Settings::resolve` applies command line > config file >
/// default. Environment variables are not a parameter source.
#[derive(Args)]
struct RunArgs {
    /// JSON file with bootstrap parameters
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    store_socket: Option<PathBuf>,
    #[arg(long)]
    mgmt_socket: Option<PathBuf>,
    /// How long to wait for the store socket before exiting.
    #[arg(long)]
    store_wait_ms: Option<u64>,
    /// Test-only override of the global instance lock; built only with the
    /// `test-hooks` feature.
    #[cfg(feature = "test-hooks")]
    #[arg(long)]
    lock_file: Option<PathBuf>,
    /// Test-only override of the daemon's own configuration file; built only
    /// with the `test-hooks` feature.
    #[cfg(feature = "test-hooks")]
    #[arg(long)]
    state_file: Option<PathBuf>,
}

impl RunArgs {
    fn settings(&self) -> Result<Settings> {
        let (file, used) = bootstrap::load(
            self.config.as_deref(),
            Path::new(bootstrap::DEFAULT_CONFIG_FILE),
        )?;
        if let Some(path) = used {
            eprintln!("credproxyd: bootstrap config {}", path.display());
        }
        Settings::resolve(
            file,
            self.store_socket.clone(),
            self.mgmt_socket.clone(),
            self.store_wait_ms,
        )
    }

    /// The global instance lock path. Production uses the built-in
    /// default; only a `test-hooks` build can point it elsewhere.
    fn lock_file(&self) -> PathBuf {
        #[cfg(feature = "test-hooks")]
        if let Some(path) = &self.lock_file {
            return path.clone();
        }
        PathBuf::from(DEFAULT_LOCK_FILE)
    }

    /// The daemon's own configuration file. Production path is fixed; only a
    /// `test-hooks` build can point it elsewhere.
    fn state_file(&self) -> PathBuf {
        #[cfg(feature = "test-hooks")]
        if let Some(path) = &self.state_file {
            return path.clone();
        }
        PathBuf::from(DEFAULT_STATE_FILE)
    }
}

fn main() -> Result<()> {
    // Single compiled-in provider for rustls when only `ring` is enabled.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => run_daemon(args),
        Command::UninstallCapture => {
            capture::uninstall(&Iptables).context("uninstall netfilter capture rules")?;
            eprintln!("credproxyd: capture rules removed");
            Ok(())
        }
    }
}

#[tokio::main]
async fn run_daemon(args: RunArgs) -> Result<()> {
    // Bootstrap parameters are resolved before the lock and before the vault is
    // touched: a bad config file must fail without side effects.
    let settings = args.settings()?;
    // One daemon per machine: the lock file is fixed, not derived from any
    // per-deployment path.
    let _lock = DaemonLock::acquire(&args.lock_file())?;

    // Management-plane configuration (socket mode, group, optional token) is
    // validated before any listener is bound or served.
    let mgmt_cfg =
        mgmt::MgmtConfig::from_settings(&settings).context("management plane configuration")?;

    let store = Arc::new(
        StoreClient::connect_with_retry(
            &settings.store_socket,
            std::time::Duration::from_millis(settings.store_wait_ms),
        )
        .await
        .with_context(|| {
            format!(
                "credstore not reachable at {} (start credstore first)",
                settings.store_socket.display()
            )
        })?,
    );

    // The daemon's own configuration (CA) plus every credential in the vault.
    // The listener comes from the bootstrap settings, not from this file. A
    // missing configuration file is created as the default skeleton; anything
    // the model rejects refuses startup.
    let state_path = args.state_file();
    let mut model = control::load_model(&store, &state_path).await?;

    // The local MITM CA is generated and persisted on first start if absent
    // (design §4.2.2). Rotation is explicit through `credclient ca init
    // --force`.
    if model.config.ca.is_none() {
        let ca = trust::generate_ca().context("generate local CA")?;
        model.config.ca = Some(CaMaterial {
            cert: ca.cert,
            key: ca.key,
        });
        config::daemon_config_save(&state_path, &model.config)
            .context("persist generated local CA")?;
        eprintln!("credproxyd: generated local CA");
    }
    eprintln!(
        "credproxyd: loaded {} credential(s), CA configured",
        model.credentials.len()
    );

    // Transparent capture is the only data-plane ingress. The listen address is
    // a bootstrap input: the daemon reads it at startup and fails if the port
    // is taken.
    let listen = settings.listen_transparent;
    // Validate the capture parameters before binding anything, so a rejected
    // subnet/interface leaves no socket behind. Installation happens later,
    // once every other fallible startup step has succeeded.
    let capture_cfg = settings
        .capture
        .as_ref()
        .map(|file| CaptureConfig::from_file(file, listen))
        .transpose()
        .context("capture configuration")?;
    let transparent_listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind transparent listener {listen}"))?;

    let rt = Runtime::build(
        model.config.clone(),
        model.credentials.clone(),
        store.clone(),
        settings.upstream_ca.clone(),
    )
    .context("build runtime")?;
    let shared = runtime::shared(rt);

    let ctx = Ctx::new(
        shared.clone(),
        store.clone(),
        state_path,
        listen.to_string(),
        settings.upstream_ca.clone(),
    );
    // Bind before spawning: a daemon without a management plane must fail to
    // start, not keep serving.
    let mgmt_listener = mgmt::bind(&mgmt_cfg).context("management plane")?;

    // Netfilter capture rules are owned by the daemon: validate, install,
    // verify. A failure refuses startup (fail closed). They deliberately stay
    // installed on stop/crash and are removed only by `uninstall-capture`.
    if let Some(capture_cfg) = &capture_cfg {
        capture::install(capture_cfg, &Iptables).context("install netfilter capture rules")?;
        eprintln!(
            "credproxyd: capture {} from {} on {} -> {}",
            capture_cfg.subnet(),
            capture_cfg.interface(),
            capture_cfg.listen(),
            capture_cfg.dnat_target()
        );
    } else {
        eprintln!(
            "credproxyd: warning: bootstrap config has no capture section; \
             netfilter is unchanged and only redirected connections reach {listen}"
        );
    }

    let mgmt_cfg = Arc::new(mgmt_cfg);
    let mgmt_ctx = ctx.clone();
    tokio::spawn(async move {
        mgmt::serve_listener(mgmt_ctx, mgmt_listener, mgmt_cfg).await;
    });

    eprintln!(
        "credproxyd: transparent capture {listen}; store {}",
        settings.store_socket.display()
    );
    tokio::spawn(async move {
        ingress::run_transparent(transparent_listener, shared, "transparent").await
    });

    shutdown_signal().await;
    eprintln!("credproxyd: shutting down");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}

/// The daemon is unique per machine; this file is not derived from any
/// per-deployment path.
const DEFAULT_LOCK_FILE: &str = "/run/credsvault/credproxyd.lock";
/// Where the daemon keeps its own configuration (CA material). Location and
/// format are implementation details (design §4.2.4).
const DEFAULT_STATE_FILE: &str = "/var/lib/credsvault/daemon.json";

/// `flock` on the global lock file; a second daemon exits before touching the
/// store.
struct DaemonLock {
    _file: std::fs::File,
}

impl DaemonLock {
    fn acquire(path: &Path) -> Result<DaemonLock> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("open lock {}", path.display()))?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            bail!(
                "another credproxyd is running (lock {} is held)",
                path.display()
            );
        }
        Ok(DaemonLock { _file: file })
    }
}
