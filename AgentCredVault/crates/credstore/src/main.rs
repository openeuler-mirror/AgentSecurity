//! credstore binary: `credstore run`.
//!
//! Defaults: `/run/credstore/store.sock` and a data directory owned by the
//! vault uid.
//! The environment variables are test-only overrides; production hosts use the
//! defaults from the systemd unit.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};

use credstore::backend::{check_data_dir, FileBackend};
use credstore::server::{self, ServerConfig};
use credstore::store::Store;

#[derive(Parser)]
#[command(
    name = "credstore",
    about = "credential vault (storage + release condition)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the AF_UNIX store socket.
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// AF_UNIX socket to bind.
    #[arg(long, default_value = "/run/credstore/store.sock")]
    socket: PathBuf,
    /// Data directory (created 0700 if missing).
    #[arg(long, default_value = "/var/lib/credstore")]
    data: PathBuf,
    /// Peer uid accepted on the socket. Defaults to the uid running credstore.
    #[arg(long)]
    allow_uid: Option<u32>,
    /// Maximum concurrent client connections.
    #[arg(long, default_value_t = server::MAX_CONNECTIONS)]
    max_connections: usize,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => run(args),
    }
}

fn run(args: RunArgs) -> anyhow::Result<()> {
    let backend = FileBackend::open(&args.data)
        .with_context(|| format!("open data directory {}", args.data.display()))?;
    check_data_dir(&args.data).context("data directory self-check")?;

    let store = Arc::new(Store::new(backend));
    let allow_uid = args.allow_uid.or_else(|| Some(unsafe { libc::geteuid() }));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        server::run(
            store,
            ServerConfig {
                socket: args.socket.clone(),
                allow_uid,
                max_connections: args.max_connections,
            },
        )
        .await
    })
}
