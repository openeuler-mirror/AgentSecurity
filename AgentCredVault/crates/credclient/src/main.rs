//! `credclient`: the management-plane CLI.
//!
//! It contains no proxy logic and never touches persistent state: every
//! command is one HTTP/1.1 request with a JSON body sent to `credproxyd` over
//! `mgmt.sock`. Credential objects are written only by `credstore`; the
//! daemon's own configuration is written only by the daemon (design §4.1.3.1,
//! decision 33).
//!
//! No environment variable and no configuration file decide anything:
//! `--mgmt-socket` comes from the command line or its built-in default.

mod wire;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Map, Value};

const DEFAULT_MGMT_SOCKET: &str = "/run/credsvault/mgmt.sock";

#[derive(Parser)]
#[command(
    name = "credclient",
    version,
    about = "credential-isolation management CLI"
)]
struct Cli {
    /// credproxyd management socket.
    #[arg(long, global = true, default_value = DEFAULT_MGMT_SOCKET)]
    mgmt_socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show daemon health, including the bound transparent-capture listener
    Health,
    /// Manage the transparent-capture CA
    Ca {
        #[command(subcommand)]
        command: CaCmd,
    },
    /// Manage credential objects (`data/<fake_cred>`)
    Credential {
        #[command(subcommand)]
        command: CredentialCmd,
    },
    /// Reload the daemon configuration and every credential, report violations
    Validate,
    /// Print a structural snapshot of the daemon configuration and credentials
    Dump(DumpArgs),
}

#[derive(Subcommand)]
enum CaCmd {
    /// Rotate the CA stored in the daemon's own configuration
    Init {
        /// Rotate an existing CA; all agents must be re-provisioned.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum CredentialCmd {
    Add(CredentialAddArgs),
    Update(CredentialUpdateArgs),
    Remove {
        #[arg(long)]
        fake_cred: String,
    },
}

#[derive(Args)]
struct CredentialAddArgs {
    #[arg(long)]
    name: String,
    /// Only `https` is accepted in V1.
    #[arg(long = "type", default_value = "https", value_parser = ["https"])]
    kind: String,
    #[arg(long)]
    user_id: String,
    #[arg(long)]
    user_name: String,
    /// Repeatable target host (domain or IP, no port).
    #[arg(long = "allow-host")]
    allow_host: Vec<String>,
    /// File holding the real value; not passed through argv.
    #[arg(long)]
    value_file: Option<PathBuf>,
    /// Read the real value from stdin (the default when neither value flag is
    /// given).
    #[arg(long)]
    value_stdin: bool,
    /// Repeatable policy rule as JSON.
    #[arg(long)]
    rule: Vec<String>,
}

#[derive(Args)]
struct CredentialUpdateArgs {
    #[arg(long)]
    fake_cred: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    user_id: Option<String>,
    #[arg(long)]
    user_name: Option<String>,
    /// Repeatable target host (domain or IP, no port).
    #[arg(long = "allow-host")]
    allow_host: Vec<String>,
    /// Repeatable policy rule as JSON.
    #[arg(long)]
    rule: Vec<String>,
}

#[derive(Args)]
struct DumpArgs {
    /// Include real secret values and the CA private key (operator only).
    #[arg(long)]
    secrets: bool,
    /// Drop sensitive fields entirely (CA material, credential definitions).
    #[arg(long)]
    redacted: bool,
    #[arg(long, value_parser = ["json"], default_value = "json")]
    format: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("credclient: {e:#}");
            ExitCode::from(1)
        }
    }
}

struct Client {
    socket: PathBuf,
}

impl Client {
    async fn get(&self, target: &str) -> Result<Value> {
        wire::call(&self.socket, "GET", target, None).await
    }

    async fn post(&self, target: &str, body: Value) -> Result<Value> {
        wire::call(&self.socket, "POST", target, Some(&body)).await
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let client = Client {
        socket: cli.mgmt_socket,
    };
    match cli.command {
        Command::Health => print_result(client.get("/v1/health").await?),
        Command::Ca { command } => match command {
            CaCmd::Init { force } => {
                let result = client
                    .post("/v1/ca/init", json!({ "force": force }))
                    .await?;
                let cert = result
                    .get("cert")
                    .and_then(Value::as_str)
                    .context("ca.init returned no certificate")?;
                print!("{cert}");
                if !cert.ends_with('\n') {
                    println!();
                }
                eprintln!(
                    "credclient: CA stored in the daemon's own configuration; \
                     rotate with `ca init --force`"
                );
                Ok(ExitCode::SUCCESS)
            }
        },
        Command::Credential { command } => credential(&client, command).await,
        Command::Validate => validate(&client).await,
        Command::Dump(args) => dump(&client, args).await,
    }
}

async fn credential(client: &Client, command: CredentialCmd) -> Result<ExitCode> {
    match command {
        CredentialCmd::Add(a) => {
            print_result(client.post("/v1/credential/add", add_args(a)?).await?)
        }
        CredentialCmd::Update(a) => {
            let fake_cred = a.fake_cred.clone();
            let body = update_args(a)?;
            print_result(
                client
                    .post(
                        &format!("/v1/credential/update?fake_cred={fake_cred}"),
                        body,
                    )
                    .await?,
            )
        }
        CredentialCmd::Remove { fake_cred } => print_result(
            client
                .post(
                    &format!("/v1/credential/remove?fake_cred={fake_cred}"),
                    json!({}),
                )
                .await?,
        ),
    }
}

fn add_args(a: CredentialAddArgs) -> Result<Value> {
    if a.allow_host.is_empty() {
        bail!("credential add needs at least one --allow-host");
    }
    let mut args = Map::new();
    args.insert("name".into(), Value::String(a.name));
    args.insert("type".into(), Value::String(a.kind));
    args.insert("user_id".into(), Value::String(a.user_id));
    args.insert("user_name".into(), Value::String(a.user_name));
    args.insert("allowed_hosts".into(), json!(a.allow_host));
    if !a.rule.is_empty() {
        args.insert("rules".into(), Value::Array(parse_rules(&a.rule)?));
    }
    args.insert(
        "real_cred".into(),
        Value::String(read_secret(a.value_file, a.value_stdin)?),
    );
    Ok(Value::Object(args))
}

fn update_args(a: CredentialUpdateArgs) -> Result<Value> {
    let mut args = Map::new();
    if let Some(name) = a.name {
        args.insert("name".into(), Value::String(name));
    }
    if let Some(user_id) = a.user_id {
        args.insert("user_id".into(), Value::String(user_id));
    }
    if let Some(user_name) = a.user_name {
        args.insert("user_name".into(), Value::String(user_name));
    }
    if !a.allow_host.is_empty() {
        args.insert("allowed_hosts".into(), json!(a.allow_host));
    }
    if !a.rule.is_empty() {
        args.insert("rules".into(), Value::Array(parse_rules(&a.rule)?));
    }
    if args.is_empty() {
        bail!("credential update needs at least one field to change");
    }
    Ok(Value::Object(args))
}

fn parse_rules(raw: &[String]) -> Result<Vec<Value>> {
    raw.iter()
        .map(|r| serde_json::from_str::<Value>(r).with_context(|| format!("rule is not JSON: {r}")))
        .collect()
}

async fn validate(client: &Client) -> Result<ExitCode> {
    let result = client.get("/v1/validate").await?;
    print_result(result.clone())?;
    let violations = result
        .get("violations")
        .and_then(Value::as_array)
        .context("validate returned no violations array")?;
    if violations.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    for v in violations {
        eprintln!("violation: {}", v.as_str().unwrap_or("<non-string>"));
    }
    eprintln!("credclient: {} invariant violation(s)", violations.len());
    Ok(ExitCode::from(3))
}

async fn dump(client: &Client, args: DumpArgs) -> Result<ExitCode> {
    if args.secrets && args.redacted {
        bail!("--secrets and --redacted are mutually exclusive");
    }
    let _ = args.format;
    let mut query = Vec::new();
    if args.secrets {
        query.push("secrets=true");
    }
    if args.redacted {
        query.push("redacted=true");
    }
    let target = if query.is_empty() {
        "/v1/dump".to_string()
    } else {
        format!("/v1/dump?{}", query.join("&"))
    };
    print_result(client.get(&target).await?)
}

fn print_result(result: Value) -> Result<ExitCode> {
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(ExitCode::SUCCESS)
}

/// Reads a secret from `file` or stdin and removes exactly one trailing line
/// terminator. Nothing else is trimmed, and the value never appears in an
/// error message.
fn read_secret(file: Option<PathBuf>, stdin_flag: bool) -> Result<String> {
    if file.is_some() && stdin_flag {
        bail!("--value-file and --value-stdin are mutually exclusive");
    }
    let mut text = match file {
        Some(path) => {
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?
        }
        None => {
            use std::io::Read;
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("read secret from stdin")?;
            text
        }
    };
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    if text.is_empty() {
        bail!("secret is empty (expected stdin or --value-file)");
    }
    Ok(text)
}
