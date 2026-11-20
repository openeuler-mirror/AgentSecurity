//! Management-plane business operations.
//!
//! Every operation is dispatched from [`execute`]. The `mgmt` adapter only
//! parses HTTP, checks that the peer uid is root, maps method+path to one
//! operation, and maps `(op, args)` here; all validation, persistence and
//! runtime swap happens in this module.
//!
//! Every mutating operation holds the admin mutex, validates the complete
//! model, writes exactly one object (a credential in `credstore`, or the
//! daemon's own configuration file), builds a new runtime snapshot and swaps
//! it in. A failed write leaves both the persisted and the in-memory state as
//! they were.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tokio::sync::Mutex as AsyncMutex;

use crate::config::{self, CaMaterial, Credential, CredentialType, DaemonConfig, Model};
use crate::placeholder;
use crate::runtime::{Runtime, Shared};
use crate::store_client::{fatal_if_connection, Status, StoreClient, StoreError};
use crate::trust;

pub struct Ctx {
    pub shared: Shared,
    pub store: Arc<StoreClient>,
    admin: AsyncMutex<()>,
    /// The daemon's own configuration file (CA material).
    state_path: PathBuf,
    /// Listener address actually bound at startup (from the bootstrap config);
    /// reported by `health`. Changing it is a bootstrap-config edit plus a
    /// restart, not a management operation.
    pub bound_transparent: String,
    /// Extra origin trust root from the bootstrap config; rebuilt snapshots
    /// must keep using it (test/demo only).
    upstream_ca: Option<PathBuf>,
    pub started: Instant,
}

impl Ctx {
    pub fn new(
        shared: Shared,
        store: Arc<StoreClient>,
        state_path: PathBuf,
        bound_transparent: String,
        upstream_ca: Option<PathBuf>,
    ) -> Arc<Ctx> {
        Arc::new(Ctx {
            shared,
            store,
            admin: AsyncMutex::new(()),
            state_path,
            bound_transparent,
            upstream_ca,
            started: Instant::now(),
        })
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }
}

#[derive(Debug)]
pub struct CtlError {
    pub code: &'static str,
    pub message: String,
}

impl CtlError {
    pub fn new(code: &'static str, message: impl std::fmt::Display) -> CtlError {
        CtlError {
            code,
            message: message.to_string(),
        }
    }

    pub fn invalid(message: impl std::fmt::Display) -> CtlError {
        CtlError::new("invalid_argument", message)
    }

    pub fn unsupported(message: impl std::fmt::Display) -> CtlError {
        CtlError::new("unsupported", message)
    }

    pub fn not_found(message: impl std::fmt::Display) -> CtlError {
        CtlError::new("not_found", message)
    }

    pub fn conflict(message: impl std::fmt::Display) -> CtlError {
        CtlError::new("conflict", message)
    }

    pub fn already_exists(message: impl std::fmt::Display) -> CtlError {
        CtlError::new("already_exists", message)
    }

    pub fn internal(message: impl std::fmt::Display) -> CtlError {
        CtlError::new("internal", message)
    }

    pub fn from_store(e: StoreError) -> CtlError {
        fatal_if_connection(&e);
        CtlError::new("store", e)
    }
}

pub type CtlResult = Result<Value, CtlError>;

/// Single dispatch point.
pub async fn execute(ctx: &Ctx, op: &str, args: Value) -> CtlResult {
    let args = if args.is_null() {
        Value::Object(Default::default())
    } else {
        args
    };
    if !args.is_object() {
        return Err(CtlError::invalid("args must be a JSON object"));
    }
    match op {
        "health" => health(ctx).await,
        "credentials.list" => credentials_list(ctx).await,
        "credential.get" => credential_get(ctx, &args).await,
        "credential.add" => credential_add(ctx, &args).await,
        "credential.update" => credential_update(ctx, &args).await,
        "credential.remove" => credential_remove(ctx, &args).await,
        "validate" => validate(ctx).await,
        "dump" => dump(ctx, &args).await,
        "ca.init" => ca_init(ctx, &args).await,
        other => Err(CtlError::unsupported(format!("unknown op {other}"))),
    }
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn arg_str(args: &Value, key: &str) -> Result<String, CtlError> {
    match args.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(CtlError::invalid(format!("{key} must be a string"))),
        None => Err(CtlError::invalid(format!("missing {key}"))),
    }
}

fn arg_opt_str(args: &Value, key: &str) -> Result<Option<String>, CtlError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(CtlError::invalid(format!("{key} must be a string"))),
    }
}

fn arg_bool(args: &Value, key: &str) -> Result<bool, CtlError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(CtlError::invalid(format!("{key} must be a boolean"))),
    }
}

fn arg_str_vec(args: &Value, key: &str) -> Result<Option<Vec<String>>, CtlError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s) => out.push(s.clone()),
                    _ => {
                        return Err(CtlError::invalid(format!(
                            "{key} must be an array of strings"
                        )))
                    }
                }
            }
            Ok(Some(out))
        }
        Some(_) => Err(CtlError::invalid(format!(
            "{key} must be an array of strings"
        ))),
    }
}

/// The accepted keys of one request body, closed: a misspelt key would
/// otherwise be dropped and silently widen or narrow the credential.
fn reject_unknown_keys(args: &Value, accepted: &[&str]) -> Result<(), CtlError> {
    let Some(obj) = args.as_object() else {
        return Err(CtlError::invalid("args must be a JSON object"));
    };
    if let Some(unknown) = obj.keys().find(|k| !accepted.contains(&k.as_str())) {
        return Err(CtlError::invalid(format!(
            "unknown field {unknown:?}; accepted fields: {}",
            accepted.join(", ")
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Model access and swap
// ---------------------------------------------------------------------------

async fn current_model(ctx: &Ctx) -> Model {
    let rt = crate::runtime::snapshot(&ctx.shared).await;
    rt.model()
}

fn build_runtime(ctx: &Ctx, model: &Model) -> Result<Runtime, CtlError> {
    Runtime::build(
        model.config.clone(),
        model.credentials.clone(),
        ctx.store.clone(),
        ctx.upstream_ca.clone(),
    )
    .map_err(|e| CtlError::internal(format!("build runtime: {e:#}")))
}

/// Validates and installs a new snapshot. The caller has already written the
/// persisted state.
async fn swap(ctx: &Ctx, rt: Runtime) {
    let mut guard = ctx.shared.write().await;
    *guard = Arc::new(rt);
}

/// Publishes the edited model to the data plane: the change is live as soon
/// as the reply is written.
async fn publish(ctx: &Ctx, model: &Model) -> Result<(), CtlError> {
    model.validate().map_err(CtlError::invalid)?;
    let rt = build_runtime(ctx, model)?;
    swap(ctx, rt).await;
    Ok(())
}

fn put_daemon_config(ctx: &Ctx, config: &DaemonConfig) -> Result<(), CtlError> {
    config::daemon_config_save(&ctx.state_path, config).map_err(|e| {
        CtlError::internal(format!(
            "write daemon config {}: {e:#}",
            ctx.state_path.display()
        ))
    })
}

async fn put_credential(ctx: &Ctx, credential: &Credential) -> Result<(), CtlError> {
    let bytes = serde_json::to_vec_pretty(credential)
        .map_err(|e| CtlError::internal(format!("encode credential: {e}")))?;
    ctx.store
        .data_put(&config::credential_object(&credential.fake_cred), &bytes)
        .await
        .map_err(CtlError::from_store)
}

async fn delete_credential(ctx: &Ctx, fake_cred: &str) -> Result<(), CtlError> {
    match ctx
        .store
        .data_delete(&config::credential_object(fake_cred))
        .await
    {
        Ok(()) | Err(StoreError::Status(Status::NotFound)) => Ok(()),
        Err(e) => Err(CtlError::from_store(e)),
    }
}

/// Allocates a fresh fakecred that is unique in the model.
fn allocate_key(model: &Model) -> Result<String, CtlError> {
    for _ in 0..8 {
        let candidate = placeholder::generate_key();
        if !model.credentials.contains_key(&candidate) {
            return Ok(candidate);
        }
    }
    Err(CtlError::internal("could not allocate a unique fakecred"))
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

async fn ca_init(ctx: &Ctx, args: &Value) -> CtlResult {
    reject_unknown_keys(args, &["force"])?;
    let _guard = ctx.admin.lock().await;
    let force = arg_bool(args, "force")?;
    let mut model = current_model(ctx).await;
    if model.config.ca.is_some() && !force {
        return Err(CtlError::already_exists(
            "CA already configured; use --force to rotate (all agents must be re-provisioned)",
        ));
    }
    let ca = trust::generate_ca().map_err(CtlError::internal)?;
    model.config.ca = Some(CaMaterial {
        cert: ca.cert.clone(),
        key: ca.key.clone(),
    });
    config::validate_daemon_config(&model.config).map_err(CtlError::invalid)?;
    put_daemon_config(ctx, &model.config)?;
    publish(ctx, &model).await?;
    Ok(json!({ "cert": ca.cert }))
}

/// Creates one credential. The fakecred is allocated here; `name` must be
/// unique; `real_cred` is inside the same object.
async fn credential_add(ctx: &Ctx, args: &Value) -> CtlResult {
    reject_unknown_keys(
        args,
        &[
            "name",
            "type",
            "user_id",
            "user_name",
            "real_cred",
            "allowed_hosts",
            "rules",
        ],
    )?;
    let _guard = ctx.admin.lock().await;
    let name = arg_str(args, "name")?;
    if !config::valid_ident(&name, 64) {
        return Err(CtlError::invalid(format!(
            "invalid credential name {name:?}"
        )));
    }
    let kind = match arg_str(args, "type")?.as_str() {
        "https" => CredentialType::Https,
        other => {
            return Err(CtlError::invalid(format!(
                "unsupported credential type {other:?}; only \"https\" is accepted"
            )))
        }
    };
    let user_id = arg_str(args, "user_id")?;
    let user_name = arg_str(args, "user_name")?;
    let real_cred = arg_str(args, "real_cred")?;
    let allowed_hosts = arg_str_vec(args, "allowed_hosts")?
        .ok_or_else(|| CtlError::invalid("missing allowed_hosts"))?;
    let rules = args.get("rules").cloned().filter(|v| !v.is_null());

    let model = current_model(ctx).await;
    if model.name_taken(&name, None) {
        return Err(CtlError::already_exists(format!(
            "credential name {name:?} already exists"
        )));
    }
    let credential = Credential {
        schema_version: config::SCHEMA_VERSION,
        name,
        kind,
        user_id,
        user_name,
        fake_cred: allocate_key(&model)?,
        real_cred,
        allowed_hosts,
        rules,
    };
    config::validate_credential(&credential, &credential.fake_cred).map_err(CtlError::invalid)?;
    let mut next = model.clone();
    next.credentials
        .insert(credential.fake_cred.clone(), credential.clone());
    next.validate().map_err(CtlError::invalid)?;

    put_credential(ctx, &credential).await?;
    let view = credential_view(&credential);
    publish(ctx, &next).await?;
    Ok(view)
}

async fn credential_update(ctx: &Ctx, args: &Value) -> CtlResult {
    reject_unknown_keys(
        args,
        &[
            "fake_cred",
            "name",
            "user_id",
            "user_name",
            "allowed_hosts",
            "rules",
        ],
    )?;
    let _guard = ctx.admin.lock().await;
    let fake_cred = arg_str(args, "fake_cred")?;
    let mut model = current_model(ctx).await;
    let mut credential = model
        .credentials
        .get(&fake_cred)
        .cloned()
        .ok_or_else(|| CtlError::not_found(format!("credential {fake_cred} not found")))?;

    let mut changed = false;
    if let Some(name) = arg_opt_str(args, "name")? {
        if !config::valid_ident(&name, 64) {
            return Err(CtlError::invalid(format!(
                "invalid credential name {name:?}"
            )));
        }
        if model.name_taken(&name, Some(&fake_cred)) {
            return Err(CtlError::already_exists(format!(
                "credential name {name:?} already exists"
            )));
        }
        credential.name = name;
        changed = true;
    }
    if let Some(user_id) = arg_opt_str(args, "user_id")? {
        credential.user_id = user_id;
        changed = true;
    }
    if let Some(user_name) = arg_opt_str(args, "user_name")? {
        credential.user_name = user_name;
        changed = true;
    }
    if let Some(hosts) = arg_str_vec(args, "allowed_hosts")? {
        credential.allowed_hosts = hosts;
        changed = true;
    }
    if let Some(rules) = args.get("rules") {
        credential.rules = if rules.is_null() {
            None
        } else {
            Some(rules.clone())
        };
        changed = true;
    }
    if !changed {
        return Err(CtlError::invalid("no fields supplied"));
    }
    config::validate_credential(&credential, &fake_cred).map_err(CtlError::invalid)?;
    model
        .credentials
        .insert(fake_cred.clone(), credential.clone());
    model.validate().map_err(CtlError::invalid)?;

    put_credential(ctx, &credential).await?;
    let view = credential_view(&credential);
    publish(ctx, &model).await?;
    Ok(view)
}

async fn credential_remove(ctx: &Ctx, args: &Value) -> CtlResult {
    reject_unknown_keys(args, &["fake_cred"])?;
    let _guard = ctx.admin.lock().await;
    let fake_cred = arg_str(args, "fake_cred")?;
    let mut model = current_model(ctx).await;
    if !model.credentials.contains_key(&fake_cred) {
        return Err(CtlError::not_found(format!(
            "credential {fake_cred} not found"
        )));
    }
    model.credentials.remove(&fake_cred);
    delete_credential(ctx, &fake_cred).await?;
    publish(ctx, &model).await?;
    Ok(json!({ "fake_cred": fake_cred }))
}

/// Read-only projection. It never carries `real_cred` or `schema_version`.
fn credential_view(c: &Credential) -> Value {
    json!({
        "name": c.name,
        "type": c.kind.as_str(),
        "user_id": c.user_id,
        "user_name": c.user_name,
        "fake_cred": c.fake_cred,
        "allowed_hosts": c.allowed_hosts,
        "rules": c.rules,
    })
}

async fn credentials_list(ctx: &Ctx) -> CtlResult {
    let rt = crate::runtime::snapshot(&ctx.shared).await;
    let credentials: Vec<Value> = rt.credentials.values().map(credential_view).collect();
    Ok(json!({ "credentials": credentials }))
}

async fn credential_get(ctx: &Ctx, args: &Value) -> CtlResult {
    let fake_cred = arg_str(args, "fake_cred")?;
    let rt = crate::runtime::snapshot(&ctx.shared).await;
    let credential = rt
        .credentials
        .get(&fake_cred)
        .ok_or_else(|| CtlError::not_found(format!("credential {fake_cred} not found")))?;
    Ok(credential_view(credential))
}

async fn health(ctx: &Ctx) -> CtlResult {
    let rt = crate::runtime::snapshot(&ctx.shared).await;
    let (store, status) = match ctx.store.data_list().await {
        Ok(_) => ("ok", "ok"),
        Err(_) => ("unavailable", "degraded"),
    };
    Ok(json!({
        "status": status,
        "version": env!("CARGO_PKG_VERSION"),
        "listen_transparent": ctx.bound_transparent,
        "credentials": rt.credentials.len(),
        "store": store,
        "uptime_ms": ctx.started.elapsed().as_millis() as u64,
    }))
}

/// Reloads the daemon configuration and every `data/<fake_cred>` from disk and
/// reports every violation instead of stopping at the first one.
async fn validate(ctx: &Ctx) -> CtlResult {
    let mut violations = Vec::new();
    let config = match config::daemon_config_read(&ctx.state_path) {
        Ok(Some(config)) => Some(config),
        Ok(None) => {
            violations.push(format!(
                "daemon config {}: missing",
                ctx.state_path.display()
            ));
            None
        }
        Err(e) => {
            violations.push(format!("daemon config {}: {e:#}", ctx.state_path.display()));
            None
        }
    };

    let mut credentials: BTreeMap<String, Credential> = BTreeMap::new();
    for name in ctx.store.data_list().await.map_err(CtlError::from_store)? {
        let Some(id) = config::credential_from_object(&name) else {
            violations.push(format!(
                "data/{name}: not a credential object (V1 stores each credential as \
                 data/<fake_cred>; old storage format)"
            ));
            continue;
        };
        match ctx.store.data_get(&name).await {
            Ok(bytes) => match config::parse_credential(&bytes, id) {
                Ok(credential) => {
                    credentials.insert(id.to_string(), credential);
                }
                Err(e) => violations.push(format!("data/{name}: {e:#}")),
            },
            Err(e) => violations.push(format!("data/{name}: {e}")),
        }
    }
    if let Some(config) = &config {
        if let Err(e) = config::validate_model(config, &credentials) {
            violations.push(format!("model: {e:#}"));
        }
    }
    Ok(json!({ "violations": violations }))
}

async fn dump(ctx: &Ctx, args: &Value) -> CtlResult {
    reject_unknown_keys(args, &["secrets", "redacted"])?;
    let secrets = arg_bool(args, "secrets")?;
    let redacted = arg_bool(args, "redacted")?;
    if secrets && redacted {
        return Err(CtlError::invalid(
            "secrets and redacted are mutually exclusive",
        ));
    }
    let model = current_model(ctx).await;
    let mut config_json = serde_json::to_value(&model.config).map_err(CtlError::internal)?;
    let mut credentials_json =
        serde_json::to_value(&model.credentials).map_err(CtlError::internal)?;

    // Real values and the CA private key are masked by default; `secrets`
    // prints them. fakecreds always show.
    if !secrets {
        if let Some(ca) = config_json.get_mut("ca").filter(|v| !v.is_null()) {
            ca["key"] = Value::String("<redacted>".to_string());
        }
        if let Some(map) = credentials_json.as_object_mut() {
            for credential in map.values_mut() {
                if let Some(obj) = credential.as_object_mut() {
                    obj.remove("real_cred");
                }
            }
        }
    }

    if redacted {
        config_json["ca"] = Value::Null;
        if let Some(map) = credentials_json.as_object_mut() {
            for credential in map.values_mut() {
                let obj = credential.as_object();
                let pick = |key: &str| obj.and_then(|o| o.get(key)).cloned().unwrap_or(Value::Null);
                *credential = json!({
                    "name": pick("name"),
                    "type": pick("type"),
                    "user_id": pick("user_id"),
                    "user_name": pick("user_name"),
                    "fake_cred": pick("fake_cred"),
                });
            }
        }
    }

    Ok(json!({
        "config": config_json,
        "credentials": credentials_json,
    }))
}

// ---------------------------------------------------------------------------
// Startup load
// ---------------------------------------------------------------------------

/// Loads and fully validates the model: the daemon's own configuration (a
/// missing file is created as the default skeleton) plus every
/// `data/<fake_cred>` object. Any other object name in `data` is a storage
/// error and refuses startup.
pub async fn load_model(store: &StoreClient, state_path: &Path) -> Result<Model> {
    let config = config::daemon_config_load_or_create(state_path)?;
    let mut credentials = BTreeMap::new();
    for name in store.data_list().await.context("data_list")? {
        let Some(id) = config::credential_from_object(&name) else {
            bail!(
                "data/{name}: not a credential object; V1 stores each credential as \
                 data/<fake_cred> (old storage format; rebuild the vault)"
            );
        };
        let bytes = store
            .data_get(&name)
            .await
            .with_context(|| format!("read data/{name}"))?;
        let credential = config::parse_credential(&bytes, id)?;
        credentials.insert(id.to_string(), credential);
    }
    let model = Model {
        config,
        credentials,
    };
    model.validate().context("model validation")?;
    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(name: &str, real_cred: &str) -> Credential {
        Credential {
            schema_version: config::SCHEMA_VERSION,
            name: name.to_string(),
            kind: CredentialType::Https,
            user_id: "u-01".to_string(),
            user_name: "alice".to_string(),
            fake_cred: "fcred-0123456789abcdef0123456789abcdef".to_string(),
            real_cred: real_cred.to_string(),
            allowed_hosts: vec!["api.example.com".to_string()],
            rules: None,
        }
    }

    #[test]
    fn credential_view_never_carries_real() {
        let view = credential_view(&credential("c", "sk-secret")).to_string();
        assert!(!view.contains("sk-secret"));
        assert!(view.contains("fcred-0123456789abcdef0123456789abcdef"));
        assert!(view.contains("\"type\":\"https\""));
        assert!(view.contains("\"user_id\":\"u-01\""));
        assert!(!view.contains("schema_version"));
    }

    #[test]
    fn unknown_body_keys_are_rejected() {
        let args = json!({ "name": "c", "typo": 1 });
        let err = reject_unknown_keys(&args, &["name"]).unwrap_err();
        assert_eq!(err.code, "invalid_argument");
        assert!(err.message.contains("typo"), "{}", err.message);
    }
}
