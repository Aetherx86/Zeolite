//! HTTP gateway: deployment, replicated execution, webhooks and micro-VM boots.

// Handlers return early with a ready-made `Response`. Boxing it would add an allocation to
// every error path in exchange for nothing, since these functions are never hot.
#![allow(clippy::result_large_err)]

use crate::node::{Node, ProposeFailure};
use crate::state::{Command, Output, VmImage, Workload, valid_name};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State as AxumState};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use zeolite_faas::{Function, Limits as FaasLimits, Runtime};
use zeolite_vmm::{Payload, VmConfig, VmError};

/// Largest accepted request body, which bounds a deployed module or a webhook payload.
pub const MAX_BODY_BYTES: usize = 32 << 20;
const MAX_CONCURRENT_PER_TENANT: usize = 32;
const MAX_VM_MEMORY_BYTES: usize = 512 << 20;

pub struct Gateway {
    pub node: Arc<Node>,
    pub runtime: Arc<Runtime>,
    /// SHA-256 of the admin token. When set, mutating endpoints require it.
    pub admin_token_hash: Option<[u8; 32]>,
    /// HTTP address of each peer, for telling clients where the leader is.
    pub peer_http: BTreeMap<u64, String>,
    pub limits: FaasLimits,
    compiled: Mutex<HashMap<[u8; 32], Arc<Function>>>,
    tenant_slots: Mutex<HashMap<String, Arc<Semaphore>>>,
}

impl Gateway {
    pub fn new(
        node: Arc<Node>,
        runtime: Arc<Runtime>,
        admin_token: Option<&[u8]>,
        peer_http: BTreeMap<u64, String>,
    ) -> Arc<Gateway> {
        Arc::new(Gateway {
            node,
            runtime,
            admin_token_hash: admin_token.map(|t| Sha256::digest(t).into()),
            peer_http,
            limits: FaasLimits::default(),
            compiled: Mutex::new(HashMap::new()),
            tenant_slots: Mutex::new(HashMap::new()),
        })
    }

    fn slots(&self, tenant: &str) -> Arc<Semaphore> {
        let mut slots = self.tenant_slots.lock().unwrap_or_else(|e| e.into_inner());
        slots
            .entry(tenant.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_CONCURRENT_PER_TENANT)))
            .clone()
    }

    /// Compiles on first use. The cache key is the content hash, so a redeployed function
    /// can never run stale code.
    fn compile(&self, wasm: &[u8]) -> Result<Arc<Function>, String> {
        let key: [u8; 32] = Sha256::digest(wasm).into();
        if let Some(function) = self
            .compiled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return Ok(function.clone());
        }
        let function = Arc::new(self.runtime.deploy(wasm).map_err(|e| e.to_string())?);
        let mut cache = self.compiled.lock().unwrap_or_else(|e| e.into_inner());
        // Bounded by replacement, so that a stream of deployments cannot grow it forever.
        if cache.len() >= 1024 {
            cache.clear();
        }
        cache.insert(key, function.clone());
        Ok(function)
    }
}

pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/digest", get(digest))
        .route("/v1/functions/{tenant}/{name}", put(deploy).delete(remove))
        .route("/v1/functions/{tenant}/{name}/invoke", post(invoke))
        .route(
            "/v1/functions/{tenant}/{name}/execute/{function}",
            post(execute),
        )
        .route("/v1/functions/{tenant}/{name}/boot", post(boot))
        .route("/hooks/{tenant}/{name}", post(webhook))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(gateway)
}

fn error(code: StatusCode, message: impl std::fmt::Display) -> Response {
    (code, axum::Json(json!({ "error": message.to_string() }))).into_response()
}

fn require_admin(gateway: &Gateway, headers: &HeaderMap) -> Result<(), Response> {
    let Some(expected) = &gateway.admin_token_hash else {
        return Ok(());
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let hash: [u8; 32] = Sha256::digest(presented.unwrap_or("").as_bytes()).into();
    // Compares fixed-size digests without an early exit, so timing reveals nothing.
    let difference = hash
        .iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if presented.is_none() || difference != 0 {
        return Err(error(StatusCode::UNAUTHORIZED, "missing or invalid token"));
    }
    Ok(())
}

fn check_names(tenant: &str, name: &str) -> Result<(), Response> {
    if valid_name(tenant) && valid_name(name) {
        Ok(())
    } else {
        Err(error(
            StatusCode::BAD_REQUEST,
            "tenant and name must be 1-64 characters of [A-Za-z0-9_-]",
        ))
    }
}

fn propose_failure(gateway: &Gateway, failure: ProposeFailure) -> Response {
    match failure {
        ProposeFailure::NotLeader { leader } => {
            let leader_http = leader.and_then(|id| gateway.peer_http.get(&id).cloned());
            (
                StatusCode::MISDIRECTED_REQUEST,
                axum::Json(json!({
                    "error": "this node is not the leader",
                    "leader": leader,
                    "leader_http": leader_http,
                })),
            )
                .into_response()
        }
        ProposeFailure::Unknown => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "leadership changed; the outcome is unknown, and a retry may apply twice",
        ),
        ProposeFailure::Encoding(e) => error(StatusCode::BAD_REQUEST, e),
        ProposeFailure::Stopped => error(StatusCode::SERVICE_UNAVAILABLE, "the node is stopping"),
    }
}

fn output_response(output: Output) -> Response {
    match output {
        Output::Deployed => axum::Json(json!({ "status": "deployed" })).into_response(),
        Output::Removed => axum::Json(json!({ "status": "removed" })).into_response(),
        Output::Executed { result, gas_used } => match result {
            Ok(value) => {
                axum::Json(json!({ "result": value, "gas_used": gas_used })).into_response()
            }
            Err(trap) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                axum::Json(json!({ "trap": trap, "gas_used": gas_used })),
            )
                .into_response(),
        },
        Output::Rejected(reason) => error(StatusCode::BAD_REQUEST, reason),
    }
}

async fn status(AxumState(gateway): AxumState<Arc<Gateway>>) -> Response {
    match gateway.node.status().await {
        Some(s) => axum::Json(json!({
            "id": s.id,
            "role": format!("{:?}", s.role),
            "term": s.term,
            "leader": s.leader,
            "commit": s.commit,
            "applied": s.applied,
            "last_index": s.last_index,
            "snapshot_index": s.snapshot_index,
        }))
        .into_response(),
        None => error(StatusCode::SERVICE_UNAVAILABLE, "the node is stopping"),
    }
}

async fn digest(AxumState(gateway): AxumState<Arc<Gateway>>) -> Response {
    let state = gateway.node.state();
    let applied = gateway.node.status().await.map(|s| s.applied);
    let (digest, workloads) = {
        let state = state.read().unwrap_or_else(|e| e.into_inner());
        (state.digest(), state.len())
    };
    axum::Json(json!({ "digest": digest, "applied": applied, "workloads": workloads }))
        .into_response()
}

#[derive(Deserialize)]
struct DeployQuery {
    kind: String,
    #[serde(default = "default_memory")]
    memory_bytes: u64,
    webhook_secret: Option<String>,
    arch: Option<String>,
}

fn default_memory() -> u64 {
    1 << 16
}

async fn deploy(
    AxumState(gateway): AxumState<Arc<Gateway>>,
    Path((tenant, name)): Path<(String, String)>,
    Query(query): Query<DeployQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = require_admin(&gateway, &headers) {
        return r;
    }
    if let Err(r) = check_names(&tenant, &name) {
        return r;
    }
    let command = match query.kind.as_str() {
        "zel" => {
            let Ok(source) = String::from_utf8(body.to_vec()) else {
                return error(StatusCode::BAD_REQUEST, "Zel source must be UTF-8");
            };
            Command::DeployZel {
                tenant,
                name,
                source,
                memory_bytes: query.memory_bytes,
            }
        }
        "wasm" => {
            // Validating here keeps broken modules out of the replicated log entirely.
            if let Err(e) = gateway.runtime.deploy(&body) {
                return error(StatusCode::BAD_REQUEST, e);
            }
            Command::DeployWasm {
                tenant,
                name,
                wasm: body.to_vec(),
                webhook_secret: query.webhook_secret.map(String::into_bytes),
            }
        }
        "vm" => {
            let image = match query.arch.as_deref() {
                Some("x86-long") => VmImage::RawX86LongMode(body.to_vec()),
                Some("x86-real") => VmImage::RawX86RealMode(body.to_vec()),
                Some("aarch64") => VmImage::RawAarch64(body.to_vec()),
                _ => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "arch must be one of x86-long, x86-real or aarch64",
                    );
                }
            };
            Command::DeployVm {
                tenant,
                name,
                image,
            }
        }
        other => return error(StatusCode::BAD_REQUEST, format!("unknown kind `{other}`")),
    };
    match gateway.node.propose(&command).await {
        Ok(output) => output_response(output),
        Err(failure) => propose_failure(&gateway, failure),
    }
}

async fn remove(
    AxumState(gateway): AxumState<Arc<Gateway>>,
    Path((tenant, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&gateway, &headers) {
        return r;
    }
    match gateway
        .node
        .propose(&Command::Remove { tenant, name })
        .await
    {
        Ok(output) => output_response(output),
        Err(failure) => propose_failure(&gateway, failure),
    }
}

#[derive(Deserialize)]
struct ExecuteBody {
    #[serde(default)]
    args: Vec<i64>,
    #[serde(default = "default_gas")]
    gas: u64,
}

fn default_gas() -> u64 {
    10_000_000
}

async fn execute(
    AxumState(gateway): AxumState<Arc<Gateway>>,
    Path((tenant, name, function)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = require_admin(&gateway, &headers) {
        return r;
    }
    let parsed: ExecuteBody = if body.is_empty() {
        ExecuteBody {
            args: Vec::new(),
            gas: default_gas(),
        }
    } else {
        match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(e) => return error(StatusCode::BAD_REQUEST, e),
        }
    };
    let command = Command::Execute {
        tenant,
        name,
        function,
        args: parsed.args,
        gas: parsed.gas,
    };
    match gateway.node.propose(&command).await {
        Ok(output) => output_response(output),
        Err(failure) => propose_failure(&gateway, failure),
    }
}

/// A function's module bytes and its webhook secret.
type WasmEntry = (Arc<Vec<u8>>, Option<Vec<u8>>);

/// Fetches a Wasm function from the local replica, along with its webhook secret.
fn wasm_of(gateway: &Gateway, tenant: &str, name: &str) -> Option<WasmEntry> {
    let state = gateway.node.state();
    let state = state.read().unwrap_or_else(|e| e.into_inner());
    match state.get(tenant, name)? {
        Workload::Wasm {
            wasm,
            webhook_secret,
        } => Some((wasm.clone(), webhook_secret.clone())),
        _ => None,
    }
}

async fn run_wasm(
    gateway: Arc<Gateway>,
    tenant: String,
    wasm: Arc<Vec<u8>>,
    input: Bytes,
) -> Response {
    let slots = gateway.slots(&tenant);
    // One noisy tenant runs out of its own slots rather than starving everyone else.
    let Ok(_permit) = slots.try_acquire_owned() else {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "tenant concurrency limit reached",
        );
    };
    let task_gateway = gateway.clone();
    let result = tokio::task::spawn_blocking(move || {
        let function = task_gateway.compile(&wasm)?;
        Ok::<_, String>(
            task_gateway
                .runtime
                .invoke(&function, &input, &task_gateway.limits),
        )
    })
    .await;
    let outcome = match result {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(e)) => return error(StatusCode::BAD_REQUEST, e),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let mut headers = HeaderMap::new();
    let mut put_header = |name: &'static str, value: String| {
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(name, value);
        }
    };
    put_header("x-zeolite-fuel-used", outcome.fuel_used.to_string());
    put_header("x-zeolite-micros", outcome.elapsed.as_micros().to_string());
    put_header(
        "x-zeolite-cold-start-micros",
        outcome.instantiate.as_micros().to_string(),
    );
    match outcome.result {
        Ok(output) => (StatusCode::OK, headers, output).into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            headers,
            axum::Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn invoke(
    AxumState(gateway): AxumState<Arc<Gateway>>,
    Path((tenant, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = require_admin(&gateway, &headers) {
        return r;
    }
    let Some((wasm, _)) = wasm_of(&gateway, &tenant, &name) else {
        return error(StatusCode::NOT_FOUND, "no such Wasm function");
    };
    run_wasm(gateway, tenant, wasm, body).await
}

/// Public trigger. If the function has a secret, the caller must prove knowledge of it by
/// signing the body: `x-zeolite-signature: sha256=<hex hmac>`.
async fn webhook(
    AxumState(gateway): AxumState<Arc<Gateway>>,
    Path((tenant, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((wasm, secret)) = wasm_of(&gateway, &tenant, &name) else {
        return error(StatusCode::NOT_FOUND, "no such Wasm function");
    };
    if let Some(secret) = secret {
        let signature = headers
            .get("x-zeolite-signature")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("sha256="))
            .and_then(decode_hex);
        let Some(signature) = signature else {
            return error(StatusCode::UNAUTHORIZED, "missing or malformed signature");
        };
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&secret) else {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "invalid webhook secret");
        };
        mac.update(&body);
        if mac.verify_slice(&signature).is_err() {
            return error(StatusCode::UNAUTHORIZED, "signature does not match");
        }
    }
    run_wasm(gateway, tenant, wasm, body).await
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[derive(Deserialize)]
struct BootQuery {
    #[serde(default = "default_vm_memory")]
    memory_bytes: usize,
    #[serde(default = "default_vm_timeout")]
    timeout_ms: u64,
}

fn default_vm_memory() -> usize {
    16 << 20
}

fn default_vm_timeout() -> u64 {
    5000
}

async fn boot(
    AxumState(gateway): AxumState<Arc<Gateway>>,
    Path((tenant, name)): Path<(String, String)>,
    Query(query): Query<BootQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&gateway, &headers) {
        return r;
    }
    if query.memory_bytes > MAX_VM_MEMORY_BYTES {
        return error(StatusCode::BAD_REQUEST, "memory_bytes is too large");
    }
    let image = {
        let state = gateway.node.state();
        let state = state.read().unwrap_or_else(|e| e.into_inner());
        match state.get(&tenant, &name) {
            Some(Workload::Vm { image }) => image.clone(),
            _ => return error(StatusCode::NOT_FOUND, "no such micro-VM workload"),
        }
    };
    let slots = gateway.slots(&tenant);
    let Ok(_permit) = slots.try_acquire_owned() else {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "tenant concurrency limit reached",
        );
    };
    let payload = match image {
        VmImage::RawX86LongMode(b) => Payload::RawX86LongMode(b),
        VmImage::RawX86RealMode(b) => Payload::RawX86RealMode(b),
        VmImage::RawAarch64(b) => Payload::RawAarch64(b),
    };
    let mut cfg = VmConfig::new(payload);
    cfg.memory_bytes = query.memory_bytes;
    cfg.timeout = Duration::from_millis(query.timeout_ms.min(60_000));
    let result = tokio::task::spawn_blocking(move || zeolite_vmm::run(cfg)).await;
    match result {
        Ok(Ok(outcome)) => axum::Json(json!({
            "exit": format!("{:?}", outcome.exit),
            "serial": String::from_utf8_lossy(&outcome.serial),
            "elapsed_micros": outcome.elapsed.as_micros() as u64,
            "exits": outcome.exits,
        }))
        .into_response(),
        Ok(Err(VmError::Unavailable(why))) => error(StatusCode::NOT_IMPLEMENTED, why),
        Ok(Err(e)) => error(StatusCode::UNPROCESSABLE_ENTITY, e),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
