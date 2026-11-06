//! End-to-end tests: real nodes, real sockets, real fsync. All three pillars meet here.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeolite::http::{Gateway, router};
use zeolite::node::{Node, NodeConfig, ProposeFailure};
use zeolite::state::{Command, Output, VmImage};
use zeolite_faas::Runtime;
use zeolite_raft::Role;

const KEY: [u8; 32] = [42; 32];
const COUNTER: &str = "
    fn add(n) { let v = load(0) + n; store(0, v); return v; }
    fn get() { return load(0); }
";

fn temp_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zeolite-cluster-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

struct Cluster {
    addrs: BTreeMap<u64, SocketAddr>,
    dirs: BTreeMap<u64, PathBuf>,
    nodes: BTreeMap<u64, Node>,
    snapshot_every: u64,
}

impl Cluster {
    async fn start(size: u64, snapshot_every: u64) -> Cluster {
        let mut listeners = BTreeMap::new();
        let mut addrs = BTreeMap::new();
        for id in 1..=size {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            addrs.insert(id, listener.local_addr().unwrap());
            listeners.insert(id, listener);
        }
        let dirs: BTreeMap<u64, PathBuf> = (1..=size).map(|id| (id, temp_dir())).collect();
        let mut cluster = Cluster {
            addrs,
            dirs,
            nodes: BTreeMap::new(),
            snapshot_every,
        };
        for (id, listener) in listeners {
            let node = Node::start(cluster.config(id), listener).unwrap();
            cluster.nodes.insert(id, node);
        }
        cluster
    }

    fn config(&self, id: u64) -> NodeConfig {
        let peers = self
            .addrs
            .iter()
            .filter(|(peer, _)| **peer != id)
            .map(|(peer, addr)| (*peer, addr.to_string()))
            .collect();
        let mut cfg = NodeConfig::new(id, peers, self.dirs[&id].clone(), KEY);
        cfg.tick = Duration::from_millis(20);
        cfg.snapshot_every = self.snapshot_every;
        cfg
    }

    async fn restart(&mut self, id: u64) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let listener = loop {
            match TcpListener::bind(self.addrs[&id]).await {
                Ok(listener) => break listener,
                Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("could not rebind: {e}"),
            }
        };
        let node = Node::start(self.config(id), listener).unwrap();
        self.nodes.insert(id, node);
    }

    async fn leader(&self) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            for (id, node) in &self.nodes {
                if let Some(status) = node.status().await
                    && status.role == Role::Leader
                {
                    return *id;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no leader was elected");
    }

    /// Proposes on whichever node currently leads, retrying through elections.
    async fn propose(&self, command: &Command) -> Output {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            let leader = self.leader().await;
            match self.nodes[&leader].propose(command).await {
                Ok(output) => return output,
                Err(ProposeFailure::NotLeader { .. }) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(other) => panic!("proposal failed: {other}"),
            }
        }
        panic!("proposal timed out");
    }

    /// Waits for every live node to reach one applied index and one state digest.
    async fn converged(&self) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut last = String::new();
        while Instant::now() < deadline {
            let mut seen = Vec::new();
            for node in self.nodes.values() {
                let status = node.status().await.expect("the node is running");
                let digest = node.state().read().unwrap().digest();
                seen.push((status.applied, status.last_index, digest));
            }
            let first = seen[0].clone();
            if first.0 == first.1 && seen.iter().all(|s| *s == first) {
                return first.2;
            }
            last = format!("{seen:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("nodes did not converge: {last}");
    }

    fn cleanup(self) {
        let dirs = self.dirs.clone();
        drop(self);
        for dir in dirs.values() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn deploy_counter() -> Command {
    Command::DeployZel {
        tenant: "acme".into(),
        name: "counter".into(),
        source: COUNTER.into(),
        memory_bytes: 1024,
    }
}

fn add(n: i64) -> Command {
    Command::Execute {
        tenant: "acme".into(),
        name: "counter".into(),
        function: "add".into(),
        args: vec![n],
        gas: 100_000,
    }
}

fn executed_value(output: Output) -> i64 {
    match output {
        Output::Executed {
            result: Ok(value), ..
        } => value,
        other => panic!("expected a value, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_execution_is_identical_on_every_node() {
    let cluster = Cluster::start(3, 1000).await;
    assert_eq!(cluster.propose(&deploy_counter()).await, Output::Deployed);
    let mut expected = 0;
    for n in 1..=50 {
        expected += n;
        assert_eq!(executed_value(cluster.propose(&add(n)).await), expected);
    }
    let digest = cluster.converged().await;
    assert_eq!(digest.len(), 64);
    cluster.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cluster_survives_losing_its_leader() {
    let mut cluster = Cluster::start(3, 1000).await;
    cluster.propose(&deploy_counter()).await;
    assert_eq!(executed_value(cluster.propose(&add(10)).await), 10);

    let old_leader = cluster.leader().await;
    let term_before = cluster.nodes[&old_leader].status().await.unwrap().term;
    cluster.nodes.remove(&old_leader).unwrap().stop().unwrap();

    // The remaining majority elects a new leader, with all earlier state intact.
    assert_eq!(executed_value(cluster.propose(&add(5)).await), 15);
    let new_leader = cluster.leader().await;
    assert_ne!(new_leader, old_leader);
    assert!(cluster.nodes[&new_leader].status().await.unwrap().term > term_before);

    // The old leader recovers from disk and catches up.
    cluster.restart(old_leader).await;
    assert_eq!(executed_value(cluster.propose(&add(1)).await), 16);
    cluster.converged().await;
    cluster.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_minority_cannot_commit() {
    let mut cluster = Cluster::start(3, 1000).await;
    cluster.propose(&deploy_counter()).await;
    let leader = cluster.leader().await;
    let others: Vec<u64> = cluster
        .addrs
        .keys()
        .copied()
        .filter(|i| *i != leader)
        .collect();
    for other in &others {
        cluster.nodes.remove(other).unwrap().stop().unwrap();
    }

    let node = &cluster.nodes[&leader];
    let attempt = tokio::time::timeout(Duration::from_secs(2), node.propose(&add(1))).await;
    match attempt {
        Err(_) => {}
        Ok(Err(ProposeFailure::NotLeader { .. } | ProposeFailure::Unknown)) => {}
        Ok(other) => panic!("a lone node must not commit, but got {other:?}"),
    }

    // Once the majority is back, the cluster works again.
    for other in &others {
        cluster.restart(*other).await;
    }
    cluster.propose(&add(100)).await;
    cluster.converged().await;
    cluster.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_cluster_restart_recovers_from_disk() {
    let mut cluster = Cluster::start(3, 1000).await;
    cluster.propose(&deploy_counter()).await;
    assert_eq!(executed_value(cluster.propose(&add(7)).await), 7);
    let digest_before = cluster.converged().await;

    let ids: Vec<u64> = cluster.nodes.keys().copied().collect();
    for id in &ids {
        cluster.nodes.remove(id).unwrap().stop().unwrap();
    }
    for id in &ids {
        cluster.restart(*id).await;
    }
    // Commit a no-op-equivalent read before comparing, so that the log has been replayed.
    cluster.leader().await;
    assert_eq!(executed_value(cluster.propose(&add(0)).await), 7);
    let digest_after = cluster.converged().await;
    assert_eq!(
        digest_before, digest_after,
        "adding zero must not change the state"
    );
    cluster.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshots_compact_the_log_and_catch_up_a_lagging_node() {
    let mut cluster = Cluster::start(3, 10).await;
    cluster.propose(&deploy_counter()).await;

    let leader = cluster.leader().await;
    let lagging = cluster
        .addrs
        .keys()
        .copied()
        .find(|i| *i != leader)
        .unwrap();
    cluster.nodes.remove(&lagging).unwrap().stop().unwrap();

    let mut expected = 0;
    for n in 1..=40 {
        expected += n;
        assert_eq!(executed_value(cluster.propose(&add(n)).await), expected);
    }
    let leader = cluster.leader().await;
    let status = cluster.nodes[&leader].status().await.unwrap();
    assert!(
        status.snapshot_index > 0,
        "the leader should have compacted its log"
    );

    cluster.restart(lagging).await;
    cluster.converged().await;
    let status = cluster.nodes[&lagging].status().await.unwrap();
    assert!(
        status.snapshot_index > 0,
        "the lagging node should have installed a snapshot"
    );
    cluster.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn followers_refuse_writes_and_name_the_leader() {
    let cluster = Cluster::start(3, 1000).await;
    cluster.propose(&deploy_counter()).await;
    let leader = cluster.leader().await;
    cluster.converged().await;
    let follower = cluster
        .addrs
        .keys()
        .copied()
        .find(|i| *i != leader)
        .unwrap();
    match cluster.nodes[&follower].propose(&add(1)).await {
        Err(ProposeFailure::NotLeader { leader: hint }) => assert_eq!(hint, Some(leader)),
        other => panic!("expected a redirect, got {other:?}"),
    }
    cluster.cleanup();
}

// ---- HTTP gateway ----

struct HttpResponse {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

/// A deliberately small HTTP/1.1 client, so the tests see exactly what goes on the wire.
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header block");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("response has a status code");
    let mut body = raw[split + 4..].to_vec();
    if head.to_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body);
    }
    HttpResponse {
        status,
        headers: head,
        body,
    }
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(end) = data.windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(&String::from_utf8_lossy(&data[..end]), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        out.extend_from_slice(&data[end + 2..end + 2 + size]);
        data = &data[end + 2 + size + 2..];
    }
    out
}

struct Served {
    addr: SocketAddr,
    server: tokio::task::JoinHandle<()>,
}

async fn serve(node: Node, runtime: Arc<Runtime>, token: Option<&[u8]>) -> Served {
    let gateway = Gateway::new(Arc::new(node), runtime, token, BTreeMap::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router(gateway)).await;
    });
    Served { addr, server }
}

async fn single_node_gateway(token: Option<&[u8]>) -> (Served, PathBuf) {
    let dir = temp_dir();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node = Node::start(
        {
            let mut cfg = NodeConfig::new(1, BTreeMap::new(), dir.clone(), KEY);
            cfg.tick = Duration::from_millis(10);
            cfg
        },
        listener,
    )
    .unwrap();
    let served = serve(node, Arc::new(Runtime::new().unwrap()), token).await;

    // A single node elects itself.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let r = http(served.addr, "GET", "/v1/status", &[], b"").await;
        if String::from_utf8_lossy(&r.body).contains("Leader") {
            return (served, dir);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the single node never became leader");
}

fn echo_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (memory (export "memory") 1)
            (func (export "alloc") (param i32) (result i32) i32.const 1024)
            (func (export "handle") (param $p i32) (param $l i32) (result i64)
                local.get $p
                i64.extend_i32_u
                i64.const 32
                i64.shl
                local.get $l
                i64.extend_i32_u
                i64.or))"#,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_deploys_and_invokes_wasm_with_metering_headers() {
    let (s, dir) = single_node_gateway(None).await;
    let r = http(
        s.addr,
        "PUT",
        "/v1/functions/acme/echo?kind=wasm",
        &[],
        &echo_wasm(),
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    let r = http(
        s.addr,
        "POST",
        "/v1/functions/acme/echo/invoke",
        &[],
        b"ping",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"ping");
    assert!(r.headers.to_lowercase().contains("x-zeolite-fuel-used"));
    assert!(
        r.headers
            .to_lowercase()
            .contains("x-zeolite-cold-start-micros")
    );

    let r = http(
        s.addr,
        "POST",
        "/v1/functions/acme/missing/invoke",
        &[],
        b"",
    )
    .await;
    assert_eq!(r.status, 404);

    s.server.abort();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_rejects_bad_deployments() {
    let (s, dir) = single_node_gateway(None).await;
    for (path, body) in [
        ("/v1/functions/acme/x?kind=wasm", b"not wasm".as_slice()),
        ("/v1/functions/acme/x?kind=zel", b"fn f( {".as_slice()),
        ("/v1/functions/acme/x?kind=zel", b"\xFF\xFE".as_slice()),
        ("/v1/functions/acme/x?kind=nonsense", b"".as_slice()),
        ("/v1/functions/acme/x?kind=vm", b"".as_slice()),
        (
            "/v1/functions/..%2Fetc/x?kind=zel",
            b"fn f() { }".as_slice(),
        ),
    ] {
        let r = http(s.addr, "PUT", path, &[], body).await;
        assert_eq!(
            r.status,
            400,
            "{path}: {}",
            String::from_utf8_lossy(&r.body)
        );
    }
    let r = http(s.addr, "GET", "/v1/digest", &[], b"").await;
    assert!(
        String::from_utf8_lossy(&r.body).contains("\"workloads\":0"),
        "nothing should have been deployed: {}",
        String::from_utf8_lossy(&r.body)
    );
    s.server.abort();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_runs_replicated_zel_over_http() {
    let (s, dir) = single_node_gateway(None).await;
    let r = http(
        s.addr,
        "PUT",
        "/v1/functions/acme/c?kind=zel",
        &[],
        COUNTER.as_bytes(),
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let body = br#"{"args":[5],"gas":10000}"#;
    let r = http(
        s.addr,
        "POST",
        "/v1/functions/acme/c/execute/add",
        &[],
        body,
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).contains("\"result\":5"));
    let r = http(
        s.addr,
        "POST",
        "/v1/functions/acme/c/execute/add",
        &[],
        br#"{"args":[5]}"#,
    )
    .await;
    assert!(String::from_utf8_lossy(&r.body).contains("\"result\":10"));

    // Running out of gas is a committed, deterministic result. It is not a server error.
    let r = http(
        s.addr,
        "POST",
        "/v1/functions/acme/c/execute/add",
        &[],
        br#"{"args":[1],"gas":1}"#,
    )
    .await;
    assert_eq!(r.status, 422);
    assert!(String::from_utf8_lossy(&r.body).contains("gas"));

    let r = http(s.addr, "DELETE", "/v1/functions/acme/c", &[], b"").await;
    assert_eq!(r.status, 200);
    let r = http(s.addr, "POST", "/v1/functions/acme/c/execute/get", &[], b"").await;
    assert_eq!(r.status, 400);
    s.server.abort();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_token_protects_mutating_endpoints() {
    let (s, dir) = single_node_gateway(Some(b"s3cret")).await;
    let path = "/v1/functions/acme/echo?kind=wasm";
    for headers in [
        vec![],
        vec![("Authorization", "Bearer wrong")],
        vec![("Authorization", "s3cret")],
        vec![("Authorization", "Bearer ")],
    ] {
        let r = http(s.addr, "PUT", path, &headers, &echo_wasm()).await;
        assert_eq!(r.status, 401, "{headers:?}");
    }
    let auth = [("Authorization", "Bearer s3cret")];
    let r = http(s.addr, "PUT", path, &auth, &echo_wasm()).await;
    assert_eq!(r.status, 200);

    let r = http(s.addr, "POST", "/v1/functions/acme/echo/invoke", &[], b"x").await;
    assert_eq!(r.status, 401, "invoke requires the token too");
    let r = http(
        s.addr,
        "POST",
        "/v1/functions/acme/echo/invoke",
        &auth,
        b"x",
    )
    .await;
    assert_eq!(r.status, 200);

    // Status endpoints stay readable, for health checks.
    assert_eq!(
        http(s.addr, "GET", "/v1/status", &[], b"").await.status,
        200
    );
    s.server.abort();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webhooks_verify_their_signature() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let (s, dir) = single_node_gateway(None).await;
    let path = "/v1/functions/acme/hook?kind=wasm&webhook_secret=topsecret";
    assert_eq!(
        http(s.addr, "PUT", path, &[], &echo_wasm()).await.status,
        200
    );

    let sign = |body: &[u8]| -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"topsecret").unwrap();
        mac.update(body);
        let tag = mac.finalize().into_bytes();
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256={hex}")
    };

    let body = b"payload";
    let good = sign(body);
    let header = [("x-zeolite-signature", good.as_str())];
    let r = http(s.addr, "POST", "/hooks/acme/hook", &header, body).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, body);

    let tampered = http(s.addr, "POST", "/hooks/acme/hook", &header, b"payloaX").await;
    assert_eq!(tampered.status, 401, "a modified body must fail");
    let missing = http(s.addr, "POST", "/hooks/acme/hook", &[], body).await;
    assert_eq!(missing.status, 401);
    for bad in ["sha256=zz", "sha256=abc", "md5=00", "", "sha256=é1"] {
        let r = http(
            s.addr,
            "POST",
            "/hooks/acme/hook",
            &[("x-zeolite-signature", bad)],
            body,
        )
        .await;
        assert_eq!(r.status, 401, "{bad}");
    }

    // A function deployed without a secret is a public webhook.
    let path = "/v1/functions/acme/open?kind=wasm";
    assert_eq!(
        http(s.addr, "PUT", path, &[], &echo_wasm()).await.status,
        200
    );
    assert_eq!(
        http(s.addr, "POST", "/hooks/acme/open", &[], b"hi")
            .await
            .status,
        200
    );
    s.server.abort();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn micro_vm_workloads_are_replicated_and_booted_through_the_gateway() {
    let (s, dir) = single_node_gateway(None).await;

    // Picks a payload this host's hypervisor can run. Prints "ok" and stops.
    let (arch, image): (&str, Vec<u8>) = if cfg!(target_arch = "aarch64") {
        let mut blob: Vec<u8> = [
            0xD2A1_2000u32,
            0x1000_00C1,
            0x3840_1422,
            0x3400_0062,
            0x3900_0002,
            0x17FF_FFFD,
            0xD400_0002,
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        blob.extend_from_slice(b"ok\0");
        ("aarch64", blob)
    } else {
        (
            "x86-long",
            vec![
                0x66, 0xBA, 0xF8, 0x03, 0xB0, b'o', 0xEE, 0xB0, b'k', 0xEE, 0xF4,
            ],
        )
    };

    let path = format!("/v1/functions/acme/vm?kind=vm&arch={arch}");
    assert_eq!(http(s.addr, "PUT", &path, &[], &image).await.status, 200);
    let r = http(s.addr, "POST", "/v1/functions/acme/vm/boot", &[], b"").await;
    let text = String::from_utf8_lossy(&r.body).to_string();
    match r.status {
        200 => {
            assert!(text.contains("\"serial\":\"ok\""), "{text}");
            assert!(text.contains("Halted"), "{text}");
        }
        // No hypervisor is reachable here, which is a legitimate outcome on some hosts.
        501 => {
            assert!(
                std::env::var_os("ZEOLITE_REQUIRE_HV").is_none(),
                "a hypervisor is required: {text}"
            );
            eprintln!("skipping the boot check: {text}");
        }
        other => panic!("unexpected status {other}: {text}"),
    }

    let r = http(
        s.addr,
        "POST",
        "/v1/functions/acme/vm/boot?memory_bytes=99999999999",
        &[],
        b"",
    )
    .await;
    assert_eq!(r.status, 400, "guest memory requests have an upper bound");
    let r = http(s.addr, "POST", "/v1/functions/acme/nope/boot", &[], b"").await;
    assert_eq!(r.status, 404);
    s.server.abort();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_bodies_are_refused() {
    let (s, dir) = single_node_gateway(None).await;
    let huge = vec![0u8; zeolite::http::MAX_BODY_BYTES + 1];
    let mut stream = TcpStream::connect(s.addr).await.unwrap();
    let head = format!(
        "PUT /v1/functions/acme/x?kind=wasm HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        huge.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let _ = stream.write_all(&huge).await;
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw);
    assert!(
        text.starts_with("HTTP/1.1 413"),
        "got: {}",
        &text[..text.len().min(100)]
    );
    s.server.abort();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn vm_image_commands_round_trip_through_the_log_encoding() {
    let command = Command::DeployVm {
        tenant: "a".into(),
        name: "b".into(),
        image: VmImage::RawAarch64(vec![1, 2, 3]),
    };
    let bytes = postcard::to_allocvec(&command).unwrap();
    assert_eq!(postcard::from_bytes::<Command>(&bytes).unwrap(), command);
}
