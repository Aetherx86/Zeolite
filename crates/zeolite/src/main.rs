use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use zeolite::http::{Gateway, router};
use zeolite::node::{Node, NodeConfig};
use zeolite_faas::{Limits, Runtime};
use zeolite_jit::{Backend, Limits as JitLimits, Module};
use zeolite_vmm::{Payload, VmConfig};

#[derive(Parser)]
#[command(
    name = "zeolite",
    version,
    about = "Distributed micro-VM and sandboxed function runtime"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Runs a cluster node.
    Serve {
        #[arg(long)]
        id: u64,
        /// Address for consensus traffic.
        #[arg(long)]
        raft: String,
        /// Address for the HTTP gateway.
        #[arg(long)]
        http: String,
        /// A peer, as ID=RAFT_ADDR=HTTP_ADDR. Repeat once per peer.
        #[arg(long = "peer")]
        peers: Vec<String>,
        #[arg(long)]
        data: PathBuf,
        /// File holding the 32-byte cluster key as 64 hex characters.
        #[arg(long)]
        key_file: PathBuf,
        /// File holding the admin token. Without it, mutating endpoints are open.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Prints a new random cluster key, in the format `--key-file` expects.
    GenerateKey,
    /// Runs a Zel program locally.
    Zel {
        file: PathBuf,
        #[arg(long, default_value = "main")]
        call: String,
        #[arg(long, value_delimiter = ',', allow_hyphen_values = true)]
        args: Vec<i64>,
        #[arg(long, default_value_t = 100_000_000)]
        gas: u64,
        #[arg(long, default_value_t = 65536)]
        memory: usize,
        #[arg(long, conflicts_with = "compare")]
        interpret: bool,
        /// Runs the call on both the interpreter and the JIT, each on its own copy of
        /// memory, and fails unless results, gas and final memory all agree.
        #[arg(long)]
        compare: bool,
        /// Prints the outcome as JSON on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Examines a node's data directory without modifying it.
    Inspect {
        /// The directory given to `serve --data`.
        dir: PathBuf,
        /// Prints the report as JSON on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Runs a Wasm function locally, with stdin as its input.
    Wasm {
        file: PathBuf,
        #[arg(long, default_value_t = 100_000_000)]
        fuel: u64,
    },
    /// Boots a micro-VM and prints its serial output.
    Vm {
        /// Linux bzImage to boot.
        #[arg(long, conflicts_with_all = ["blob_long", "blob_real", "blob_aarch64"])]
        kernel: Option<PathBuf>,
        #[arg(
            long,
            default_value = "console=ttyS0 reboot=k panic=-1 noapic nolapic pci=off"
        )]
        cmdline: String,
        #[arg(long)]
        initrd: Option<PathBuf>,
        /// Raw x86-64 code, entered in 64-bit mode.
        #[arg(long)]
        blob_long: Option<PathBuf>,
        /// Raw x86 code, entered in 16-bit real mode.
        #[arg(long)]
        blob_real: Option<PathBuf>,
        /// Raw AArch64 code, entered at EL1 on Apple Silicon.
        #[arg(long)]
        blob_aarch64: Option<PathBuf>,
        #[arg(long, default_value_t = 256)]
        memory_mib: usize,
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
    },
}

type AnyError = Box<dyn std::error::Error + Send + Sync>;

fn read_key(path: &PathBuf) -> Result<[u8; 32], AnyError> {
    let text = std::fs::read_to_string(path)?;
    let text = text.trim();
    if text.len() != 64 {
        return Err("the key file must hold exactly 64 hex characters".into());
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| "the key file holds a non-hex character")?;
    }
    Ok(key)
}

fn parse_peer(text: &str) -> Result<(u64, String, String), AnyError> {
    let mut parts = text.splitn(3, '=');
    let (Some(id), Some(raft), Some(http)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(format!("peer `{text}` is not in the form ID=RAFT_ADDR=HTTP_ADDR").into());
    };
    Ok((id.parse()?, raft.to_string(), http.to_string()))
}

async fn serve(
    id: u64,
    raft: String,
    http: String,
    peers: Vec<String>,
    data: PathBuf,
    key_file: PathBuf,
    token_file: Option<PathBuf>,
) -> Result<(), AnyError> {
    let key = read_key(&key_file)?;
    let token = match &token_file {
        Some(path) => Some(std::fs::read_to_string(path)?.trim().as_bytes().to_vec()),
        None => {
            eprintln!(
                "warning: no --token-file was given, so mutating endpoints are open to anyone who can reach them"
            );
            None
        }
    };

    let mut peer_raft = BTreeMap::new();
    let mut peer_http = BTreeMap::new();
    for text in &peers {
        let (peer, raft_addr, http_addr) = parse_peer(text)?;
        peer_raft.insert(peer, raft_addr);
        peer_http.insert(peer, http_addr);
    }

    let raft_listener = tokio::net::TcpListener::bind(&raft).await?;
    let node = Arc::new(Node::start(
        NodeConfig::new(id, peer_raft, data, key),
        raft_listener,
    )?);
    let runtime = Arc::new(Runtime::new()?);
    let gateway = Gateway::new(node, runtime, token.as_deref(), peer_http);

    let listener = tokio::net::TcpListener::bind(&http).await?;
    eprintln!("node {id}: consensus on {raft}, gateway on {http}");
    axum::serve(listener, router(gateway)).await?;
    Ok(())
}

struct ZelRun {
    backend: Backend,
    outcome: zeolite_jit::Outcome,
    memory: Vec<u8>,
}

impl ZelRun {
    fn json(&self) -> serde_json::Value {
        use sha2::{Digest, Sha256};
        let digest: String = Sha256::digest(&self.memory)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut value = serde_json::json!({
            "backend": match self.backend {
                Backend::Interpreter => "interpreter",
                Backend::Jit => "jit",
            },
            "gas_used": self.outcome.gas_used,
            "memory_sha256": digest,
        });
        match self.outcome.result {
            Ok(result) => value["result"] = result.into(),
            Err(trap) => value["trap"] = trap.to_string().into(),
        }
        value
    }
}

#[allow(clippy::too_many_arguments)]
fn run_zel(
    file: PathBuf,
    call: String,
    args: Vec<i64>,
    gas: u64,
    memory: usize,
    interpret: bool,
    compare: bool,
    json: bool,
) -> Result<(), AnyError> {
    let source = std::fs::read_to_string(file)?;
    let module = if interpret {
        Module::compile_interpreted(&source)?
    } else {
        Module::compile(&source)?
    };
    let backends: &[Backend] = if compare {
        &[Backend::Interpreter, Backend::Jit]
    } else if interpret {
        &[Backend::Interpreter]
    } else {
        &[Backend::Jit]
    };
    let mut runs = Vec::new();
    for backend in backends {
        let mut linear = vec![0u8; memory];
        let outcome = module.call(
            *backend,
            &call,
            &args,
            &mut linear,
            JitLimits::with_gas(gas),
        )?;
        runs.push(ZelRun {
            backend: *backend,
            outcome,
            memory: linear,
        });
    }

    if compare {
        let (a, b) = (&runs[0], &runs[1]);
        let agree = a.outcome == b.outcome && a.memory == b.memory;
        if json {
            let report = serde_json::json!({
                "function": call,
                "agree": agree,
                "interpreter": a.json(),
                "jit": b.json(),
            });
            println!("{report}");
        } else {
            for run in &runs {
                let shown = run.json();
                println!(
                    "{:<12} {} (gas used {})",
                    shown["backend"].as_str().unwrap_or(""),
                    match run.outcome.result {
                        Ok(value) => value.to_string(),
                        Err(trap) => format!("trap: {trap}"),
                    },
                    run.outcome.gas_used
                );
            }
        }
        if !agree {
            return Err("the interpreter and the JIT disagree".into());
        }
        return Ok(());
    }

    let run = &runs[0];
    if json {
        let mut report = run.json();
        report["function"] = call.into();
        println!("{report}");
        return Ok(());
    }
    eprintln!("gas used: {}", run.outcome.gas_used);
    match run.outcome.result {
        Ok(value) => {
            println!("{value}");
            Ok(())
        }
        Err(trap) => Err(format!("trap: {trap}").into()),
    }
}

fn run_inspect(dir: PathBuf, json: bool) -> Result<(), AnyError> {
    let report = zeolite::inspect::inspect(&dir)?;
    if json {
        println!("{}", zeolite::inspect::to_json(&report));
    } else {
        print!("{}", zeolite::inspect::to_text(&report));
    }
    if report.is_unrecoverable() {
        return Err("a node could not start from this directory".into());
    }
    Ok(())
}

fn run_wasm(file: PathBuf, fuel: u64) -> Result<(), AnyError> {
    use std::io::{Read, Write};
    let wasm = std::fs::read(file)?;
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let runtime = Runtime::new()?;
    let function = runtime.deploy(&wasm)?;
    let limits = Limits {
        fuel,
        ..Limits::default()
    };
    let outcome = runtime.invoke(&function, &input, &limits);
    eprintln!(
        "fuel used: {}, instantiate: {:?}, total: {:?}",
        outcome.fuel_used, outcome.instantiate, outcome.elapsed
    );
    if !outcome.logs.is_empty() {
        eprintln!("logs: {}", String::from_utf8_lossy(&outcome.logs));
    }
    std::io::stdout().write_all(&outcome.result?)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_vm(
    kernel: Option<PathBuf>,
    cmdline: String,
    initrd: Option<PathBuf>,
    blob_long: Option<PathBuf>,
    blob_real: Option<PathBuf>,
    blob_aarch64: Option<PathBuf>,
    memory_mib: usize,
    timeout_secs: u64,
) -> Result<(), AnyError> {
    use std::io::Write;
    let payload = if let Some(path) = kernel {
        Payload::LinuxBzImage {
            kernel: std::fs::read(path)?,
            cmdline,
            initrd: initrd.map(std::fs::read).transpose()?,
        }
    } else if let Some(path) = blob_long {
        Payload::RawX86LongMode(std::fs::read(path)?)
    } else if let Some(path) = blob_real {
        Payload::RawX86RealMode(std::fs::read(path)?)
    } else if let Some(path) = blob_aarch64 {
        Payload::RawAarch64(std::fs::read(path)?)
    } else {
        return Err("give one of --kernel, --blob-long, --blob-real or --blob-aarch64".into());
    };
    let mut cfg = VmConfig::new(payload);
    cfg.memory_bytes = memory_mib << 20;
    cfg.timeout = Duration::from_secs(timeout_secs);
    let outcome = zeolite_vmm::run(cfg)?;
    std::io::stdout().write_all(&outcome.serial)?;
    eprintln!(
        "exit: {:?}, elapsed: {:?}, VM exits: {}",
        outcome.exit, outcome.elapsed, outcome.exits
    );
    Ok(())
}

fn main() -> Result<(), AnyError> {
    match Cli::parse().command {
        Commands::Serve {
            id,
            raft,
            http,
            peers,
            data,
            key_file,
            token_file,
        } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(serve(id, raft, http, peers, data, key_file, token_file)),
        Commands::GenerateKey => {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).map_err(|e| e.to_string())?;
            let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
            println!("{hex}");
            Ok(())
        }
        Commands::Zel {
            file,
            call,
            args,
            gas,
            memory,
            interpret,
            compare,
            json,
        } => run_zel(file, call, args, gas, memory, interpret, compare, json),
        Commands::Inspect { dir, json } => run_inspect(dir, json),
        Commands::Wasm { file, fuel } => run_wasm(file, fuel),
        Commands::Vm {
            kernel,
            cmdline,
            initrd,
            blob_long,
            blob_real,
            blob_aarch64,
            memory_mib,
            timeout_secs,
        } => run_vm(
            kernel,
            cmdline,
            initrd,
            blob_long,
            blob_real,
            blob_aarch64,
            memory_mib,
            timeout_secs,
        ),
    }
}
