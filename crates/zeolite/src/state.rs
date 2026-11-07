//! The replicated state machine: `State + Command -> New State + Result`.
//!
//! Every node applies the same commands in the same order, so `apply` must be a pure
//! function of the current state and the command. Compilation results and other local
//! caches stay outside the digest, and metering is deterministic, so all replicas agree.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeolite_jit::{Backend, Limits as JitLimits, Module};

pub const MAX_ZEL_SOURCE_BYTES: usize = 256 << 10;
pub const MAX_ZEL_MEMORY_BYTES: u64 = 16 << 20;
pub const MAX_EXEC_GAS: u64 = 1_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// Deploys a Zel program with persistent linear memory.
    DeployZel {
        tenant: String,
        name: String,
        source: String,
        memory_bytes: u64,
    },
    /// Stores a Wasm function for request-scoped invocation on any node.
    DeployWasm {
        tenant: String,
        name: String,
        wasm: Vec<u8>,
        webhook_secret: Option<Vec<u8>>,
    },
    /// Stores a micro-VM payload. Each node boots it when asked to.
    DeployVm {
        tenant: String,
        name: String,
        image: VmImage,
    },
    /// Runs a Zel function on every replica, mutating its replicated memory.
    Execute {
        tenant: String,
        name: String,
        function: String,
        args: Vec<i64>,
        gas: u64,
    },
    Remove {
        tenant: String,
        name: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmImage {
    RawX86LongMode(Vec<u8>),
    RawX86RealMode(Vec<u8>),
    RawAarch64(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Output {
    Deployed,
    Removed,
    Executed {
        result: Result<i64, String>,
        gas_used: u64,
    },
    /// The command was committed but had no effect. Replicas all reject it identically.
    Rejected(String),
}

/// Serialized form of a workload, which is exactly what the digest covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum StoredWorkload {
    Zel {
        source: String,
        memory: Vec<u8>,
    },
    Wasm {
        wasm: Vec<u8>,
        webhook_secret: Option<Vec<u8>>,
    },
    Vm {
        image: VmImage,
    },
}

/// A deployed workload, with its compiled code held alongside the stored form.
pub enum Workload {
    Zel {
        source: String,
        memory: Vec<u8>,
        module: Arc<Module>,
    },
    Wasm {
        wasm: Arc<Vec<u8>>,
        webhook_secret: Option<Vec<u8>>,
    },
    Vm {
        image: VmImage,
    },
}

#[derive(Default)]
pub struct State {
    workloads: BTreeMap<(String, String), Workload>,
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn compile(source: &str) -> Result<Arc<Module>, String> {
    // Native compilation can fail on hosts that forbid executable memory. Interpreted
    // modules behave identically, so falling back cannot fork replica state. A compile
    // error in the source itself is reported by both paths with the same message.
    let module = match Module::compile(source) {
        Ok(module) => module,
        Err(error) if error.message.starts_with("code generation failed") => {
            Module::compile_interpreted(source).map_err(|e| e.to_string())?
        }
        Err(error) => return Err(error.to_string()),
    };
    Ok(Arc::new(module))
}

impl State {
    pub fn get(&self, tenant: &str, name: &str) -> Option<&Workload> {
        self.workloads.get(&(tenant.to_string(), name.to_string()))
    }

    pub fn len(&self) -> usize {
        self.workloads.len()
    }

    pub fn is_empty(&self) -> bool {
        self.workloads.is_empty()
    }

    pub fn apply(&mut self, command: Command) -> Output {
        match command {
            Command::DeployZel {
                tenant,
                name,
                source,
                memory_bytes,
            } => {
                if let Err(e) = check_identity(&tenant, &name) {
                    return Output::Rejected(e);
                }
                if source.len() > MAX_ZEL_SOURCE_BYTES {
                    return Output::Rejected("source is too large".into());
                }
                if !(8..=MAX_ZEL_MEMORY_BYTES).contains(&memory_bytes) {
                    return Output::Rejected(format!(
                        "memory size must be between 8 and {MAX_ZEL_MEMORY_BYTES} bytes"
                    ));
                }
                let module = match compile(&source) {
                    Ok(module) => module,
                    Err(e) => return Output::Rejected(e),
                };
                self.workloads.insert(
                    (tenant, name),
                    Workload::Zel {
                        source,
                        memory: vec![0; memory_bytes as usize],
                        module,
                    },
                );
                Output::Deployed
            }
            Command::DeployWasm {
                tenant,
                name,
                wasm,
                webhook_secret,
            } => {
                if let Err(e) = check_identity(&tenant, &name) {
                    return Output::Rejected(e);
                }
                self.workloads.insert(
                    (tenant, name),
                    Workload::Wasm {
                        wasm: Arc::new(wasm),
                        webhook_secret,
                    },
                );
                Output::Deployed
            }
            Command::DeployVm {
                tenant,
                name,
                image,
            } => {
                if let Err(e) = check_identity(&tenant, &name) {
                    return Output::Rejected(e);
                }
                self.workloads
                    .insert((tenant, name), Workload::Vm { image });
                Output::Deployed
            }
            Command::Execute {
                tenant,
                name,
                function,
                args,
                gas,
            } => self.execute(tenant, name, &function, &args, gas),
            Command::Remove { tenant, name } => match self.workloads.remove(&(tenant, name)) {
                Some(_) => Output::Removed,
                None => Output::Rejected("no such workload".into()),
            },
        }
    }

    fn execute(
        &mut self,
        tenant: String,
        name: String,
        function: &str,
        args: &[i64],
        gas: u64,
    ) -> Output {
        let Some(Workload::Zel { memory, module, .. }) = self.workloads.get_mut(&(tenant, name))
        else {
            return Output::Rejected("no such Zel workload".into());
        };
        let backend = if module.has_jit() {
            Backend::Jit
        } else {
            Backend::Interpreter
        };
        let limits = JitLimits::with_gas(gas.min(MAX_EXEC_GAS));
        match module.call(backend, function, args, memory, limits) {
            Ok(outcome) => Output::Executed {
                result: outcome.result.map_err(|t| t.to_string()),
                gas_used: outcome.gas_used,
            },
            Err(error) => Output::Rejected(error.to_string()),
        }
    }

    /// Canonical encoding of the replicated state, used for snapshots and digests.
    pub fn encode(&self) -> Vec<u8> {
        let stored: Vec<(&(String, String), StoredWorkload)> = self
            .workloads
            .iter()
            .map(|(key, workload)| {
                let stored = match workload {
                    Workload::Zel { source, memory, .. } => StoredWorkload::Zel {
                        source: source.clone(),
                        memory: memory.clone(),
                    },
                    Workload::Wasm {
                        wasm,
                        webhook_secret,
                    } => StoredWorkload::Wasm {
                        wasm: wasm.as_ref().clone(),
                        webhook_secret: webhook_secret.clone(),
                    },
                    Workload::Vm { image } => StoredWorkload::Vm {
                        image: image.clone(),
                    },
                };
                (key, stored)
            })
            .collect();
        // Encoding plain data into a Vec has no failure path for these types.
        postcard::to_allocvec(&stored).unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Result<State, String> {
        let stored: Vec<((String, String), StoredWorkload)> =
            postcard::from_bytes(bytes).map_err(|e| e.to_string())?;
        let mut workloads = BTreeMap::new();
        for (key, workload) in stored {
            let workload = match workload {
                StoredWorkload::Zel { source, memory } => Workload::Zel {
                    module: compile(&source)?,
                    source,
                    memory,
                },
                StoredWorkload::Wasm {
                    wasm,
                    webhook_secret,
                } => Workload::Wasm {
                    wasm: Arc::new(wasm),
                    webhook_secret,
                },
                StoredWorkload::Vm { image } => Workload::Vm { image },
            };
            workloads.insert(key, workload);
        }
        Ok(State { workloads })
    }

    /// SHA-256 over the canonical encoding. Replicas at one applied index must agree.
    pub fn digest(&self) -> String {
        Sha256::digest(self.encode())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

fn check_identity(tenant: &str, name: &str) -> Result<(), String> {
    if valid_name(tenant) && valid_name(name) {
        Ok(())
    } else {
        Err("tenant and workload names must be 1-64 characters of [A-Za-z0-9_-]".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTER: &str = "
        fn add(n) { let v = load(0) + n; store(0, v); return v; }
        fn get() { return load(0); }
        fn crash() { store(0, 999); return 1 / 0; }
    ";

    fn deploy(state: &mut State) {
        let out = state.apply(Command::DeployZel {
            tenant: "acme".into(),
            name: "counter".into(),
            source: COUNTER.into(),
            memory_bytes: 64,
        });
        assert_eq!(out, Output::Deployed);
    }

    fn exec(state: &mut State, function: &str, args: &[i64]) -> Output {
        state.apply(Command::Execute {
            tenant: "acme".into(),
            name: "counter".into(),
            function: function.into(),
            args: args.to_vec(),
            gas: 10_000,
        })
    }

    #[test]
    fn execution_mutates_replicated_memory() {
        let mut state = State::default();
        deploy(&mut state);
        for expected in [5, 10] {
            match exec(&mut state, "add", &[5]) {
                Output::Executed { result, .. } => assert_eq!(result, Ok(expected)),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn identical_command_sequences_produce_identical_digests() {
        let run = || {
            let mut state = State::default();
            deploy(&mut state);
            exec(&mut state, "add", &[7]);
            exec(&mut state, "crash", &[]);
            state.digest()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn digest_covers_memory_and_code() {
        let mut state = State::default();
        deploy(&mut state);
        let before = state.digest();
        exec(&mut state, "add", &[1]);
        assert_ne!(state.digest(), before);
    }

    #[test]
    fn a_trap_keeps_the_partial_writes_of_the_trapping_call() {
        // Replicas agree either way, but the semantics have to be pinned: effects before a
        // trap are retained, and the trap itself is the committed result.
        let mut state = State::default();
        deploy(&mut state);
        match exec(&mut state, "crash", &[]) {
            Output::Executed { result, .. } => assert!(result.unwrap_err().contains("division")),
            other => panic!("{other:?}"),
        }
        match exec(&mut state, "get", &[]) {
            Output::Executed { result, .. } => assert_eq!(result, Ok(999)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn snapshot_round_trip_preserves_state_and_digest() {
        let mut state = State::default();
        deploy(&mut state);
        exec(&mut state, "add", &[42]);
        state.apply(Command::DeployWasm {
            tenant: "acme".into(),
            name: "fn".into(),
            wasm: vec![1, 2, 3],
            webhook_secret: Some(vec![9]),
        });
        state.apply(Command::DeployVm {
            tenant: "acme".into(),
            name: "vm".into(),
            image: VmImage::RawX86LongMode(vec![0xF4]),
        });

        let mut restored = State::decode(&state.encode()).unwrap();
        assert_eq!(restored.digest(), state.digest());
        assert_eq!(restored.len(), 3);
        match exec(&mut restored, "get", &[]) {
            Output::Executed { result, .. } => assert_eq!(result, Ok(42)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn invalid_commands_are_rejected_without_changing_state() {
        let mut state = State::default();
        deploy(&mut state);
        let before = state.digest();
        let rejected = [
            Command::DeployZel {
                tenant: "../etc".into(),
                name: "x".into(),
                source: COUNTER.into(),
                memory_bytes: 64,
            },
            Command::DeployZel {
                tenant: "a".into(),
                name: "x".into(),
                source: "fn f( {".into(),
                memory_bytes: 64,
            },
            Command::DeployZel {
                tenant: "a".into(),
                name: "x".into(),
                source: COUNTER.into(),
                memory_bytes: 2,
            },
            Command::DeployZel {
                tenant: "a".into(),
                name: "x".into(),
                source: COUNTER.into(),
                memory_bytes: MAX_ZEL_MEMORY_BYTES + 1,
            },
            Command::DeployZel {
                tenant: "a".into(),
                name: "x".into(),
                source: "x".repeat(MAX_ZEL_SOURCE_BYTES + 1),
                memory_bytes: 64,
            },
            Command::DeployWasm {
                tenant: "".into(),
                name: "x".into(),
                wasm: vec![],
                webhook_secret: None,
            },
            Command::DeployVm {
                tenant: "a".into(),
                name: "x/y".into(),
                image: VmImage::RawX86LongMode(vec![]),
            },
            Command::Execute {
                tenant: "acme".into(),
                name: "missing".into(),
                function: "f".into(),
                args: vec![],
                gas: 1,
            },
            Command::Execute {
                tenant: "acme".into(),
                name: "counter".into(),
                function: "missing".into(),
                args: vec![],
                gas: 1,
            },
            Command::Execute {
                tenant: "acme".into(),
                name: "counter".into(),
                function: "add".into(),
                args: vec![],
                gas: 1,
            },
            Command::Remove {
                tenant: "acme".into(),
                name: "missing".into(),
            },
        ];
        for command in rejected {
            let shown = format!("{command:?}");
            assert!(
                matches!(state.apply(command), Output::Rejected(_)),
                "should be rejected: {}",
                &shown[..shown.len().min(100)]
            );
        }
        assert_eq!(state.digest(), before);
    }

    #[test]
    fn gas_requests_are_clamped() {
        let mut state = State::default();
        state.apply(Command::DeployZel {
            tenant: "acme".into(),
            name: "spin".into(),
            source: "fn f() { while 1 { } return 0; }".into(),
            memory_bytes: 64,
        });
        let out = state.apply(Command::Execute {
            tenant: "acme".into(),
            name: "spin".into(),
            function: "f".into(),
            args: vec![],
            gas: u64::MAX,
        });
        match out {
            Output::Executed { result, gas_used } => {
                assert!(result.unwrap_err().contains("gas"));
                assert!(gas_used <= MAX_EXEC_GAS);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn corrupt_snapshots_are_refused() {
        assert!(State::decode(&[0xFF; 16]).is_err());
    }
}
