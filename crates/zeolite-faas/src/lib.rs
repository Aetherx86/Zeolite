//! Multi-tenant WebAssembly function engine.
//!
//! Tenants upload core Wasm modules that run in a fresh instance for every request, so no
//! state leaks between invocations or tenants. Each request has a hard budget of fuel
//! (metered instructions), linear memory, wall-clock time and output.
//!
//! # Function ABI
//!
//! A module exports:
//!
//! - `memory`: its linear memory
//! - `alloc(len: i32) -> i32`: reserves a buffer the host copies the input into
//! - `handle(ptr: i32, len: i32) -> i64`: processes the input and returns
//!   `(output_ptr << 32) | output_len`
//!
//! The only import a module may use is `zeolite.log(ptr: i32, len: i32)`. No filesystem,
//! network or clock is reachable, because nothing else is linked.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use wasmtime::{
    Caller, Config, Engine, Extern, ExternType, InstancePre, Linker, Module, Store, StoreLimits,
    StoreLimitsBuilder, Trap, Val, ValType,
};

const EPOCH_TICK: Duration = Duration::from_millis(5);

/// Per-invocation resource budget.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub fuel: u64,
    pub max_memory_bytes: usize,
    pub wall_clock: Duration,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_log_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            fuel: 100_000_000,
            max_memory_bytes: 64 << 20,
            wall_clock: Duration::from_secs(5),
            max_input_bytes: 8 << 20,
            max_output_bytes: 8 << 20,
            max_log_bytes: 64 << 10,
        }
    }
}

#[derive(Debug)]
pub enum DeployError {
    /// The bytes are not a valid Wasm module.
    Invalid(String),
    /// The module is valid but does not follow the function ABI.
    Abi(String),
}

impl fmt::Display for DeployError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeployError::Invalid(m) => write!(f, "invalid module: {m}"),
            DeployError::Abi(m) => write!(f, "module does not follow the function ABI: {m}"),
        }
    }
}

impl std::error::Error for DeployError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvokeError {
    OutOfFuel,
    TimedOut,
    InputTooLarge,
    OutputTooLarge,
    /// The guest trapped, for example on an out-of-bounds access or `unreachable`.
    Trap(String),
    /// The guest returned something the ABI does not allow.
    Abi(String),
}

impl fmt::Display for InvokeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvokeError::OutOfFuel => write!(f, "fuel budget exhausted"),
            InvokeError::TimedOut => write!(f, "wall-clock limit exceeded"),
            InvokeError::InputTooLarge => write!(f, "input exceeds the limit"),
            InvokeError::OutputTooLarge => write!(f, "output exceeds the limit"),
            InvokeError::Trap(m) => write!(f, "guest trapped: {m}"),
            InvokeError::Abi(m) => write!(f, "guest violated the function ABI: {m}"),
        }
    }
}

impl std::error::Error for InvokeError {}

#[derive(Clone, Debug)]
pub struct InvokeOutcome {
    pub result: Result<Vec<u8>, InvokeError>,
    /// Fuel consumed, which approximates the number of instructions executed.
    pub fuel_used: u64,
    pub logs: Vec<u8>,
    pub elapsed: Duration,
    /// Time spent creating the instance, which is the cold-start cost of a request.
    pub instantiate: Duration,
}

struct HostState {
    limits: StoreLimits,
    logs: Vec<u8>,
    max_log: usize,
}

/// A validated, compiled function, ready to be instantiated cheaply for each request.
pub struct Function {
    pre: InstancePre<HostState>,
}

impl fmt::Debug for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Function").finish_non_exhaustive()
    }
}

struct Ticker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Ticker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}

/// Compiles and runs functions. Cheap to share between threads.
pub struct Runtime {
    engine: Engine,
    linker: Linker<HostState>,
    _ticker: Ticker,
}

fn config() -> Result<Config, String> {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    // Threads would let a guest outlive its budget. They are unavailable here because this
    // crate does not enable wasmtime's `threads` feature, and a test proves they are refused.
    Ok(config)
}

impl Runtime {
    pub fn new() -> Result<Runtime, String> {
        let engine = Engine::new(&config()?).map_err(|e| e.to_string())?;
        let mut linker = Linker::new(&engine);
        linker
            .func_wrap(
                "zeolite",
                "log",
                |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                    let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
                        return;
                    };
                    let (data, state) = memory.data_and_store_mut(&mut caller);
                    let start = ptr as u32 as usize;
                    let len = len as u32 as usize;
                    let Some(bytes) = start.checked_add(len).and_then(|end| data.get(start..end))
                    else {
                        return;
                    };
                    let room = state.max_log.saturating_sub(state.logs.len());
                    state.logs.extend_from_slice(&bytes[..len.min(room)]);
                },
            )
            .map_err(|e| e.to_string())?;

        // The epoch clock is what lets a wall-clock limit stop a guest in a tight loop.
        let stop = Arc::new(AtomicBool::new(false));
        let ticker_engine = engine.clone();
        let ticker_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("zeolite-epoch".into())
            .spawn(move || {
                while !ticker_stop.load(Ordering::Relaxed) {
                    std::thread::park_timeout(EPOCH_TICK);
                    ticker_engine.increment_epoch();
                }
            })
            .map_err(|e| e.to_string())?;

        Ok(Runtime {
            engine,
            linker,
            _ticker: Ticker {
                stop,
                thread: Some(thread),
            },
        })
    }

    /// Validates and compiles a module, and checks that it follows the function ABI.
    pub fn deploy(&self, wasm: &[u8]) -> Result<Function, DeployError> {
        let module =
            Module::new(&self.engine, wasm).map_err(|e| DeployError::Invalid(format!("{e:#}")))?;
        check_abi(&module)?;
        let pre = self
            .linker
            .instantiate_pre(&module)
            .map_err(|e| DeployError::Abi(format!("{e:#}")))?;
        Ok(Function { pre })
    }

    /// Runs one request in a brand new instance.
    pub fn invoke(&self, function: &Function, input: &[u8], limits: &Limits) -> InvokeOutcome {
        let started = Instant::now();
        let state = HostState {
            limits: StoreLimitsBuilder::new()
                .memory_size(limits.max_memory_bytes)
                .memories(1)
                .tables(4)
                .instances(1)
                .trap_on_grow_failure(false)
                .build(),
            logs: Vec::new(),
            max_log: limits.max_log_bytes,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        let finish = |store: Store<HostState>,
                      result: Result<Vec<u8>, InvokeError>,
                      instantiate: Duration| {
            let fuel_used = limits.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
            InvokeOutcome {
                result,
                fuel_used,
                logs: store.into_data().logs,
                elapsed: started.elapsed(),
                instantiate,
            }
        };

        // The budget goes in first, so that early exits report zero fuel used.
        if store.set_fuel(limits.fuel).is_err() {
            return finish(
                store,
                Err(InvokeError::Trap("failed to set the fuel budget".into())),
                Duration::ZERO,
            );
        }
        if input.len() > limits.max_input_bytes {
            return finish(store, Err(InvokeError::InputTooLarge), Duration::ZERO);
        }
        let ticks = (limits.wall_clock.as_millis() / EPOCH_TICK.as_millis()).max(1) as u64 + 1;
        store.set_epoch_deadline(ticks);

        let instance = match function.pre.instantiate(&mut store) {
            Ok(instance) => instance,
            Err(e) => {
                let elapsed = started.elapsed();
                return finish(store, Err(classify(&e)), elapsed);
            }
        };
        let instantiate = started.elapsed();
        let result = call_handler(&mut store, &instance, input, limits);
        finish(store, result, instantiate)
    }
}

fn check_abi(module: &Module) -> Result<(), DeployError> {
    let export = |name: &str| {
        module
            .get_export(name)
            .ok_or_else(|| DeployError::Abi(format!("missing export `{name}`")))
    };
    if !matches!(export("memory")?, ExternType::Memory(_)) {
        return Err(DeployError::Abi("`memory` is not a memory".into()));
    }
    let check_func =
        |name: &str, params: &[ValKind], results: &[ValKind]| -> Result<(), DeployError> {
            let ExternType::Func(func) = export(name)? else {
                return Err(DeployError::Abi(format!("`{name}` is not a function")));
            };
            let got_params: Vec<Option<ValKind>> = func.params().map(|t| ValKind::of(&t)).collect();
            let got_results: Vec<Option<ValKind>> =
                func.results().map(|t| ValKind::of(&t)).collect();
            let want_params: Vec<Option<ValKind>> = params.iter().copied().map(Some).collect();
            let want_results: Vec<Option<ValKind>> = results.iter().copied().map(Some).collect();
            if got_params != want_params || got_results != want_results {
                return Err(DeployError::Abi(format!(
                    "`{name}` must have the signature {params:?} -> {results:?}"
                )));
            }
            Ok(())
        };
    check_func("alloc", &[ValKind::I32], &[ValKind::I32])?;
    check_func("handle", &[ValKind::I32, ValKind::I32], &[ValKind::I64])?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValKind {
    I32,
    I64,
}

impl ValKind {
    fn of(t: &ValType) -> Option<ValKind> {
        match t {
            ValType::I32 => Some(ValKind::I32),
            ValType::I64 => Some(ValKind::I64),
            _ => None,
        }
    }
}

fn classify(error: &wasmtime::Error) -> InvokeError {
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => InvokeError::OutOfFuel,
        Some(Trap::Interrupt) => InvokeError::TimedOut,
        _ => InvokeError::Trap(format!("{error:#}")),
    }
}

fn call_handler(
    store: &mut Store<HostState>,
    instance: &wasmtime::Instance,
    input: &[u8],
    limits: &Limits,
) -> Result<Vec<u8>, InvokeError> {
    let missing = |name: &str| InvokeError::Abi(format!("missing export `{name}`"));
    let memory = instance
        .get_memory(&mut *store, "memory")
        .ok_or_else(|| missing("memory"))?;
    let alloc = instance
        .get_func(&mut *store, "alloc")
        .ok_or_else(|| missing("alloc"))?;
    let handle = instance
        .get_func(&mut *store, "handle")
        .ok_or_else(|| missing("handle"))?;

    let mut out = [Val::I32(0)];
    alloc
        .call(&mut *store, &[Val::I32(input.len() as i32)], &mut out)
        .map_err(|e| classify(&e))?;
    let ptr = out[0]
        .i32()
        .ok_or_else(|| InvokeError::Abi("`alloc` did not return i32".into()))?;

    memory
        .write(&mut *store, ptr as u32 as usize, input)
        .map_err(|_| InvokeError::Abi("`alloc` returned a buffer outside of memory".into()))?;

    let mut out = [Val::I64(0)];
    handle
        .call(
            &mut *store,
            &[Val::I32(ptr), Val::I32(input.len() as i32)],
            &mut out,
        )
        .map_err(|e| classify(&e))?;
    let packed = out[0]
        .i64()
        .ok_or_else(|| InvokeError::Abi("`handle` did not return i64".into()))?
        as u64;
    let out_ptr = (packed >> 32) as usize;
    let out_len = (packed & 0xFFFF_FFFF) as usize;
    if out_len > limits.max_output_bytes {
        return Err(InvokeError::OutputTooLarge);
    }
    let data = memory.data(&*store);
    let bytes = out_ptr
        .checked_add(out_len)
        .and_then(|end| data.get(out_ptr..end))
        .ok_or_else(|| InvokeError::Abi("`handle` returned a range outside of memory".into()))?;
    Ok(bytes.to_vec())
}
