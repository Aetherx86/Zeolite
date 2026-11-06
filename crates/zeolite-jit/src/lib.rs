//! Deterministic, metered execution of Zel programs.
//!
//! A [`Module`] holds a program compiled for two interchangeable backends: a reference
//! interpreter and a Cranelift JIT. Both produce the same result, the same gas count and
//! the same memory contents for every input, including inputs that trap. That property
//! is what lets replicas of a consensus group execute a command independently and still
//! arrive at the same state, whichever backend each one runs.
//!
//! Arithmetic wraps. There are no floats, clocks or randomness in the language, so
//! results do not depend on the host.

mod interp;
pub mod ir;
mod jit;
pub mod syntax;

pub use crate::syntax::CompileError;
use std::fmt;

/// Smallest usable linear memory, which is one 8-byte word.
pub const MIN_MEMORY_BYTES: usize = 8;

/// Default stack budget. The calling thread needs at least this much native stack free,
/// with headroom, for JIT execution.
pub const DEFAULT_STACK_BUDGET: u64 = 256 << 10;

/// Largest accepted budget, which keeps guests well inside a normal 2 MiB worker stack.
pub const MAX_STACK_BUDGET: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub gas: u64,
    pub stack_budget: u64,
}

impl Limits {
    pub fn with_gas(gas: u64) -> Self {
        Limits {
            gas,
            stack_budget: DEFAULT_STACK_BUDGET,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Trap {
    OutOfGas,
    MemoryOutOfBounds,
    DivideByZero,
    IntegerOverflow,
    StackOverflow,
}

impl fmt::Display for Trap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Trap::OutOfGas => "out of gas",
            Trap::MemoryOutOfBounds => "memory access out of bounds",
            Trap::DivideByZero => "division by zero",
            Trap::IntegerOverflow => "integer overflow",
            Trap::StackOverflow => "stack budget exceeded",
        })
    }
}

impl std::error::Error for Trap {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub result: Result<i64, Trap>,
    pub gas_used: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError {
    UnknownFunction(String),
    WrongArgumentCount { expected: u32, supplied: usize },
    MemoryTooSmall,
    StackBudgetTooLarge,
    BackendUnavailable,
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallError::UnknownFunction(name) => write!(f, "no function named `{name}`"),
            CallError::WrongArgumentCount { expected, supplied } => {
                write!(f, "expected {expected} arguments, got {supplied}")
            }
            CallError::MemoryTooSmall => {
                write!(
                    f,
                    "linear memory must hold at least {MIN_MEMORY_BYTES} bytes"
                )
            }
            CallError::StackBudgetTooLarge => {
                write!(f, "stack budget exceeds {MAX_STACK_BUDGET} bytes")
            }
            CallError::BackendUnavailable => write!(f, "this module has no JIT code"),
        }
    }
}

impl std::error::Error for CallError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Interpreter,
    Jit,
}

pub struct Module {
    program: ir::Program,
    jit: Option<jit::JitCode>,
}

impl fmt::Debug for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Module")
            .field("functions", &self.program.functions.len())
            .field("jit", &self.jit.is_some())
            .finish()
    }
}

impl Module {
    /// Parses and lowers `source`, then generates native code for it.
    pub fn compile(source: &str) -> Result<Module, CompileError> {
        let program = ir::lower(&syntax::parse(source)?)?;
        let jit = jit::JitCode::compile(&program)?;
        Ok(Module {
            program,
            jit: Some(jit),
        })
    }

    /// Parses and lowers `source` for the interpreter only. No executable memory is
    /// allocated, which suits hosts that forbid it.
    pub fn compile_interpreted(source: &str) -> Result<Module, CompileError> {
        Ok(Module {
            program: ir::lower(&syntax::parse(source)?)?,
            jit: None,
        })
    }

    pub fn program(&self) -> &ir::Program {
        &self.program
    }

    pub fn has_jit(&self) -> bool {
        self.jit.is_some()
    }

    pub fn function_names(&self) -> impl Iterator<Item = &str> {
        self.program.exports.keys().map(String::as_str)
    }

    /// Runs one exported function against `memory`, which the guest may mutate.
    pub fn call(
        &self,
        backend: Backend,
        function: &str,
        args: &[i64],
        memory: &mut [u8],
        limits: Limits,
    ) -> Result<Outcome, CallError> {
        let entry = *self
            .program
            .exports
            .get(function)
            .ok_or_else(|| CallError::UnknownFunction(function.to_string()))?;
        let expected = self.program.functions[entry as usize].n_params;
        if args.len() != expected as usize {
            return Err(CallError::WrongArgumentCount {
                expected,
                supplied: args.len(),
            });
        }
        if memory.len() < MIN_MEMORY_BYTES {
            return Err(CallError::MemoryTooSmall);
        }
        if limits.stack_budget > MAX_STACK_BUDGET {
            return Err(CallError::StackBudgetTooLarge);
        }
        match backend {
            Backend::Interpreter => Ok(interp::run(&self.program, entry, args, memory, limits)),
            Backend::Jit => {
                let code = self.jit.as_ref().ok_or(CallError::BackendUnavailable)?;
                Ok(code.run(entry, args, memory, limits))
            }
        }
    }
}
