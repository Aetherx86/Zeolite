//! Differential testing: the interpreter and the JIT must agree on the result, the gas
//! count and the final memory for randomly generated programs.
//!
//! Replicated execution depends on this. A disagreement here would fork replica state.

use std::collections::HashMap;
use zeolite_jit::{Backend, Limits, Module, Trap};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

struct Gen {
    rng: Rng,
    vars: Vec<String>,
    /// Name and arity of every function that may be called.
    functions: Vec<(String, usize)>,
    next_var: u32,
    in_loop: bool,
    budget: i32,
}

const BIN_OPS: &[&str] = &[
    "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>", "==", "!=", "<", "<=", ">", ">=",
    "&&", "||",
];

const INTERESTING: &[i64] = &[
    0,
    1,
    -1,
    2,
    7,
    8,
    63,
    64,
    255,
    256,
    1000,
    4088,
    4095,
    4096,
    i64::MAX,
    i64::MIN,
    i64::MIN + 1,
];

impl Gen {
    fn literal(&mut self) -> String {
        let value = if self.rng.below(4) == 0 {
            self.rng.next() as i64
        } else {
            INTERESTING[self.rng.below(INTERESTING.len() as u64) as usize]
        };
        if value < 0 {
            // Spelled as a bit pattern so that every value has a literal form.
            format!("0x{:X}", value as u64)
        } else {
            value.to_string()
        }
    }

    fn expr(&mut self, depth: u32) -> String {
        self.budget -= 1;
        if depth == 0 || self.budget <= 0 {
            if !self.vars.is_empty() && self.rng.below(2) == 0 {
                let i = self.rng.below(self.vars.len() as u64) as usize;
                return self.vars[i].clone();
            }
            return self.literal();
        }
        match self.rng.below(12) {
            0..=5 => {
                let op = BIN_OPS[self.rng.below(BIN_OPS.len() as u64) as usize];
                let a = self.expr(depth - 1);
                let b = self.expr(depth - 1);
                format!("({a} {op} {b})")
            }
            6 => {
                let op = ["-", "!", "~"][self.rng.below(3) as usize];
                let a = self.expr(depth - 1);
                format!("({op}{a})")
            }
            7 => format!("load(({}) & 4095)", self.expr(depth - 1)),
            8 => format!("load8(({}) & 8191)", self.expr(depth - 1)),
            9 => "mem_size()".to_string(),
            10 if !self.functions.is_empty() => {
                let i = self.rng.below(self.functions.len() as u64) as usize;
                let (name, arity) = self.functions[i].clone();
                let args: Vec<String> = (0..arity).map(|_| self.expr(depth - 1)).collect();
                format!("{name}({})", args.join(", "))
            }
            _ => self.literal(),
        }
    }

    fn block(&mut self, depth: u32, out: &mut String) {
        let saved = self.vars.len();
        let count = 1 + self.rng.below(5);
        for _ in 0..count {
            self.stmt(depth, out);
        }
        self.vars.truncate(saved);
    }

    fn stmt(&mut self, depth: u32, out: &mut String) {
        self.budget -= 1;
        let choice = if depth == 0 || self.budget <= 0 {
            self.rng.below(4)
        } else {
            self.rng.below(9)
        };
        match choice {
            0 | 1 => {
                let value = self.expr(3);
                let name = format!("v{}", self.next_var);
                self.next_var += 1;
                out.push_str(&format!("let {name} = {value};\n"));
                self.vars.push(name);
            }
            2 if !self.vars.is_empty() => {
                let i = self.rng.below(self.vars.len() as u64) as usize;
                let name = self.vars[i].clone();
                let value = self.expr(3);
                out.push_str(&format!("{name} = {value};\n"));
            }
            3 => {
                let addr = self.expr(2);
                let value = self.expr(2);
                // Some addresses stray out of bounds on purpose.
                let (call, mask) = match self.rng.below(3) {
                    0 => ("store", "4095"),
                    1 => ("store8", "8191"),
                    _ => ("store", "4088"),
                };
                out.push_str(&format!("{call}(({addr}) & {mask}, {value});\n"));
            }
            4 | 5 => {
                let cond = self.expr(2);
                out.push_str(&format!("if {cond} {{\n"));
                self.block(depth - 1, out);
                if self.rng.below(2) == 0 {
                    out.push_str("} else {\n");
                    self.block(depth - 1, out);
                }
                out.push_str("}\n");
            }
            6 => {
                let name = format!("i{}", self.next_var);
                self.next_var += 1;
                let bound = self.rng.below(12);
                out.push_str(&format!("let {name} = 0;\nwhile {name} < {bound} {{\n"));
                out.push_str(&format!("{name} = {name} + 1;\n"));
                self.vars.push(name.clone());
                let was_in_loop = self.in_loop;
                self.in_loop = true;
                self.block(depth - 1, out);
                self.in_loop = was_in_loop;
                self.vars.retain(|v| v != &name);
                out.push_str("}\n");
            }
            7 if self.in_loop => {
                let cond = self.expr(1);
                let word = if self.rng.below(2) == 0 {
                    "break"
                } else {
                    "continue"
                };
                out.push_str(&format!("if {cond} {{ {word}; }}\n"));
            }
            _ => {
                let value = self.expr(2);
                out.push_str(&format!("if {} {{ return {value}; }}\n", self.expr(1)));
            }
        }
    }

    fn program(&mut self) -> (String, Vec<(String, usize)>) {
        let mut src = String::new();
        let count = 1 + self.rng.below(5);
        let mut all = Vec::new();
        for f in 0..count {
            let arity = self.rng.below(5) as usize;
            let name = format!("f{f}");
            // Later functions call earlier ones and, sometimes, themselves.
            let recursive = self.rng.below(4) == 0;
            self.functions = all.clone();
            if recursive {
                self.functions.push((name.clone(), arity));
            }
            let params: Vec<String> = (0..arity).map(|i| format!("p{i}")).collect();
            self.vars = params.clone();
            self.in_loop = false;
            self.budget = 60;
            src.push_str(&format!("fn {name}({}) {{\n", params.join(", ")));
            let mut body = String::new();
            self.block(4, &mut body);
            src.push_str(&body);
            let result = self.expr(3);
            src.push_str(&format!("return {result};\n}}\n"));
            all.push((name, arity));
        }
        (src, all)
    }
}

#[test]
fn backends_agree_on_random_programs() {
    let mut outcomes: HashMap<Option<Trap>, u32> = HashMap::new();
    let mut total_gas = 0u64;
    let seeds = 400u64;
    for seed in 1..=seeds {
        let mut generator = Gen {
            rng: Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
            vars: Vec::new(),
            functions: Vec::new(),
            next_var: 0,
            in_loop: false,
            budget: 0,
        };
        let (src, functions) = generator.program();
        let module = Module::compile(&src).unwrap_or_else(|e| {
            panic!("seed {seed}: generated program failed to compile: {e}\n{src}")
        });

        for (name, arity) in &functions {
            for _ in 0..4 {
                let args: Vec<i64> = (0..*arity)
                    .map(|_| {
                        if generator.rng.below(2) == 0 {
                            INTERESTING[generator.rng.below(INTERESTING.len() as u64) as usize]
                        } else {
                            generator.rng.next() as i64
                        }
                    })
                    .collect();
                // A random gas limit exercises out-of-gas at many different points.
                let gas = match generator.rng.below(3) {
                    0 => generator.rng.below(64),
                    1 => generator.rng.below(4096),
                    _ => 200_000,
                };
                let limits = Limits::with_gas(gas);

                let mut seed_mem = vec![0u8; 4096];
                for (i, byte) in seed_mem.iter_mut().enumerate() {
                    *byte = (i as u64).wrapping_mul(seed) as u8;
                }
                let mut interp_mem = seed_mem.clone();
                let mut jit_mem = seed_mem;
                let a = module
                    .call(Backend::Interpreter, name, &args, &mut interp_mem, limits)
                    .unwrap();
                let b = module
                    .call(Backend::Jit, name, &args, &mut jit_mem, limits)
                    .unwrap();
                assert_eq!(
                    a, b,
                    "seed {seed}: backends disagree on {name}{args:?} with gas {gas}\n{src}"
                );
                assert!(
                    interp_mem == jit_mem,
                    "seed {seed}: memory differs after {name}{args:?} with gas {gas}\n{src}"
                );
                *outcomes.entry(a.result.err()).or_default() += 1;
                total_gas += a.gas_used;
            }
        }
    }

    // A generator that stopped producing variety would leave this test passing while
    // proving nothing, so each outcome class has to actually occur.
    for key in [
        None,
        Some(Trap::OutOfGas),
        Some(Trap::MemoryOutOfBounds),
        Some(Trap::DivideByZero),
    ] {
        let count = outcomes.get(&key).copied().unwrap_or(0);
        assert!(
            count >= 20,
            "outcome {key:?} occurred only {count} times: {outcomes:?}"
        );
    }
    assert!(
        total_gas > 100_000,
        "programs did too little work: {total_gas}"
    );
}

#[test]
fn backends_agree_on_overflow_and_recursion_traps() {
    let src = "
        fn div(a, b) { return a / b; }
        fn rec(n) { store(0, n); return rec(n + 1) + 1; }
    ";
    let module = Module::compile(src).unwrap();
    let limits = Limits::with_gas(50_000_000);
    let mut a_mem = vec![0u8; 64];
    let mut b_mem = vec![0u8; 64];
    let a = module
        .call(
            Backend::Interpreter,
            "div",
            &[i64::MIN, -1],
            &mut a_mem,
            limits,
        )
        .unwrap();
    let b = module
        .call(Backend::Jit, "div", &[i64::MIN, -1], &mut b_mem, limits)
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(a.result, Err(Trap::IntegerOverflow));

    let a = module
        .call(Backend::Interpreter, "rec", &[0], &mut a_mem, limits)
        .unwrap();
    let b = module
        .call(Backend::Jit, "rec", &[0], &mut b_mem, limits)
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(a.result, Err(Trap::StackOverflow));
    assert_eq!(a_mem, b_mem, "the depth at which the trap fired must match");
}
