//! Language and sandbox behavior, checked on both backends.

use zeolite_jit::{Backend, CallError, Limits, Module, Trap};

const BACKENDS: [Backend; 2] = [Backend::Interpreter, Backend::Jit];

fn run(src: &str, func: &str, args: &[i64]) -> Result<i64, Trap> {
    let module = Module::compile(src).unwrap();
    let mut results = Vec::new();
    for backend in BACKENDS {
        let mut memory = vec![0u8; 4096];
        let out = module
            .call(
                backend,
                func,
                args,
                &mut memory,
                Limits::with_gas(10_000_000),
            )
            .unwrap();
        results.push(out);
    }
    assert_eq!(
        results[0], results[1],
        "backends disagree on {func}{args:?}"
    );
    results[0].result
}

#[test]
fn arithmetic_wraps_and_respects_precedence() {
    let src = "fn f(a, b) { return a + b * 2 - 1; }
               fn w() { return 0x7FFFFFFFFFFFFFFF + 1; }
               fn s() { return (1 << 65) + (-8 >> 1) + (-8 >>> 60); }";
    assert_eq!(run(src, "f", &[3, 4]), Ok(10));
    assert_eq!(run(src, "w", &[]), Ok(i64::MIN));
    assert_eq!(run(src, "s", &[]), Ok(2 - 4 + 15));
}

#[test]
fn control_flow_and_recursion_compute_correctly() {
    let src = "
        fn fib(n) { if n < 2 { return n; } return fib(n - 1) + fib(n - 2); }
        fn sum_odds(n) {
            let total = 0;
            let i = 0;
            while 1 {
                i = i + 1;
                if i > n { break; }
                if i % 2 == 0 { continue; }
                total = total + i;
            }
            return total;
        }
        fn classify(x) {
            if x < 0 { return 0 - 1; } else if x == 0 { return 0; } else { return 1; }
        }
    ";
    assert_eq!(run(src, "fib", &[20]), Ok(6765));
    assert_eq!(run(src, "sum_odds", &[10]), Ok(25));
    assert_eq!(run(src, "classify", &[-5]), Ok(-1));
    assert_eq!(run(src, "classify", &[0]), Ok(0));
    assert_eq!(run(src, "classify", &[9]), Ok(1));
}

#[test]
fn logical_operators_short_circuit_and_normalize() {
    let src = "
        fn boom() { return 1 / 0; }
        fn and_skips() { return 0 && boom(); }
        fn or_skips() { return 7 || boom(); }
        fn and_runs() { return 3 && 9; }
        fn or_runs() { return 0 || 4; }
        fn and_traps() { return 1 && boom(); }
    ";
    assert_eq!(run(src, "and_skips", &[]), Ok(0));
    assert_eq!(run(src, "or_skips", &[]), Ok(1));
    assert_eq!(run(src, "and_runs", &[]), Ok(1));
    assert_eq!(run(src, "or_runs", &[]), Ok(1));
    assert_eq!(run(src, "and_traps", &[]), Err(Trap::DivideByZero));
}

#[test]
fn division_edge_cases_trap_instead_of_faulting() {
    let src = "
        fn d(a, b) { return a / b; }
        fn r(a, b) { return a % b; }
    ";
    assert_eq!(run(src, "d", &[7, 0]), Err(Trap::DivideByZero));
    assert_eq!(run(src, "r", &[7, 0]), Err(Trap::DivideByZero));
    // These two inputs raise a hardware exception if the backend lets them through.
    assert_eq!(run(src, "d", &[i64::MIN, -1]), Err(Trap::IntegerOverflow));
    assert_eq!(run(src, "r", &[i64::MIN, -1]), Ok(0));
    assert_eq!(run(src, "d", &[-7, 2]), Ok(-3));
    assert_eq!(run(src, "r", &[-7, 2]), Ok(-1));
}

#[test]
fn every_out_of_bounds_access_traps_at_the_exact_edge() {
    let src = "
        fn l64(a) { return load(a); }
        fn l8(a) { return load8(a); }
        fn s64(a) { store(a, 1); return 0; }
        fn s8(a) { store8(a, 1); return 0; }
        fn size() { return mem_size(); }
    ";
    let module = Module::compile(src).unwrap();
    for backend in BACKENDS {
        let mut memory = vec![0u8; 64];
        let mut call = |f: &str, a: i64| {
            module
                .call(backend, f, &[a], &mut memory, Limits::with_gas(1000))
                .unwrap()
                .result
        };
        assert_eq!(call("l64", 56), Ok(0), "last valid word");
        assert_eq!(call("l64", 57), Err(Trap::MemoryOutOfBounds));
        assert_eq!(call("s64", 56), Ok(0));
        assert_eq!(call("s64", 57), Err(Trap::MemoryOutOfBounds));
        assert_eq!(call("l8", 63), Ok(0), "last valid byte");
        assert_eq!(call("l8", 64), Err(Trap::MemoryOutOfBounds));
        assert_eq!(call("s8", 63), Ok(0));
        assert_eq!(call("s8", 64), Err(Trap::MemoryOutOfBounds));
        // Negative addresses and values near the top of the address space must not wrap
        // around the bounds check and reach host memory.
        for hostile in [-1, -8, i64::MIN, i64::MAX, i64::MAX - 6] {
            assert_eq!(
                call("l64", hostile),
                Err(Trap::MemoryOutOfBounds),
                "{hostile}"
            );
            assert_eq!(
                call("s64", hostile),
                Err(Trap::MemoryOutOfBounds),
                "{hostile}"
            );
            assert_eq!(
                call("l8", hostile),
                Err(Trap::MemoryOutOfBounds),
                "{hostile}"
            );
            assert_eq!(
                call("s8", hostile),
                Err(Trap::MemoryOutOfBounds),
                "{hostile}"
            );
        }
        let size = module
            .call(backend, "size", &[], &mut memory, Limits::with_gas(1000))
            .unwrap();
        assert_eq!(size.result, Ok(64));
    }
}

#[test]
fn memory_round_trips_little_endian_and_unaligned() {
    let src = "
        fn put(a, v) { store(a, v); return 0; }
        fn get(a) { return load(a); }
        fn byte(a) { return load8(a); }
    ";
    let module = Module::compile(src).unwrap();
    for backend in BACKENDS {
        let mut memory = vec![0u8; 64];
        let limits = Limits::with_gas(1000);
        module
            .call(
                backend,
                "put",
                &[3, 0x0102_0304_0506_0708],
                &mut memory,
                limits,
            )
            .unwrap();
        assert_eq!(memory[3..11], [8, 7, 6, 5, 4, 3, 2, 1]);
        let got = module
            .call(backend, "get", &[3], &mut memory, limits)
            .unwrap();
        assert_eq!(got.result, Ok(0x0102_0304_0506_0708));
        let got = module
            .call(backend, "byte", &[3], &mut memory, limits)
            .unwrap();
        assert_eq!(got.result, Ok(8), "load8 zero-extends");
    }
}

#[test]
fn infinite_loops_run_out_of_gas() {
    let module = Module::compile("fn spin() { while 1 { } return 0; }").unwrap();
    for backend in BACKENDS {
        let mut memory = vec![0u8; 16];
        let out = module
            .call(backend, "spin", &[], &mut memory, Limits::with_gas(100_000))
            .unwrap();
        assert_eq!(out.result, Err(Trap::OutOfGas));
        assert!(out.gas_used <= 100_000);
    }
}

#[test]
fn a_loop_of_empty_blocks_still_consumes_gas() {
    // The loop condition reads a variable, which needs no instruction, and the body is
    // empty. Metering must still make this cycle cost something or it never terminates.
    let module = Module::compile("fn spin(x) { while x { } return 0; }").unwrap();
    for backend in BACKENDS {
        let mut memory = vec![0u8; 16];
        let out = module
            .call(backend, "spin", &[1], &mut memory, Limits::with_gas(10_000))
            .unwrap();
        assert_eq!(out.result, Err(Trap::OutOfGas));
    }
}

/// Exact gas values are part of the replicated state machine's contract: nodes running
/// different builds must charge the same amounts or their state forks. This test exists
/// so that a change to the cost model has to be made deliberately.
#[test]
fn gas_costs_are_pinned() {
    let cases: [(&str, &str, &[i64], u64); 3] = [
        ("fn f() { return 1; }", "f", &[], 2),
        (
            "fn f(n) { let i = 0; while i < n { i = i + 1; } return i; }",
            "f",
            &[3],
            31,
        ),
        ("fn g() { return 1; } fn f() { return g(); }", "f", &[], 4),
    ];
    for (src, func, args, expected) in cases {
        let module = Module::compile(src).unwrap();
        for backend in BACKENDS {
            let mut memory = vec![0u8; 16];
            let out = module
                .call(backend, func, args, &mut memory, Limits::with_gas(10_000))
                .unwrap();
            assert_eq!(out.gas_used, expected, "{src}");
        }
    }
}

#[test]
fn zero_gas_traps_before_any_work() {
    let module = Module::compile("fn f() { store(0, 1); return 1; }").unwrap();
    for backend in BACKENDS {
        let mut memory = vec![0u8; 16];
        let out = module
            .call(backend, "f", &[], &mut memory, Limits::with_gas(0))
            .unwrap();
        assert_eq!(out.result, Err(Trap::OutOfGas));
        assert_eq!(out.gas_used, 0);
        assert_eq!(
            memory,
            vec![0u8; 16],
            "no side effect may precede the charge"
        );
    }
}

#[test]
fn unbounded_recursion_traps_without_crashing_the_host() {
    let src = "
        fn down(n) { return down(n + 1) + 1; }
        fn mutual_a(n) { return mutual_b(n); }
        fn mutual_b(n) { return mutual_a(n); }
    ";
    assert_eq!(run(src, "down", &[0]), Err(Trap::StackOverflow));
    assert_eq!(run(src, "mutual_a", &[0]), Err(Trap::StackOverflow));
}

#[test]
fn a_huge_frame_is_charged_for_its_size() {
    // Many live registers per frame have to exhaust the budget proportionally sooner.
    let mut src = String::from("fn big(n) {\n");
    for i in 0..2000 {
        src.push_str(&format!("let v{i} = n + {i};\n"));
    }
    src.push_str("return big(n + 1) + v0 + v1999;\n}\nfn small(n) { return small(n + 1) + 1; }\n");
    let module = Module::compile(&src).unwrap();
    for backend in BACKENDS {
        let mut memory = vec![0u8; 16];
        let limits = Limits::with_gas(100_000_000);
        let big = module
            .call(backend, "big", &[0], &mut memory, limits)
            .unwrap();
        let small = module
            .call(backend, "small", &[0], &mut memory, limits)
            .unwrap();
        assert_eq!(big.result, Err(Trap::StackOverflow));
        assert_eq!(small.result, Err(Trap::StackOverflow));
        assert!(big.gas_used < small.gas_used * 50);
    }
}

#[test]
fn eight_parameters_pass_in_the_right_order() {
    let src = "fn f(a, b, c, d, e, g, h, i) {
        return a + b * 10 + c * 100 + d * 1000 + e * 10000 + g * 100000 + h * 1000000 + i * 10000000;
    }";
    assert_eq!(run(src, "f", &[1, 2, 3, 4, 5, 6, 7, 8]), Ok(87654321));
}

#[test]
fn variables_are_block_scoped_and_shadowing_is_correct() {
    let src = "fn f() {
        let x = 1;
        if 1 { let x = 2; x = x + 1; }
        return x;
    }";
    assert_eq!(run(src, "f", &[]), Ok(1));
}

#[test]
fn a_variable_operand_keeps_its_value_across_calls() {
    let src = "
        fn id(v) { return v; }
        fn f(x) { return x + id(x + 1); }
    ";
    assert_eq!(run(src, "f", &[10]), Ok(21));
}

#[test]
fn compile_errors_are_reported() {
    let cases = [
        ("fn f() { return y; }", "undeclared variable"),
        ("fn f() { y = 1; }", "undeclared variable"),
        ("fn f() { return g(); }", "undefined function"),
        (
            "fn g(a) { return a; } fn f() { return g(); }",
            "takes 1 arguments",
        ),
        ("fn f() { } fn f() { }", "defined twice"),
        ("fn f(a, a) { }", "declared twice"),
        ("fn f() { break; }", "outside of a loop"),
        ("fn f() { continue; }", "outside of a loop"),
        ("fn f(a,b,c,d,e,g,h,i,j) { }", "more than 8 parameters"),
        ("fn f() { return 1 }", "expected `;`"),
        ("fn f() { let let = 1; }", "reserved word"),
        (
            "fn f() { return 99999999999999999999999; }",
            "invalid integer",
        ),
        ("fn f() { return $; }", "unexpected character"),
        ("fn f() {", "end of input"),
    ];
    for (src, needle) in cases {
        let error = Module::compile(src).expect_err(src);
        assert!(
            error.message.contains(needle),
            "{src}: expected {needle:?}, got {:?}",
            error.message
        );
    }
}

#[test]
fn hostile_nesting_is_rejected_instead_of_overflowing_the_stack() {
    let deep_parens = format!(
        "fn f() {{ return {}1{}; }}",
        "(".repeat(100_000),
        ")".repeat(100_000)
    );
    assert!(
        Module::compile(&deep_parens)
            .unwrap_err()
            .message
            .contains("nesting")
    );

    let deep_unary = format!("fn f() {{ return {}1; }}", "-".repeat(100_000));
    assert!(
        Module::compile(&deep_unary)
            .unwrap_err()
            .message
            .contains("nesting")
    );

    let deep_blocks = format!(
        "fn f() {{ {}{} }}",
        "if 1 {".repeat(10_000),
        "}".repeat(10_000)
    );
    assert!(
        Module::compile(&deep_blocks)
            .unwrap_err()
            .message
            .contains("nesting")
    );

    // A flat operator chain parses in a loop, yet builds a tree as deep as it is long.
    let long_chain = format!("fn f() {{ return 1{}; }}", " + 1".repeat(200_000));
    assert!(
        Module::compile(&long_chain)
            .unwrap_err()
            .message
            .contains("too deep")
    );

    // Parentheses and a rising precedence staircase combined: the worst parser recursion.
    let staircase = "(1 || 1 && 1 | 1 ^ 1 & 1 == 1 < 1 << 1 + 1 * ".repeat(5000);
    let hostile = format!("fn f() {{ return {staircase}1{}; }}", ")".repeat(5000));
    assert!(
        Module::compile(&hostile)
            .unwrap_err()
            .message
            .contains("nesting")
    );

    let deep_calls = format!(
        "fn g(a) {{ return a; }} fn f() {{ return {}1{}; }}",
        "g(".repeat(50_000),
        ")".repeat(50_000)
    );
    assert!(
        Module::compile(&deep_calls)
            .unwrap_err()
            .message
            .contains("nesting")
    );

    let deep_loads = format!(
        "fn f() {{ return {}1{}; }}",
        "load(".repeat(50_000),
        ")".repeat(50_000)
    );
    assert!(
        Module::compile(&deep_loads)
            .unwrap_err()
            .message
            .contains("nesting")
    );

    let too_large = "/".repeat(zeolite_jit::syntax::MAX_SOURCE_BYTES + 1);
    assert!(
        Module::compile(&too_large)
            .unwrap_err()
            .message
            .contains("limit")
    );
}

#[test]
fn the_deepest_accepted_programs_still_compile_and_run() {
    // Sits right below the limits, so accepted input also has to be safe downstream.
    let chain = format!("fn f() {{ return 1{}; }}", " + 1".repeat(250));
    assert_eq!(run(&chain, "f", &[]), Ok(251));

    let parens = format!("fn f() {{ return {}7{}; }}", "(".repeat(55), ")".repeat(55));
    assert_eq!(run(&parens, "f", &[]), Ok(7));

    let staircase = "(1 || 1 && 1 | 1 ^ 1 & 1 == 1 < 1 << 1 + 1 * ".repeat(5);
    let tall = format!("fn f() {{ return {staircase}1{}; }}", ")".repeat(5));
    assert!(Module::compile(&tall).is_ok());

    let blocks = format!(
        "fn f() {{ {}return 3;{} }}",
        "if 1 {".repeat(30),
        "}".repeat(30)
    );
    assert_eq!(run(&blocks, "f", &[]), Ok(3));
}

#[test]
fn call_errors_are_reported_before_running() {
    let module = Module::compile("fn f(a) { return a; }").unwrap();
    let mut memory = vec![0u8; 16];
    let limits = Limits::with_gas(100);
    assert_eq!(
        module.call(Backend::Jit, "g", &[], &mut memory, limits),
        Err(CallError::UnknownFunction("g".into()))
    );
    assert_eq!(
        module.call(Backend::Jit, "f", &[], &mut memory, limits),
        Err(CallError::WrongArgumentCount {
            expected: 1,
            supplied: 0
        })
    );
    let mut tiny = vec![0u8; 4];
    assert_eq!(
        module.call(Backend::Jit, "f", &[1], &mut tiny, limits),
        Err(CallError::MemoryTooSmall)
    );
    let oversized = Limits {
        gas: 100,
        stack_budget: zeolite_jit::MAX_STACK_BUDGET + 1,
    };
    assert_eq!(
        module.call(Backend::Jit, "f", &[1], &mut memory, oversized),
        Err(CallError::StackBudgetTooLarge)
    );
    let interpreted = Module::compile_interpreted("fn f(a) { return a; }").unwrap();
    assert!(!interpreted.has_jit());
    assert_eq!(
        interpreted.call(Backend::Jit, "f", &[1], &mut memory, limits),
        Err(CallError::BackendUnavailable)
    );
}

#[test]
fn compiled_modules_free_their_code_and_can_be_shared_between_threads() {
    for _ in 0..50 {
        let module = Module::compile("fn f(x) { return x * 2; }").unwrap();
        std::thread::scope(|scope| {
            for t in 0..4 {
                let module = &module;
                scope.spawn(move || {
                    let mut memory = vec![0u8; 16];
                    let out = module
                        .call(Backend::Jit, "f", &[t], &mut memory, Limits::with_gas(100))
                        .unwrap();
                    assert_eq!(out.result, Ok(t * 2));
                });
            }
        });
    }
}
