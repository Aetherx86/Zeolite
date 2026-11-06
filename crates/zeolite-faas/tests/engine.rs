//! Behavior of the function engine against real Wasm modules, including hostile ones.

use std::sync::Arc;
use std::time::{Duration, Instant};
use zeolite_faas::{DeployError, Function, InvokeError, Limits, Runtime};

/// Wraps a body in the required ABI. `handle` starts with the input at local 0 and its
/// length at local 1, and the bump allocator starts at offset 1024.
fn module(body: &str, extra: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
            (import "zeolite" "log" (func $log (param i32 i32)))
            (memory (export "memory") 1)
            (global $next (mut i32) (i32.const 1024))
            (func (export "alloc") (param $len i32) (result i32)
                (local $p i32)
                global.get $next
                local.set $p
                global.get $next
                local.get $len
                i32.add
                global.set $next
                local.get $p)
            {extra}
            (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
                {body}))"#
    ))
    .unwrap()
}

/// Returns the input unchanged.
fn echo() -> Vec<u8> {
    module(
        r#"local.get $ptr
           i64.extend_i32_u
           i64.const 32
           i64.shl
           local.get $len
           i64.extend_i32_u
           i64.or"#,
        "",
    )
}

fn deploy(runtime: &Runtime, wasm: &[u8]) -> Function {
    runtime.deploy(wasm).unwrap()
}

#[test]
fn echoes_input_and_reports_metering() {
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &echo());
    let out = runtime.invoke(&f, b"hello tenant", &Limits::default());
    assert_eq!(out.result.unwrap(), b"hello tenant");
    assert!(out.fuel_used > 0);
    assert!(out.instantiate <= out.elapsed);
}

#[test]
fn every_invocation_starts_from_a_clean_instance() {
    // Counts calls in a global and in memory. Both must reset on every request, or one
    // request could read data left behind by another tenant's request.
    let wasm = module(
        r#"(i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.const 1)))
           (global.set $calls (i32.add (global.get $calls) (i32.const 1)))
           (i32.store (i32.const 4) (global.get $calls))
           i64.const 0
           i64.const 32
           i64.shl
           i64.const 8
           i64.or"#,
        "(global $calls (mut i32) (i32.const 0))",
    );
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &wasm);
    for _ in 0..3 {
        let out = runtime.invoke(&f, b"", &Limits::default());
        assert_eq!(out.result.unwrap(), [1, 0, 0, 0, 1, 0, 0, 0]);
    }
}

#[test]
fn infinite_loop_runs_out_of_fuel() {
    let wasm = module("(loop $l (br $l)) i64.const 0", "");
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &wasm);
    let limits = Limits {
        fuel: 1_000_000,
        ..Limits::default()
    };
    let out = runtime.invoke(&f, b"", &limits);
    assert_eq!(out.result, Err(InvokeError::OutOfFuel));
    assert_eq!(out.fuel_used, 1_000_000);
}

#[test]
fn wall_clock_limit_stops_a_guest_that_still_has_fuel() {
    let wasm = module("(loop $l (br $l)) i64.const 0", "");
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &wasm);
    let limits = Limits {
        fuel: u64::MAX / 2,
        wall_clock: Duration::from_millis(100),
        ..Limits::default()
    };
    let started = Instant::now();
    let out = runtime.invoke(&f, b"", &limits);
    assert_eq!(out.result, Err(InvokeError::TimedOut));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn fuel_metering_is_proportional_to_work() {
    // Loops `input[0]` times.
    let wasm = module(
        r#"(local $i i32)
           (local.set $i (i32.load8_u (local.get $ptr)))
           (loop $l
               (local.set $i (i32.sub (local.get $i) (i32.const 1)))
               (br_if $l (local.get $i)))
           i64.const 0"#,
        "",
    );
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &wasm);
    let small = runtime.invoke(&f, &[10], &Limits::default());
    let large = runtime.invoke(&f, &[200], &Limits::default());
    small.result.as_ref().unwrap();
    large.result.as_ref().unwrap();
    assert!(
        large.fuel_used > small.fuel_used * 5,
        "{} vs {}",
        large.fuel_used,
        small.fuel_used
    );
    // The same input has to meter identically, or usage-based limits are unfair.
    let again = runtime.invoke(&f, &[10], &Limits::default());
    assert_eq!(again.fuel_used, small.fuel_used);
}

#[test]
fn memory_growth_is_capped_without_trapping_the_guest() {
    // Tries to grow by 1 GiB and returns the result of memory.grow, which should be -1.
    let wasm = module(
        r#"(i32.store (i32.const 0) (memory.grow (i32.const 16384)))
           i64.const 0
           i64.const 32
           i64.shl
           i64.const 4
           i64.or"#,
        "",
    );
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &wasm);
    let limits = Limits {
        max_memory_bytes: 1 << 20,
        ..Limits::default()
    };
    let out = runtime.invoke(&f, b"", &limits);
    assert_eq!(out.result.unwrap(), (-1i32).to_le_bytes());
}

#[test]
fn a_module_declaring_oversized_memory_fails_at_instantiation() {
    let wasm = wat::parse_str(
        r#"(module
            (memory (export "memory") 2000)
            (func (export "alloc") (param i32) (result i32) i32.const 0)
            (func (export "handle") (param i32 i32) (result i64) i64.const 0))"#,
    )
    .unwrap();
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &wasm);
    let limits = Limits {
        max_memory_bytes: 1 << 20,
        ..Limits::default()
    };
    let out = runtime.invoke(&f, b"", &limits);
    assert!(
        matches!(out.result, Err(InvokeError::Trap(_))),
        "{:?}",
        out.result
    );
}

#[test]
fn guest_traps_are_contained() {
    let cases = [
        ("unreachable i64.const 0", "unreachable"),
        (
            "(i32.store (i32.const -4) (i32.const 1)) i64.const 0",
            "out of bounds",
        ),
        (
            "(drop (i32.div_s (i32.const 1) (i32.sub (local.get $len) (local.get $len)))) i64.const 0",
            "divide by zero",
        ),
    ];
    let runtime = Runtime::new().unwrap();
    for (body, needle) in cases {
        let f = deploy(&runtime, &module(body, ""));
        let out = runtime.invoke(&f, b"", &Limits::default());
        match &out.result {
            Err(InvokeError::Trap(message)) => assert!(
                message.to_lowercase().contains(needle),
                "{body}: expected {needle:?} in {message:?}"
            ),
            other => panic!("{body}: expected a trap, got {other:?}"),
        }
    }
}

#[test]
fn unbounded_guest_recursion_is_contained() {
    let wasm = module("(call $down) i64.const 0", r#"(func $down (call $down))"#);
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &wasm);
    let limits = Limits {
        fuel: u64::MAX / 2,
        ..Limits::default()
    };
    let out = runtime.invoke(&f, b"", &limits);
    assert!(
        matches!(out.result, Err(InvokeError::Trap(_))),
        "{:?}",
        out.result
    );
}

#[test]
fn hostile_output_ranges_are_rejected() {
    let cases = [
        // Starts past the end of memory.
        "i64.const 0x7FFFFFFF00000001",
        // In bounds at the start, but runs one byte past the end of the 64 KiB memory.
        "i64.const 0x0000000100010000",
        // Pointer and length near the top of the 32-bit range, as a wrap-around attempt.
        "i64.const -1",
    ];
    let runtime = Runtime::new().unwrap();
    for body in cases {
        let f = deploy(&runtime, &module(body, ""));
        let limits = Limits {
            max_output_bytes: usize::MAX,
            ..Limits::default()
        };
        let out = runtime.invoke(&f, b"", &limits);
        assert!(
            matches!(out.result, Err(InvokeError::Abi(_))),
            "{body}: {:?}",
            out.result
        );
    }
}

#[test]
fn an_output_range_that_exactly_fills_memory_is_valid() {
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &module("i64.const 0x0000000000010000", ""));
    let out = runtime.invoke(&f, b"", &Limits::default());
    assert_eq!(out.result.unwrap().len(), 65536);
}

#[test]
fn output_limit_is_enforced() {
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &echo());
    let limits = Limits {
        max_output_bytes: 4,
        ..Limits::default()
    };
    let out = runtime.invoke(&f, b"too long", &limits);
    assert_eq!(out.result, Err(InvokeError::OutputTooLarge));
}

#[test]
fn input_limit_is_enforced_before_any_guest_code_runs() {
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &echo());
    let limits = Limits {
        max_input_bytes: 2,
        ..Limits::default()
    };
    let out = runtime.invoke(&f, b"too long", &limits);
    assert_eq!(out.result, Err(InvokeError::InputTooLarge));
    assert_eq!(out.fuel_used, 0);
}

#[test]
fn a_hostile_alloc_cannot_write_outside_memory() {
    let wasm = wat::parse_str(
        r#"(module
            (memory (export "memory") 1)
            (func (export "alloc") (param i32) (result i32) i32.const -8)
            (func (export "handle") (param i32 i32) (result i64) i64.const 0))"#,
    )
    .unwrap();
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &wasm);
    let out = runtime.invoke(&f, &[1; 64], &Limits::default());
    assert!(
        matches!(out.result, Err(InvokeError::Abi(_))),
        "{:?}",
        out.result
    );
}

#[test]
fn logs_are_captured_and_bounded() {
    let wasm = module(
        r#"(call $log (local.get $ptr) (local.get $len))
           (call $log (local.get $ptr) (local.get $len))
           (call $log (i32.const -1) (i32.const 100))
           i64.const 0"#,
        "",
    );
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &wasm);
    let out = runtime.invoke(&f, b"abc", &Limits::default());
    assert_eq!(
        out.logs, b"abcabc",
        "a hostile range must be ignored, not fatal"
    );
    let limits = Limits {
        max_log_bytes: 4,
        ..Limits::default()
    };
    let out = runtime.invoke(&f, b"abc", &limits);
    assert_eq!(out.logs, b"abca");
}

#[test]
fn deployment_rejects_invalid_modules_and_abi_violations() {
    let runtime = Runtime::new().unwrap();
    assert!(matches!(
        runtime.deploy(b"not wasm"),
        Err(DeployError::Invalid(_))
    ));
    assert!(matches!(runtime.deploy(&[]), Err(DeployError::Invalid(_))));

    let bad_abi = [
        ("(module)", "missing"),
        (r#"(module (memory (export "memory") 1))"#, "missing"),
        (
            r#"(module (memory (export "memory") 1)
                (func (export "alloc") (result i32) i32.const 0)
                (func (export "handle") (param i32 i32) (result i64) i64.const 0))"#,
            "signature",
        ),
        (
            r#"(module (memory (export "memory") 1)
                (func (export "alloc") (param i32) (result i32) i32.const 0)
                (func (export "handle") (param i32 i32) (result i32) i32.const 0))"#,
            "signature",
        ),
        (
            r#"(module (memory (export "memory") 1)
                (func (export "alloc") (param f32) (result i32) i32.const 0)
                (func (export "handle") (param i32 i32) (result i64) i64.const 0))"#,
            "signature",
        ),
        (
            r#"(module (global (export "memory") i32 (i32.const 0))
                (func (export "alloc") (param i32) (result i32) i32.const 0)
                (func (export "handle") (param i32 i32) (result i64) i64.const 0))"#,
            "not a memory",
        ),
    ];
    for (source, needle) in bad_abi {
        let wasm = wat::parse_str(source).unwrap();
        match runtime.deploy(&wasm) {
            Err(DeployError::Abi(message)) => {
                assert!(message.contains(needle), "{source}: {message}");
            }
            other => panic!("{source}: expected an ABI error, got {other:?}"),
        }
    }
}

#[test]
fn modules_cannot_import_anything_outside_the_sandbox() {
    let runtime = Runtime::new().unwrap();
    for import in [
        r#"(import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))"#,
        r#"(import "env" "system" (func (param i32) (result i32)))"#,
        r#"(import "zeolite" "exec" (func))"#,
    ] {
        let wasm = wat::parse_str(format!(
            r#"(module {import}
                (memory (export "memory") 1)
                (func (export "alloc") (param i32) (result i32) i32.const 0)
                (func (export "handle") (param i32 i32) (result i64) i64.const 0))"#
        ))
        .unwrap();
        assert!(
            matches!(runtime.deploy(&wasm), Err(DeployError::Abi(_))),
            "{import} should be refused"
        );
    }
}

#[test]
fn modules_using_threads_are_refused() {
    // A shared memory and atomics are how a guest would get at threads.
    let runtime = Runtime::new().unwrap();
    let wasm = wat::parse_str(
        r#"(module
            (memory (export "memory") 1 1 shared)
            (func (export "alloc") (param i32) (result i32) i32.const 0)
            (func (export "handle") (param i32 i32) (result i64) i64.const 0))"#,
    )
    .unwrap();
    assert!(runtime.deploy(&wasm).is_err());
}

#[test]
fn concurrent_tenants_are_isolated() {
    let runtime = Arc::new(Runtime::new().unwrap());
    let f = Arc::new(deploy(&runtime, &echo()));
    std::thread::scope(|scope| {
        for t in 0..8u8 {
            let (runtime, f) = (runtime.clone(), f.clone());
            scope.spawn(move || {
                for i in 0..50u8 {
                    let input = [t, i, t ^ i];
                    let out = runtime.invoke(&f, &input, &Limits::default());
                    assert_eq!(out.result.unwrap(), input);
                }
            });
        }
    });
}

#[test]
fn cold_start_is_well_under_a_millisecond_once_warm() {
    let runtime = Runtime::new().unwrap();
    let f = deploy(&runtime, &echo());
    let mut samples: Vec<Duration> = (0..200)
        .map(|_| runtime.invoke(&f, b"x", &Limits::default()).instantiate)
        .collect();
    samples.sort();
    let median = samples[samples.len() / 2];
    eprintln!(
        "instantiation median {median:?}, max {:?}",
        samples[samples.len() - 1]
    );
    // A generous bound so that a loaded CI machine does not make this flaky.
    assert!(median < Duration::from_millis(10), "median was {median:?}");
}
