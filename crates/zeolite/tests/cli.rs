//! Runs the real `zeolite` binary for the local, offline subcommands.

use std::path::PathBuf;
use std::process::{Command as Process, Output};
use zeolite::state::{Command, State};
use zeolite_raft::{Entry, HardState, Ready, Storage};

fn zeolite(args: &[&str]) -> Output {
    Process::new(env!("CARGO_BIN_EXE_zeolite"))
        .args(args)
        .output()
        .expect("the binary runs")
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}): {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn temp_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("zeolite-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let _ = std::fs::remove_file(&path);
    path
}

fn program(name: &str) -> PathBuf {
    let path = temp_path(name);
    std::fs::write(
        &path,
        "fn add(a, b) { store(0, a + b); return a + b; }\nfn div(a, b) { return a / b; }\n",
    )
    .unwrap();
    path
}

#[test]
fn zel_reports_results_and_traps_as_json() {
    let file = program("json.zel");
    let file = file.to_str().unwrap();

    let out = zeolite(&["zel", file, "--call", "add", "--args", "2,-5", "--json"]);
    assert!(out.status.success());
    let value = json(&out);
    assert_eq!(value["result"], -3);
    assert_eq!(value["backend"], "jit");
    assert_eq!(value["function"], "add");
    assert!(value["gas_used"].as_u64().unwrap() > 0);
    assert_eq!(value["memory_sha256"].as_str().unwrap().len(), 64);

    // A trap is a completed run, reported in the JSON rather than as a failure.
    let out = zeolite(&[
        "zel",
        file,
        "--call",
        "div",
        "--args",
        "1,0",
        "--json",
        "--interpret",
    ]);
    assert!(out.status.success());
    let value = json(&out);
    assert_eq!(value["trap"], "division by zero");
    assert_eq!(value["backend"], "interpreter");
    assert!(value.get("result").is_none());

    // Without --json a trap is still an error exit.
    let out = zeolite(&["zel", file, "--call", "div", "--args", "1,0"]);
    assert!(!out.status.success());
    std::fs::remove_file(file).unwrap();
}

#[test]
fn zel_compare_runs_both_backends() {
    let file = program("compare.zel");
    let file = file.to_str().unwrap();
    let out = zeolite(&[
        "zel",
        file,
        "--call",
        "add",
        "--args",
        "40,2",
        "--compare",
        "--json",
    ]);
    assert!(out.status.success());
    let value = json(&out);
    assert_eq!(value["agree"], true);
    assert_eq!(value["interpreter"]["result"], 42);
    assert_eq!(value["jit"]["result"], 42);
    assert_eq!(value["interpreter"]["gas_used"], value["jit"]["gas_used"]);
    assert_eq!(
        value["interpreter"]["memory_sha256"],
        value["jit"]["memory_sha256"]
    );

    // Out of gas partway through, on both.
    let out = zeolite(&[
        "zel",
        file,
        "--call",
        "add",
        "--args",
        "1,1",
        "--gas",
        "1",
        "--compare",
    ]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.matches("trap: out of gas").count(), 2, "{text}");

    let out = zeolite(&["zel", file, "--compare", "--interpret"]);
    assert!(!out.status.success(), "--compare and --interpret conflict");
    std::fs::remove_file(file).unwrap();
}

#[test]
fn inspect_reports_a_data_directory_without_changing_it() {
    let dir = temp_path("inspect");
    let (mut storage, _) = Storage::open(&dir).unwrap();
    let deploy = Command::DeployZel {
        tenant: "acme".into(),
        name: "counter".into(),
        source: "fn add(n) { let v = load(0) + n; store(0, v); return v; }".into(),
        memory_bytes: 64,
    };
    let add = Command::Execute {
        tenant: "acme".into(),
        name: "counter".into(),
        function: "add".into(),
        args: vec![7],
        gas: 10_000,
    };
    let entries: Vec<Entry> = [Vec::new(), postcard_bytes(&deploy), postcard_bytes(&add)]
        .into_iter()
        .enumerate()
        .map(|(i, data)| Entry {
            term: 1,
            index: i as u64 + 1,
            data,
        })
        .collect();
    storage
        .persist(&Ready {
            entries,
            hard_state: Some(HardState {
                term: 1,
                voted_for: Some(1),
                commit: 3,
            }),
            ..Ready::default()
        })
        .unwrap();
    drop(storage);
    let wal_before = std::fs::read(dir.join("wal")).unwrap();

    let mut expected = State::default();
    expected.apply(deploy);
    expected.apply(add);

    let out = zeolite(&["inspect", dir.to_str().unwrap(), "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value = json(&out);
    assert_eq!(value["log"]["last_index"], 3);
    assert_eq!(value["log"]["commit_index"], 3);
    assert_eq!(value["commands"]["deploy_zel"], 1);
    assert_eq!(value["commands"]["execute"], 1);
    assert_eq!(value["commands"]["noop"], 1);
    assert_eq!(value["state"]["digest"], expected.digest());
    assert_eq!(value["wal"]["torn_bytes"], 0);
    assert!(value["snapshot"].is_null());

    let out = zeolite(&["inspect", dir.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(&expected.digest()));
    assert_eq!(std::fs::read(dir.join("wal")).unwrap(), wal_before);
    assert!(!dir.join("snapshot").exists());

    let missing = temp_path("inspect-missing");
    let out = zeolite(&["inspect", missing.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(!missing.exists(), "inspect must not create the directory");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn postcard_bytes(command: &Command) -> Vec<u8> {
    postcard::to_allocvec(command).unwrap()
}
