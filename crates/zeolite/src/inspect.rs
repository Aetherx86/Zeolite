//! Offline inspection of a node's data directory.
//!
//! Nothing here writes to disk. The report shows what a node would recover if it started
//! from the directory, and replays the committed log onto the snapshot to compute the state
//! digest at the stored commit index. Two stopped replicas with the same commit index must
//! report the same digest, which makes this a way to check replicas against each other
//! without starting them.

use crate::state::{Command, State};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
use zeolite_raft::storage::{self, Inspection};

/// The replicated state rebuilt from a data directory.
pub struct Replayed {
    pub applied_index: u64,
    pub digest: String,
    pub workloads: usize,
}

/// A data directory examined at both layers: Raft storage and the state machine.
pub struct Report {
    pub storage: Inspection,
    /// Committed commands by kind. Empty entries count as `noop`.
    pub commands: BTreeMap<&'static str, u64>,
    pub snapshot_state: Option<Replayed>,
    pub state: Option<Replayed>,
    /// Why the state could not be rebuilt, when it could not.
    pub state_error: Option<String>,
}

impl Report {
    /// Whether a node would refuse to start from this directory.
    pub fn is_unrecoverable(&self) -> bool {
        self.storage.snapshot_error.is_some() || self.state_error.is_some()
    }
}

pub fn inspect(dir: impl AsRef<Path>) -> std::io::Result<Report> {
    let storage = storage::inspect(dir)?;
    let mut commands = BTreeMap::new();
    let mut snapshot_state = None;
    let mut state = None;
    let mut state_error = storage.snapshot_error.clone();

    if state_error.is_none() {
        let base = match &storage.snapshot {
            Some(snapshot) => State::decode(&snapshot.data)
                .map_err(|e| format!("snapshot state does not decode: {e}")),
            None => Ok(State::default()),
        };
        match base {
            Ok(mut replica) => {
                let snapshot_index = storage.snapshot_index();
                if storage.snapshot.is_some() {
                    snapshot_state = Some(Replayed {
                        applied_index: snapshot_index,
                        digest: replica.digest(),
                        workloads: replica.len(),
                    });
                }
                // Apply exactly what the node's driver would: committed entries in order,
                // skipping the no-ops that new leaders append.
                let commit = storage.commit_index();
                for entry in storage.usable().iter().filter(|e| e.index <= commit) {
                    let kind = if entry.data.is_empty() {
                        "noop"
                    } else {
                        match postcard::from_bytes::<Command>(&entry.data) {
                            Ok(command) => {
                                let kind = command.kind();
                                replica.apply(command);
                                kind
                            }
                            Err(_) => "undecodable",
                        }
                    };
                    *commands.entry(kind).or_insert(0) += 1;
                }
                state = Some(Replayed {
                    applied_index: commit,
                    digest: replica.digest(),
                    workloads: replica.len(),
                });
            }
            Err(e) => state_error = Some(e),
        }
    }

    Ok(Report {
        storage,
        commands,
        snapshot_state,
        state,
        state_error,
    })
}

fn replayed_json(replayed: &Option<Replayed>) -> Value {
    match replayed {
        Some(r) => json!({
            "applied_index": r.applied_index,
            "digest": r.digest,
            "workloads": r.workloads,
        }),
        None => Value::Null,
    }
}

pub fn to_json(report: &Report) -> Value {
    let s = &report.storage;
    let usable = s.usable();
    json!({
        "wal": {
            "bytes": s.wal_bytes,
            "valid_bytes": s.valid_bytes,
            "torn_bytes": s.torn_bytes,
            "records": {
                "hard_state": s.records.hard_state,
                "truncate": s.records.truncate,
                "entry": s.records.entry,
            },
        },
        "hard_state": {
            "term": s.hard_state.term,
            "voted_for": s.hard_state.voted_for,
            "commit": s.hard_state.commit,
        },
        "snapshot": s.snapshot.as_ref().map(|snap| json!({
            "last_index": snap.last_index,
            "last_term": snap.last_term,
            "file_bytes": s.snapshot_file_bytes,
            "data_bytes": snap.data.len(),
            "state": replayed_json(&report.snapshot_state),
        })),
        "snapshot_error": s.snapshot_error,
        "log": {
            "first_index": usable.first().map(|e| e.index),
            "last_index": s.last_index(),
            "commit_index": s.commit_index(),
            "usable_entries": s.usable_entries,
            "discarded_entries": s.discarded_entries(),
            "payload_bytes": usable.iter().map(|e| e.data.len() as u64).sum::<u64>(),
        },
        "commands": report.commands,
        "state": replayed_json(&report.state),
        "state_error": report.state_error,
    })
}

pub fn to_text(report: &Report) -> String {
    let s = &report.storage;
    let usable = s.usable();
    let mut out = String::new();
    let mut line = |label: &str, value: String| out.push_str(&format!("{label:<12}{value}\n"));
    line(
        "wal",
        format!(
            "{} bytes ({} valid, {} torn)",
            s.wal_bytes, s.valid_bytes, s.torn_bytes
        ),
    );
    line(
        "records",
        format!(
            "{} hard state, {} truncate, {} entry",
            s.records.hard_state, s.records.truncate, s.records.entry
        ),
    );
    line(
        "hard state",
        format!(
            "term {}, voted for {}, commit {}",
            s.hard_state.term,
            s.hard_state
                .voted_for
                .map_or("nobody".to_string(), |v| v.to_string()),
            s.hard_state.commit
        ),
    );
    match (&s.snapshot, &s.snapshot_error) {
        (Some(snap), _) => line(
            "snapshot",
            format!(
                "index {}, term {}, {} bytes of state",
                snap.last_index,
                snap.last_term,
                snap.data.len()
            ),
        ),
        (None, Some(e)) => line("snapshot", format!("CORRUPT: {e}")),
        (None, None) => line("snapshot", "none".to_string()),
    }
    let range = match (usable.first(), usable.last()) {
        (Some(first), Some(last)) => format!("{}..={}", first.index, last.index),
        _ => "empty".to_string(),
    };
    line(
        "log",
        format!(
            "{range} ({} usable, {} discarded)",
            s.usable_entries,
            s.discarded_entries()
        ),
    );
    line("commit", s.commit_index().to_string());
    if !report.commands.is_empty() {
        let parts: Vec<String> = report
            .commands
            .iter()
            .map(|(kind, n)| format!("{n} {kind}"))
            .collect();
        line("commands", parts.join(", "));
    }
    match (&report.state, &report.state_error) {
        (Some(r), _) => line(
            "state",
            format!(
                "applied {}, {} workloads, digest {}",
                r.applied_index, r.workloads, r.digest
            ),
        ),
        (None, Some(e)) => line("state", format!("UNRECOVERABLE: {e}")),
        (None, None) => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeolite_raft::{Entry, HardState, Ready, Snapshot, Storage};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("zeolite-inspect-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn command_entry(term: u64, index: u64, command: &Command) -> Entry {
        Entry {
            term,
            index,
            data: postcard::to_allocvec(command).unwrap(),
        }
    }

    fn deploy() -> Command {
        Command::DeployZel {
            tenant: "acme".into(),
            name: "counter".into(),
            source: "fn add(n) { let v = load(0) + n; store(0, v); return v; }".into(),
            memory_bytes: 64,
        }
    }

    fn add(n: i64) -> Command {
        Command::Execute {
            tenant: "acme".into(),
            name: "counter".into(),
            function: "add".into(),
            args: vec![n],
            gas: 10_000,
        }
    }

    #[test]
    fn replays_only_committed_commands_onto_the_snapshot() {
        let dir = temp_dir("replay");
        let (mut storage, _) = Storage::open(&dir).unwrap();

        // The snapshot holds the counter at 5.
        let mut at_snapshot = State::default();
        at_snapshot.apply(deploy());
        at_snapshot.apply(add(5));
        storage
            .save_snapshot(
                &Snapshot {
                    last_index: 3,
                    last_term: 1,
                    data: at_snapshot.encode(),
                },
                &[],
                HardState::default(),
            )
            .unwrap();
        storage
            .persist(&Ready {
                entries: vec![
                    Entry {
                        term: 2,
                        index: 4,
                        data: vec![],
                    },
                    command_entry(2, 5, &add(10)),
                    command_entry(2, 6, &add(100)),
                    Entry {
                        term: 2,
                        index: 7,
                        data: vec![0xFF, 0xFF],
                    },
                ],
                hard_state: Some(HardState {
                    term: 2,
                    voted_for: Some(1),
                    commit: 5,
                }),
                ..Ready::default()
            })
            .unwrap();
        drop(storage);

        let report = inspect(&dir).unwrap();
        assert!(!report.is_unrecoverable());
        let snap = report.snapshot_state.as_ref().unwrap();
        assert_eq!(snap.applied_index, 3);
        assert_eq!(snap.digest, at_snapshot.digest());

        // Index 6 is not committed, so only the no-op and `add(10)` are replayed.
        let mut expected = at_snapshot;
        expected.apply(add(10));
        let state = report.state.as_ref().unwrap();
        assert_eq!(state.applied_index, 5);
        assert_eq!(state.digest, expected.digest());
        assert_eq!(state.workloads, 1);
        assert_eq!(
            report.commands,
            BTreeMap::from([("execute", 1), ("noop", 1)])
        );

        let value = to_json(&report);
        assert_eq!(value["log"]["first_index"], 4);
        assert_eq!(value["log"]["last_index"], 7);
        assert_eq!(value["log"]["commit_index"], 5);
        assert_eq!(value["snapshot"]["last_index"], 3);
        assert_eq!(value["state"]["digest"], expected.digest());
        assert!(to_text(&report).contains(&expected.digest()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_corrupt_snapshot_is_reported_as_unrecoverable() {
        let dir = temp_dir("corrupt");
        let (mut storage, _) = Storage::open(&dir).unwrap();
        storage
            .save_snapshot(
                &Snapshot {
                    last_index: 1,
                    last_term: 1,
                    data: State::default().encode(),
                },
                &[],
                HardState::default(),
            )
            .unwrap();
        drop(storage);
        let path = dir.join("snapshot");
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x10;
        std::fs::write(&path, bytes).unwrap();

        let report = inspect(&dir).unwrap();
        assert!(report.is_unrecoverable());
        assert!(report.state.is_none());
        assert!(to_text(&report).contains("CORRUPT"));
        assert!(to_json(&report)["snapshot_error"].is_string());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn undecodable_snapshot_state_is_reported() {
        let dir = temp_dir("badstate");
        let (mut storage, _) = Storage::open(&dir).unwrap();
        storage
            .save_snapshot(
                &Snapshot {
                    last_index: 1,
                    last_term: 1,
                    data: vec![0xFF; 16],
                },
                &[],
                HardState::default(),
            )
            .unwrap();
        drop(storage);
        let report = inspect(&dir).unwrap();
        assert!(report.is_unrecoverable());
        assert!(report.state_error.unwrap().contains("snapshot state"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
