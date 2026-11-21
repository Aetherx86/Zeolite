# Changelog

Versions follow this rule: a bug or security fix increments `0.0.X`, and new functionality
or new platform support increments `0.X.0`.

## [0.2.0] - 2026-11-20

Added

- Raft leadership transfer. `Raft::transfer_leadership(target)` makes the leader stop
  accepting proposals (they are redirected to the target), bring the target's log up to
  date, and then send it a new `TimeoutNow` message (wire tag 9). The target starts an
  election at once, skipping pre-vote, and wins it in the next term. A transfer that has
  not completed within one base election timeout is abandoned and the leader resumes
  normal service. `Raft::transfer_target()` reports a transfer in flight.
- `Node::transfer_leadership` and `POST /v1/leadership/transfer` with `{"to": ID}` (admin
  token required). The endpoint waits, up to `timeout_ms` (default 5000, at most 60000),
  until the node sees the target lead, and returns its id and term. A follower answers
  421 naming the leader.
- `zeolite_raft::storage::inspect`, a read-only view of a storage directory: WAL size,
  valid and torn bytes, record counts, hard state, snapshot metadata or the reason it is
  corrupt, and the exact log Raft would start from. It never creates, truncates or
  rewrites files.
- `zeolite inspect DIR [--json]`, which reports the above for a node's data directory,
  counts committed commands by kind, and replays the committed log onto the snapshot to
  print the state digest at the stored commit index. Stopped replicas at one commit index
  report the same digest as `/v1/digest`. The exit status is non-zero when a node could
  not start from the directory.
- `zeolite zel --json` prints the result or trap, gas used, backend and a SHA-256 of the
  final memory. `zeolite zel --compare` runs the call on both the interpreter and the JIT,
  each on its own memory, and exits non-zero unless they agree on all three.

Tests

- Directed protocol tests for transfer, `TimeoutNow` handling and its stale form.
- Simulation: chaos runs with random transfers on top of loss, duplication, partitions,
  crashes and compaction, with all four Raft safety properties checked throughout, plus
  scenarios for a hand-off costing exactly one term, a lagging target, and a transfer to
  an unreachable node expiring.
- Cluster tests that move leadership between real nodes, over the node API and over HTTP.
- A property test that gas metering is exact on both backends: a call given exactly the
  gas it used reproduces its outcome and memory, and one unit less runs out of gas.
- Storage inspection tests, including that inspecting a torn log leaves it byte for byte
  unchanged, and end-to-end tests of the `zel` and `inspect` subcommands.

Security

- wasmtime 48.0.8 to 48.0.10 and Cranelift 0.135.8 to 0.135.10, which fixes
  RUSTSEC-2026-0566 through RUSTSEC-2026-0573. `cargo audit` reports no vulnerabilities.
  It does report nine new unsoundness warnings (RUSTSEC-2026-0574 through
  RUSTSEC-2026-0582) for `heapless` 0.7, which arrives through `postcard`. They are left
  visible rather than suppressed.

Compatibility

- `Message` gains the `TimeoutNow` variant, so a 0.1 node cannot decode it. Upgrade every
  node before using leadership transfer. Storage formats are unchanged.

## 0.1.1

Security

- `smallvec` 1.16.4 to 1.16.5.
- `.cargo/audit.toml` records the one remaining `cargo audit` warning, RUSTSEC-2023-0089: `atomic-polyfill` is unmaintained, not vulnerable, and arrives only through wasmtime and Cranelift (`postcard` to `heapless` 0.7). `cargo audit` now reports no vulnerabilities and no warnings.

## 0.1.0

First release.

- Raft consensus with pre-vote, check-quorum and snapshot-based log compaction, a
  checksummed write-ahead log, and an encrypted transport.
- Zel, a deterministic gas-metered language with an interpreter and a Cranelift JIT.
- A virtual machine monitor on KVM and Hypervisor.framework, with a Linux 64-bit boot
  loader, a 16550 UART, and virtio-mmio block, console and entropy devices.
- A multi-tenant WebAssembly function engine with per-request instruction metering.
- A cluster node with an HTTP gateway, signed webhooks and replicated execution.
