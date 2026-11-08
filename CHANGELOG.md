# Changelog

Versions follow this rule: a bug or security fix increments `0.0.X`, and new functionality
or new platform support increments `0.X.0`.

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
