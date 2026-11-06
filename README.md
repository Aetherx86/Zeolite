# Zeolite

A distributed runtime for sandboxed workloads. A cluster of nodes agrees on what is
deployed through Raft, then runs each workload in one of three isolation tiers: a
deterministic JIT, a metered WebAssembly sandbox, or a hardware-virtualized micro-VM.

Zeolites are crystals full of tiny isolated cages, which is the idea here: many small,
walled-off workloads inside one solid structure.

```
                   HTTP gateway: deploy, execute, invoke, webhooks, boot
                                          |
            +-----------------------------v------------------------------+
            |  zeolite-raft     Consensus and durable replicated log     |
            |                   State + Command -> New State + Result    |
            +----------+------------------+------------------+-----------+
                       |                  |                  |
            +----------v-----+  +---------v-------+  +-------v----------+
            |  zeolite-jit   |  |  zeolite-faas   |  |  zeolite-vmm     |
            |  Zel language  |  |  Wasm functions |  |  KVM / HVF       |
            |  replicated    |  |  per request    |  |  micro-VMs       |
            +----------------+  +-----------------+  +------------------+
```

## Execution tiers

| Tier | Isolation | State | Use it for |
|---|---|---|---|
| Zel | Bounds checks and gas, on both backends | Replicated on every node | Deterministic state machines |
| Wasm | WebAssembly sandbox, a fresh instance per request | None between requests | Webhooks and stateless functions |
| Micro-VM | Hardware virtualization | None between boots | Untrusted native code and whole kernels |

## Crates

**`zeolite-raft`** is consensus, written from scratch. The protocol core is sans-IO: it
never touches a clock, a disk or a socket, which is what makes it possible to test it
deterministically. It implements elections with pre-vote, check-quorum, log replication,
and log compaction through snapshots. Around the core are a checksummed write-ahead log
that recovers from torn writes, and a transport where every frame is encrypted and
authenticated (ChaCha20-Poly1305, with per-direction keys derived from a pre-shared
cluster key and fresh nonces).

**`zeolite-jit`** compiles Zel, a small statement language over `i64`, to a register IR
and then to native code through Cranelift. A reference interpreter runs the same IR. The
two backends must agree exactly on results, gas used and memory contents, even for
programs that trap. That property lets replicas execute a command independently and
still reach the same state. Generated code never relies on signals: gas, bounds, division
and recursion are all checked explicitly, so a guest fault cannot take down the host.

```
fn add(n) { let v = load(0) + n; store(0, v); return v; }
```

**`zeolite-vmm`** is a virtual machine monitor written directly against the hypervisor
interfaces, with no VMM libraries.

| Host | Backend | Guests |
|---|---|---|
| Linux on x86-64 | `/dev/kvm` | Raw 16-bit and 64-bit code, Linux bzImage kernels |
| macOS on Apple Silicon | Hypervisor.framework | Raw AArch64 code |
| Anything else | None | Runs fail with a clear "unavailable" error |

It sets up page tables and a GDT, loads kernels through the Linux 64-bit boot protocol,
emulates a 16550 UART, and provides virtio-mmio block, console and entropy devices.
Guest memory is only ever copied in and out, never referenced, and everything read from a
virtqueue is treated as hostile.

**`zeolite-faas`** runs uploaded WebAssembly modules on Wasmtime, with a fresh instance
per request and hard limits on fuel (metered instructions), memory, wall-clock time and
output. Modules can import nothing except a bounded log function, so no filesystem,
network or clock is reachable.

**`zeolite`** ties it together: the node, the replicated state machine, the HTTP gateway
and the command line.

## Quick start

Run code locally, with no cluster:

```sh
cargo run -p zeolite -- zel program.zel --call main --args 1,2
cargo run -p zeolite -- wasm function.wasm < input.bin
cargo run -p zeolite -- vm --kernel bzImage --memory-mib 512
```

Start a three-node cluster on one machine:

```sh
cargo build --release -p zeolite
Z=target/release/zeolite
$Z generate-key > cluster.key
printf 'choose-a-long-random-token' > admin.token

$Z serve --id 1 --raft 127.0.0.1:7001 --http 127.0.0.1:8001 --data data/1 \
  --key-file cluster.key --token-file admin.token \
  --peer 2=127.0.0.1:7002=127.0.0.1:8002 --peer 3=127.0.0.1:7003=127.0.0.1:8003 &
$Z serve --id 2 --raft 127.0.0.1:7002 --http 127.0.0.1:8002 --data data/2 \
  --key-file cluster.key --token-file admin.token \
  --peer 1=127.0.0.1:7001=127.0.0.1:8001 --peer 3=127.0.0.1:7003=127.0.0.1:8003 &
$Z serve --id 3 --raft 127.0.0.1:7003 --http 127.0.0.1:8003 --data data/3 \
  --key-file cluster.key --token-file admin.token \
  --peer 1=127.0.0.1:7001=127.0.0.1:8001 --peer 2=127.0.0.1:7002=127.0.0.1:8002 &
```

Writes go to the leader. Any other node answers with status 421 and names the leader.

```sh
AUTH="Authorization: Bearer choose-a-long-random-token"
LEADER=127.0.0.1:8001

# Deploy a program and run it on every replica.
curl -H "$AUTH" -X PUT "$LEADER/v1/functions/acme/counter?kind=zel" \
  --data-binary 'fn add(n) { let v = load(0) + n; store(0, v); return v; }'
curl -H "$AUTH" -X POST "$LEADER/v1/functions/acme/counter/execute/add" -d '{"args":[5]}'

# Every node reports the same digest once it has applied the same commands.
curl 127.0.0.1:8001/v1/digest
curl 127.0.0.1:8002/v1/digest
```

## HTTP API

| Method and path | Purpose | Auth |
|---|---|---|
| `GET /v1/status` | Role, term, leader and log positions | None |
| `GET /v1/digest` | SHA-256 of the replicated state | None |
| `PUT /v1/functions/{tenant}/{name}?kind=zel\|wasm\|vm` | Deploy a workload | Token |
| `DELETE /v1/functions/{tenant}/{name}` | Remove a workload | Token |
| `POST /v1/functions/{tenant}/{name}/execute/{function}` | Run Zel on all replicas | Token |
| `POST /v1/functions/{tenant}/{name}/invoke` | Run Wasm on this node | Token |
| `POST /v1/functions/{tenant}/{name}/boot` | Boot a micro-VM on this node | Token |
| `POST /hooks/{tenant}/{name}` | Webhook trigger for a Wasm function | HMAC if a secret is set |

Wasm responses carry `x-zeolite-fuel-used`, `x-zeolite-cold-start-micros` and
`x-zeolite-micros`.

Deploying with `kind=vm` also takes `arch=x86-long`, `x86-real` or `aarch64`. A webhook
secret is set at deploy time with `webhook_secret=...`, and callers then sign the body:
`x-zeolite-signature: sha256=<hex hmac>`.

### Wasm function ABI

A module exports `memory`, `alloc(len: i32) -> i32` and
`handle(ptr: i32, len: i32) -> i64`, which returns `(output_ptr << 32) | output_len`.

## How it is tested

The goal is tests that can fail, so several were checked by deliberately breaking the code.

- **Raft** runs in a deterministic simulator with message loss, duplication, reordering,
  partitions, crashes and compaction across hundreds of seeded runs, checking Election
  Safety, Log Matching, Leader Completeness and State Machine Safety throughout. Directed
  tests cover scenarios chaos rarely reaches, such as Figure 8 of the Raft paper.
- **The JIT** is differentially tested against the interpreter on randomly generated
  programs, comparing results, gas and final memory. The test fails if the generator stops
  producing a variety of outcomes.
- **Mutation checks**: known bugs were injected into the Raft core and the JIT, such as an
  off-by-one quorum, double voting, signed bounds checks and dropped callee traps. Each one
  made the suite fail. Mutants that initially survived led to new tests.
- **The VMM** boots real guests. CI boots a real Linux kernel to userspace under KVM with a
  small static init. The virtio stack is driven through its registers and rings with hostile
  input, on every platform.
- **The cluster** tests run real nodes with real sockets and fsync, including leader
  failure, full restarts and catching up through snapshots.

## Measured

On an Apple Silicon laptop, in a debug build:

| Operation | Time |
|---|---|
| Wasm instance creation, median | 16 microseconds |
| Micro-VM, boot to halt with a small AArch64 payload | About 60 microseconds |

On a GitHub Actions runner, under nested virtualization:

| Operation | Time |
|---|---|
| Unmodified Linux 7.0 distribution kernel, boot to its first userspace process and reboot | About 4.4 seconds |

These are single measurements, not a benchmark suite. The kernel is a large general-purpose
build that was not tuned for fast booting.

## Limitations

- Cluster membership is fixed at startup.
- A VM has one vCPU. Linux boots on x86-64 KVM only, and Hypervisor.framework runs raw
  AArch64 payloads only.
- Guest RAM is limited to 3 GiB on KVM, because of the fixed MMIO hole.
- The virtio console and block devices have been exercised through their registers, but
  not yet by a Linux guest driver in CI.
- Proposals are not deduplicated. If a leader changes mid-request, the client gets an
  "outcome unknown" error, and a blind retry can apply the command twice.
- Snapshots travel as one message, so state size is bounded by the transport's frame limit.
- The cluster key authenticates membership, not individual nodes: any key holder can claim
  to be any member.
- Webhook secrets and workloads are stored unencrypted in the data directory.
- This has not had an independent security review. Treat the isolation claims accordingly.

## Versioning

A bug or security fix increments `0.0.X`. New functionality or new platform support
increments `0.X.0`. See [CHANGELOG.md](CHANGELOG.md). Each tag publishes binaries to GitHub
Releases and a container image to `ghcr.io/aetherx86/zeolite`.

## License

MIT. See [LICENSE](LICENSE).
