# Zeolite

A distributed runtime for sandboxed workloads. A cluster of nodes agrees on what is
deployed through Raft, then runs each workload in one of three isolation tiers: a
deterministic JIT, a metered WebAssembly sandbox, or a hardware-virtualized micro-VM.

Zeolites are crystals full of tiny isolated cages, which is the idea here: many small,
walled-off workloads inside one solid structure.

```text
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
| --- | --- | --- | --- |
| Zel | Bounds checks and gas, on both backends | Replicated on every node | Deterministic state machines |
| Wasm | WebAssembly sandbox, a fresh instance per request | None between requests | Webhooks and stateless functions |
| Micro-VM | Hardware virtualization | None between boots | Untrusted native code and whole kernels |

## Crates

**`zeolite-raft`** is consensus, written from scratch. The protocol core is sans-IO: it
never touches a clock, a disk or a socket, which is what makes it possible to test it
deterministically. It implements elections with pre-vote, check-quorum, log replication,
log compaction through snapshots, and leadership transfer. Around the core are a checksummed write-ahead log
that recovers from torn writes, and a transport where every frame is encrypted and
authenticated (ChaCha20-Poly1305, with per-direction keys derived from a pre-shared
cluster key and fresh nonces).

**`zeolite-jit`** compiles Zel, a small statement language over `i64`, to a register IR
and then to native code through Cranelift. A reference interpreter runs the same IR. The
two backends must agree exactly on results, gas used and memory contents, even for
programs that trap. That property lets replicas execute a command independently and
still reach the same state. Generated code never relies on signals: gas, bounds, division
and recursion are all checked explicitly, so a guest fault cannot take down the host.

```text
fn add(n) { let v = load(0) + n; store(0, v); return v; }
```

**`zeolite-vmm`** is a virtual machine monitor written directly against the hypervisor
interfaces, with no VMM libraries.

| Host | Backend | Guests |
| --- | --- | --- |
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
| --- | --- | --- |
| `GET /v1/status` | Role, term, leader and log positions | None |
| `GET /v1/digest` | SHA-256 of the replicated state | None |
| `POST /v1/leadership/transfer` | Hand leadership to another node | Token |
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

## Leadership transfer, offline inspection and backend comparison

Added in 0.2.0. Every command below was run against a local three-node cluster started
as in the quick start.

### Moving leadership

Before taking the leader down for maintenance, hand leadership to another node:

```sh
curl -H "$AUTH" -X POST "$LEADER/v1/leadership/transfer" -d '{"to":2}'
# {"leader":2,"leader_http":"127.0.0.1:8002","status":"transferred","term":2}
```

The leader stops accepting writes, brings node 2's log up to date, then tells it to start
an election immediately. The request returns once this node sees node 2 lead, normally
one term later. `timeout_ms` in the body bounds the wait (default 5000, at most 60000).
If the target has not taken over within one election timeout, the transfer is dropped
and the old leader resumes taking writes. While a transfer is in flight, the leader
answers writes with status 421 naming the target. Once it has handed off, it answers
writes and transfer requests with 421 naming the new leader:

```sh
curl -H "$AUTH" -X POST "$LEADER/v1/leadership/transfer" -d '{"to":3}'
# {"error":"this node is not the leader","leader":2,"leader_http":"127.0.0.1:8002"}
```

All nodes must run 0.2.0 or later, because the hand-off uses a new consensus message.

### Inspecting a data directory

`zeolite inspect` reads a node's data directory without changing it, so it is safe on a
stopped node, or on a copy of a running node's directory. It shows what the node would
recover, and replays the committed log onto the snapshot to compute the state digest at
the stored commit index:

```sh
$Z inspect data/1
# wal         514 bytes (514 valid, 0 torn)
# records     7 hard state, 0 truncate, 5 entry
# hard state  term 2, voted for 2, commit 5
# snapshot    none
# log         1..=5 (5 usable, 0 discarded)
# commit      5
# commands    1 deploy_zel, 2 execute, 2 noop
# state       applied 5, 1 workloads, digest c8bd238c...
$Z inspect data/2 --json
```

Replicas stopped at the same commit index report the same digest, and it is the digest
`/v1/digest` returned while they ran. Torn bytes are what a crash left at the tail of the
log, which the node truncates when it next starts. The command exits non-zero when the
snapshot is corrupt or its state does not decode, which are the cases where a node
refuses to start.

### Running Zel with JSON output, or on both backends

```sh
$Z zel program.zel --call add --args 2,-5 --json
# {"backend":"jit","function":"add","gas_used":7,"memory_sha256":"2a97...","result":-3}
$Z zel program.zel --call div --args 1,0 --json
# {"backend":"jit","function":"div","gas_used":3,"memory_sha256":"de2f...","trap":"division by zero"}
$Z zel program.zel --call add --args 40,2 --compare
# interpreter  42 (gas used 7)
# jit          42 (gas used 7)
```

With `--json`, a trap is reported in the output and the exit status is 0. Without it, a
trap is an error exit as before. `--compare` runs the call on the interpreter and the JIT,
each against its own copy of memory, and exits non-zero unless the result, the gas used
and the final memory all agree. Add `--json` to get both outcomes and an `agree` field.

## How it is tested

The goal is tests that can fail, so several were checked by deliberately breaking the code.

- **Raft** runs in a deterministic simulator with message loss, duplication, reordering,
  partitions, crashes, compaction and leadership transfers across hundreds of seeded
  runs, checking Election
  Safety, Log Matching, Leader Completeness and State Machine Safety throughout. Directed
  tests cover scenarios chaos rarely reaches, such as Figure 8 of the Raft paper.
- **The JIT** is differentially tested against the interpreter on randomly generated
  programs, comparing results, gas and final memory. The test fails if the generator stops
  producing a variety of outcomes. A property test checks that metering is exact on both:
  a call given exactly the gas it used repeats its outcome, and one unit less runs out.
- **Mutation checks**: known bugs were injected into the Raft core and the JIT, such as an
  off-by-one quorum, double voting, signed bounds checks and dropped callee traps. Each one
  made the suite fail. Mutants that initially survived led to new tests.
- **The VMM** boots real guests. CI boots a real Linux kernel to userspace under KVM with a
  small static init. The virtio stack is driven through its registers and rings with hostile
  input, on every platform.
- **The cluster** tests run real nodes with real sockets and fsync, including leader
  failure, full restarts, catching up through snapshots and leadership transfer.
- **The command line** is tested by running the built binary, including a check that
  `inspect` leaves a data directory byte for byte unchanged.

## Measured

On an Apple Silicon laptop, in a debug build:

| Operation | Time |
| --- | --- |
| Wasm instance creation, median | 16 microseconds |
| Micro-VM, boot to halt with a small AArch64 payload | About 60 microseconds |

On a GitHub Actions runner, under nested virtualization:

| Operation | Time |
| --- | --- |
| Unmodified Linux 7.0 distribution kernel, boot to its first userspace process and reboot | About 4.4 seconds |

## Versioning

A bug or security fix increments `0.0.X`. New functionality or new platform support
increments `0.X.0`. See [CHANGELOG.md](CHANGELOG.md). Each tag publishes binaries to GitHub
Releases and a container image to `ghcr.io/aetherx86/zeolite`.

CI runs `cargo audit`. It reports no vulnerabilities. One unmaintained crate that arrives
through wasmtime is accepted, with its reason, in `.cargo/audit.toml`. Nine unsoundness
warnings for `heapless` 0.7, which arrives through `postcard`, are still reported.

## Limitations

- **Hypervisor host platforms**: Hardware-accelerated microVMs require KVM on Linux (`x86_64` / `aarch64`) or `Hypervisor.framework` on macOS (`Apple Silicon` with the `com.apple.security.hypervisor` entitlement).
- **Zel JIT target**: The Cranelift-backed native JIT targets 64-bit host architectures; unsupported hosts fall back automatically to the deterministic bytecode interpreter.
- **Cluster membership changes**: Raft membership is configured statically at node startup; dynamic joint-consensus membership reconfiguration is outside the current scope.

## License

MIT. See [LICENSE](LICENSE).
