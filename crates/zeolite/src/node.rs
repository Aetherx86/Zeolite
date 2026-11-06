//! A cluster node: the consensus driver thread, durable storage and the state machine.
//!
//! All consensus work happens on one dedicated thread, which keeps the driver contract
//! from `zeolite_raft::core` easy to uphold: persist, then send, then apply.

use crate::state::{Command, Output, State};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc as async_mpsc, oneshot};
use zeolite_raft::{
    Config, Envelope, Index, NodeId, ProposeError, Raft, Ready, Role, Storage, Term, Transport,
    TransportConfig,
};

#[derive(Clone)]
pub struct NodeConfig {
    pub id: NodeId,
    pub peers: BTreeMap<NodeId, String>,
    pub data_dir: PathBuf,
    pub cluster_key: [u8; 32],
    pub tick: Duration,
    pub election_ticks: u32,
    pub heartbeat_ticks: u32,
    /// Take a snapshot after this many applied entries.
    pub snapshot_every: u64,
}

impl NodeConfig {
    pub fn new(
        id: NodeId,
        peers: BTreeMap<NodeId, String>,
        data_dir: PathBuf,
        cluster_key: [u8; 32],
    ) -> Self {
        NodeConfig {
            id,
            peers,
            data_dir,
            cluster_key,
            tick: Duration::from_millis(50),
            election_ticks: 10,
            heartbeat_ticks: 2,
            snapshot_every: 1000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposeFailure {
    /// This node cannot take writes. The hint names the leader when it is known.
    NotLeader {
        leader: Option<NodeId>,
    },
    /// Leadership changed before the entry was applied, so its outcome is unknown. It may
    /// still commit. Commands are not deduplicated, so a blind retry can apply twice.
    Unknown,
    Encoding(String),
    Stopped,
}

impl std::fmt::Display for ProposeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposeFailure::NotLeader { leader: Some(id) } => {
                write!(f, "not the leader; node {id} is")
            }
            ProposeFailure::NotLeader { leader: None } => {
                write!(f, "not the leader, and no leader is known")
            }
            ProposeFailure::Unknown => write!(f, "leadership changed; the outcome is unknown"),
            ProposeFailure::Encoding(e) => write!(f, "could not encode the command: {e}"),
            ProposeFailure::Stopped => write!(f, "the node is stopping"),
        }
    }
}

impl std::error::Error for ProposeFailure {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub id: NodeId,
    pub role: Role,
    pub term: Term,
    pub leader: Option<NodeId>,
    pub commit: Index,
    pub applied: Index,
    pub last_index: Index,
    pub snapshot_index: Index,
}

type ProposeReply = oneshot::Sender<Result<Output, ProposeFailure>>;

enum Input {
    Message(Envelope),
    Propose(Vec<u8>, ProposeReply),
    Status(oneshot::Sender<Status>),
    Stop,
}

/// Handle to a running node. Dropping it stops the node.
pub struct Node {
    id: NodeId,
    inbox: mpsc::Sender<Input>,
    state: Arc<RwLock<State>>,
    thread: Option<JoinHandle<io::Result<()>>>,
    forwarder: tokio::task::JoinHandle<()>,
    _transport: Arc<Transport>,
    raft_addr: std::net::SocketAddr,
}

impl Node {
    /// Starts a node. Must be called from inside a Tokio runtime.
    pub fn start(cfg: NodeConfig, listener: TcpListener) -> io::Result<Node> {
        let (storage, recovered) = Storage::open(&cfg.data_dir)?;
        let state = match &recovered.snapshot {
            Some(snapshot) => State::decode(&snapshot.data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            None => State::default(),
        };
        let state = Arc::new(RwLock::new(state));

        let mut raft_cfg = Config::new(cfg.id, cfg.peers.keys().copied().collect());
        raft_cfg.election_ticks = cfg.election_ticks;
        raft_cfg.heartbeat_ticks = cfg.heartbeat_ticks;
        let raft = Raft::new(raft_cfg, recovered);

        let (net_tx, mut net_rx) = async_mpsc::channel::<Envelope>(4096);
        let raft_addr = listener.local_addr()?;
        let transport = Arc::new(Transport::start(
            TransportConfig::new(cfg.id, cfg.peers.clone(), cfg.cluster_key),
            listener,
            net_tx,
        )?);

        let (inbox, rx) = mpsc::channel();
        let forward = inbox.clone();
        let forwarder = tokio::spawn(async move {
            while let Some(env) = net_rx.recv().await {
                if forward.send(Input::Message(env)).is_err() {
                    return;
                }
            }
        });

        let driver = Driver {
            raft,
            storage,
            state: state.clone(),
            transport: transport.clone(),
            pending: HashMap::new(),
            applied_since_snapshot: 0,
            snapshot_every: cfg.snapshot_every,
            was_leader: false,
        };
        let tick = cfg.tick;
        let thread = std::thread::Builder::new()
            .name(format!("zeolite-raft-{}", cfg.id))
            .stack_size(4 << 20)
            .spawn(move || driver.run(rx, tick))?;

        Ok(Node {
            id: cfg.id,
            inbox,
            state,
            thread: Some(thread),
            forwarder,
            _transport: transport,
            raft_addr,
        })
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn raft_addr(&self) -> std::net::SocketAddr {
        self.raft_addr
    }

    /// Replicates a command and waits for it to be applied here.
    pub async fn propose(&self, command: &Command) -> Result<Output, ProposeFailure> {
        let data =
            postcard::to_allocvec(command).map_err(|e| ProposeFailure::Encoding(e.to_string()))?;
        let (tx, rx) = oneshot::channel();
        self.inbox
            .send(Input::Propose(data, tx))
            .map_err(|_| ProposeFailure::Stopped)?;
        rx.await.map_err(|_| ProposeFailure::Stopped)?
    }

    pub async fn status(&self) -> Option<Status> {
        let (tx, rx) = oneshot::channel();
        self.inbox.send(Input::Status(tx)).ok()?;
        rx.await.ok()
    }

    /// Read access to the local replica of the state machine.
    pub fn state(&self) -> Arc<RwLock<State>> {
        self.state.clone()
    }

    /// Stops the node and waits for its consensus thread to finish.
    pub fn stop(mut self) -> io::Result<()> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> io::Result<()> {
        let _ = self.inbox.send(Input::Stop);
        self.forwarder.abort();
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("the consensus thread panicked"))),
            None => Ok(()),
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

struct Driver {
    raft: Raft,
    storage: Storage,
    state: Arc<RwLock<State>>,
    transport: Arc<Transport>,
    pending: HashMap<Index, (Term, ProposeReply)>,
    applied_since_snapshot: u64,
    snapshot_every: u64,
    was_leader: bool,
}

impl Driver {
    fn run(mut self, rx: mpsc::Receiver<Input>, tick: Duration) -> io::Result<()> {
        const MAX_BATCH: usize = 512;
        let mut next_tick = Instant::now() + tick;
        loop {
            let wait = next_tick.saturating_duration_since(Instant::now());
            match rx.recv_timeout(wait) {
                Ok(input) => {
                    if self.handle(input) {
                        return Ok(());
                    }
                    // Group whatever else is queued, so that one fsync covers many entries.
                    for _ in 0..MAX_BATCH {
                        match rx.try_recv() {
                            Ok(input) => {
                                if self.handle(input) {
                                    return Ok(());
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            }
            let now = Instant::now();
            if now >= next_tick {
                self.raft.tick();
                next_tick = now + tick;
            }
            self.drain()?;
        }
    }

    /// Returns true when the node should stop.
    fn handle(&mut self, input: Input) -> bool {
        match input {
            Input::Message(env) => self.raft.step(env.from, env.msg),
            Input::Propose(data, reply) => match self.raft.propose(data) {
                Ok(index) => {
                    self.pending.insert(index, (self.raft.term(), reply));
                }
                Err(ProposeError::NotLeader { leader }) => {
                    let _ = reply.send(Err(ProposeFailure::NotLeader { leader }));
                }
            },
            Input::Status(reply) => {
                let _ = reply.send(Status {
                    id: self.raft.id(),
                    role: self.raft.role(),
                    term: self.raft.term(),
                    leader: self.raft.leader(),
                    commit: self.raft.commit_index(),
                    applied: self.raft.applied_index(),
                    last_index: self.raft.last_index(),
                    snapshot_index: self.raft.snapshot_index(),
                });
            }
            Input::Stop => return true,
        }
        false
    }

    fn drain(&mut self) -> io::Result<()> {
        while self.raft.has_ready() {
            let ready = self.raft.take_ready();
            self.process(ready)?;
        }
        // Proposals from a term this node no longer leads have an unknown fate.
        let leading = self.raft.role() == Role::Leader;
        if self.was_leader && !leading {
            for (_, (_, reply)) in self.pending.drain() {
                let _ = reply.send(Err(ProposeFailure::Unknown));
            }
        }
        self.was_leader = leading;
        Ok(())
    }

    fn process(&mut self, ready: Ready) -> io::Result<()> {
        // A storage failure is fatal: continuing could acknowledge data that is not
        // durable, which would break the protocol's safety argument.
        self.storage.persist(&ready)?;

        for env in ready.messages {
            self.transport.send(env);
        }

        if let Some(snapshot) = &ready.install_snapshot {
            let restored = State::decode(&snapshot.data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            *self.state.write().unwrap_or_else(|e| e.into_inner()) = restored;
        }

        for entry in ready.committed {
            // Empty entries are the no-ops that new leaders append.
            let output = if entry.data.is_empty() {
                None
            } else {
                Some(match postcard::from_bytes::<Command>(&entry.data) {
                    Ok(command) => self
                        .state
                        .write()
                        .unwrap_or_else(|e| e.into_inner())
                        .apply(command),
                    // Every replica sees the same bytes and fails the same way.
                    Err(e) => Output::Rejected(format!("undecodable command: {e}")),
                })
            };
            self.applied_since_snapshot += 1;

            if let Some((term, reply)) = self.pending.remove(&entry.index) {
                let result = match output {
                    Some(output) if term == entry.term => Ok(output),
                    // A different leader overwrote this index with its own entry.
                    _ => Err(ProposeFailure::Unknown),
                };
                let _ = reply.send(result);
            }
        }

        if self.applied_since_snapshot >= self.snapshot_every {
            self.take_snapshot()?;
        }
        Ok(())
    }

    fn take_snapshot(&mut self) -> io::Result<()> {
        let index = self.raft.applied_index();
        let data = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .encode();
        if let Ok(snapshot) = self.raft.compact(index, data) {
            self.storage
                .save_snapshot(&snapshot, self.raft.log(), self.raft.hard_state())?;
            self.applied_since_snapshot = 0;
        }
        Ok(())
    }
}
