//! Raft consensus: a sans-IO protocol core, a durable log, and an encrypted transport.
//!
//! The core implements leader election with pre-vote, check-quorum, log replication,
//! and snapshot-based log compaction. Cluster membership is static.

pub mod codec;
pub mod core;
pub mod storage;
pub mod transport;

pub use crate::core::{
    CompactError, Config, Entry, Envelope, HardState, Index, Message, NodeId, ProposeError, Raft,
    Ready, Recovered, Role, Snapshot, Term,
};
pub use crate::storage::Storage;
pub use crate::transport::{Transport, TransportConfig};
