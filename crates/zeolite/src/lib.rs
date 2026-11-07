//! Distributed execution node: a Raft-replicated state machine that deploys and runs
//! sandboxed workloads, exposed through an HTTP gateway.

pub mod http;
pub mod node;
pub mod state;
