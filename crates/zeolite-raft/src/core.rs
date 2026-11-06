//! Sans-IO Raft state machine.
//!
//! This module performs no I/O and reads no clock. The driver feeds it ticks and
//! inbound messages, then drains a [`Ready`] batch and must process it in order:
//!
//! 1. Persist `install_snapshot`, then `truncate_from` + `entries`, then `hard_state`.
//! 2. Flush to stable storage.
//! 3. Send `messages`.
//! 4. Restore the state machine from `install_snapshot`, then apply `committed`.
//!
//! Sending only after the flush is what makes the protocol's durability assumptions
//! hold: a vote or an append acknowledgement is never visible to a peer before it
//! would survive a crash.

use std::collections::BTreeMap;

pub type NodeId = u64;
pub type Term = u64;
pub type Index = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub term: Term,
    pub index: Index,
    /// Application payload. Empty data marks the no-op a new leader appends.
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HardState {
    pub term: Term,
    pub voted_for: Option<NodeId>,
    pub commit: Index,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub last_index: Index,
    pub last_term: Term,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    PreVote {
        term: Term,
        last_index: Index,
        last_term: Term,
    },
    PreVoteResp {
        term: Term,
        granted: bool,
    },
    Vote {
        term: Term,
        last_index: Index,
        last_term: Term,
    },
    VoteResp {
        term: Term,
        granted: bool,
    },
    Append {
        term: Term,
        prev_index: Index,
        prev_term: Term,
        entries: Vec<Entry>,
        commit: Index,
    },
    AppendResp {
        term: Term,
        success: bool,
        match_index: Index,
        hint: Index,
    },
    Snapshot {
        term: Term,
        snapshot: Snapshot,
    },
    SnapshotResp {
        term: Term,
        index: Index,
    },
}

impl Message {
    pub fn term(&self) -> Term {
        match self {
            Message::PreVote { term, .. }
            | Message::PreVoteResp { term, .. }
            | Message::Vote { term, .. }
            | Message::VoteResp { term, .. }
            | Message::Append { term, .. }
            | Message::AppendResp { term, .. }
            | Message::Snapshot { term, .. }
            | Message::SnapshotResp { term, .. } => *term,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub from: NodeId,
    pub to: NodeId,
    pub msg: Message,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub id: NodeId,
    /// Every other member of the cluster. Must not contain `id`.
    pub peers: Vec<NodeId>,
    /// Base election timeout in ticks. The effective timeout is randomized in
    /// `[election_ticks, 2 * election_ticks)`.
    pub election_ticks: u32,
    pub heartbeat_ticks: u32,
    pub max_entries_per_append: usize,
    pub max_bytes_per_append: usize,
    /// Seeds the election jitter, which keeps simulations reproducible.
    pub seed: u64,
}

impl Config {
    pub fn new(id: NodeId, peers: Vec<NodeId>) -> Self {
        Config {
            id,
            peers,
            election_ticks: 10,
            heartbeat_ticks: 2,
            max_entries_per_append: 256,
            max_bytes_per_append: 1 << 20,
            seed: id.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5851_F42D_4C95_7F2D,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Recovered {
    pub hard_state: HardState,
    pub snapshot: Option<Snapshot>,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Follower,
    PreCandidate,
    Candidate,
    Leader,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposeError {
    NotLeader { leader: Option<NodeId> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompactError {
    /// The index has not been applied yet, so a snapshot at it would be unsafe.
    NotApplied,
    /// The index is already covered by the current snapshot.
    AlreadyCompacted,
}

#[derive(Debug, Default)]
pub struct Ready {
    pub hard_state: Option<HardState>,
    pub install_snapshot: Option<Snapshot>,
    pub truncate_from: Option<Index>,
    pub entries: Vec<Entry>,
    pub messages: Vec<Envelope>,
    pub committed: Vec<Entry>,
}

impl Ready {
    pub fn is_empty(&self) -> bool {
        self.hard_state.is_none()
            && self.install_snapshot.is_none()
            && self.truncate_from.is_none()
            && self.entries.is_empty()
            && self.messages.is_empty()
            && self.committed.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Progress {
    next: Index,
    matched: Index,
    active: bool,
}

pub struct Raft {
    cfg: Config,
    term: Term,
    voted_for: Option<NodeId>,
    commit: Index,
    applied: Index,

    log: Vec<Entry>,
    snap_index: Index,
    snap_term: Term,
    snapshot: Option<Snapshot>,

    role: Role,
    leader: Option<NodeId>,
    elapsed: u32,
    timeout: u32,
    heartbeat_elapsed: u32,
    quorum_elapsed: u32,
    votes: BTreeMap<NodeId, bool>,
    progress: BTreeMap<NodeId, Progress>,

    rng: u64,
    outbox: Vec<Envelope>,
    hs_dirty: bool,
    dirty_from: Option<Index>,
    force_truncate: Option<Index>,
    stable_last: Index,
    pending_restore: Option<Snapshot>,
}

impl Raft {
    pub fn new(cfg: Config, recovered: Recovered) -> Self {
        assert!(
            !cfg.peers.contains(&cfg.id),
            "peers must not contain this node's own id"
        );
        assert!(
            cfg.election_ticks > cfg.heartbeat_ticks && cfg.heartbeat_ticks > 0,
            "election timeout must exceed the heartbeat interval"
        );
        let (snap_index, snap_term) = recovered
            .snapshot
            .as_ref()
            .map_or((0, 0), |s| (s.last_index, s.last_term));

        // Entries at or below the snapshot are dead. Anything non-contiguous cannot
        // be trusted as a log suffix, so it is discarded rather than guessed at.
        let mut log: Vec<Entry> = Vec::with_capacity(recovered.entries.len());
        for e in recovered.entries {
            if e.index <= snap_index {
                continue;
            }
            if e.index != snap_index + log.len() as u64 + 1 {
                break;
            }
            log.push(e);
        }
        let last = snap_index + log.len() as u64;
        let commit = recovered.hard_state.commit.clamp(snap_index, last);
        let seed = cfg.seed | 1;
        let mut raft = Raft {
            term: recovered.hard_state.term,
            voted_for: recovered.hard_state.voted_for,
            commit,
            applied: snap_index,
            log,
            snap_index,
            snap_term,
            snapshot: recovered.snapshot,
            role: Role::Follower,
            leader: None,
            elapsed: 0,
            timeout: 0,
            heartbeat_elapsed: 0,
            quorum_elapsed: 0,
            votes: BTreeMap::new(),
            progress: BTreeMap::new(),
            rng: seed,
            outbox: Vec::new(),
            hs_dirty: false,
            dirty_from: None,
            force_truncate: None,
            stable_last: last,
            pending_restore: None,
            cfg,
        };
        raft.reset_timeout();
        raft
    }

    pub fn id(&self) -> NodeId {
        self.cfg.id
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn term(&self) -> Term {
        self.term
    }

    pub fn leader(&self) -> Option<NodeId> {
        self.leader
    }

    pub fn commit_index(&self) -> Index {
        self.commit
    }

    pub fn applied_index(&self) -> Index {
        self.applied
    }

    pub fn last_index(&self) -> Index {
        self.snap_index + self.log.len() as u64
    }

    pub fn last_term(&self) -> Term {
        self.log.last().map_or(self.snap_term, |e| e.term)
    }

    pub fn snapshot_index(&self) -> Index {
        self.snap_index
    }

    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /// Entries still held in memory, in index order.
    pub fn log(&self) -> &[Entry] {
        &self.log
    }

    pub fn hard_state(&self) -> HardState {
        HardState {
            term: self.term,
            voted_for: self.voted_for,
            commit: self.commit,
        }
    }

    pub fn term_at(&self, index: Index) -> Option<Term> {
        if index == self.snap_index {
            return Some(self.snap_term);
        }
        if index < self.snap_index || index > self.last_index() {
            return None;
        }
        Some(self.log[(index - self.snap_index - 1) as usize].term)
    }

    fn quorum(&self) -> usize {
        self.cfg.peers.len().div_ceil(2) + 1
    }

    fn next_random(&mut self) -> u64 {
        // xorshift64*: cheap, deterministic, and only used for election jitter.
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn reset_timeout(&mut self) {
        let base = self.cfg.election_ticks;
        self.timeout = base + (self.next_random() % u64::from(base)) as u32;
        self.elapsed = 0;
    }

    fn send(&mut self, to: NodeId, msg: Message) {
        self.outbox.push(Envelope {
            from: self.cfg.id,
            to,
            msg,
        });
    }

    fn set_term(&mut self, term: Term) {
        if term != self.term {
            self.term = term;
            self.voted_for = None;
            self.hs_dirty = true;
        }
    }

    fn become_follower(&mut self, term: Term, leader: Option<NodeId>) {
        self.set_term(term);
        self.role = Role::Follower;
        self.leader = leader;
        self.votes.clear();
        self.progress.clear();
        self.reset_timeout();
    }

    fn up_to_date(&self, last_index: Index, last_term: Term) -> bool {
        (last_term, last_index) >= (self.last_term(), self.last_index())
    }

    fn leader_is_live(&self) -> bool {
        self.role == Role::Leader
            || (self.leader.is_some() && self.elapsed < self.cfg.election_ticks)
    }

    /// Advances logical time by one tick.
    pub fn tick(&mut self) {
        match self.role {
            Role::Leader => {
                self.heartbeat_elapsed += 1;
                self.quorum_elapsed += 1;
                if self.quorum_elapsed >= self.cfg.election_ticks {
                    self.quorum_elapsed = 0;
                    // Check-quorum: a leader cut off from a majority must stop acting
                    // as leader, or followers that can still reach it would refuse
                    // pre-votes forever.
                    let active = self.progress.values().filter(|p| p.active).count() + 1;
                    if active < self.quorum() {
                        let term = self.term;
                        self.become_follower(term, None);
                        return;
                    }
                    for p in self.progress.values_mut() {
                        p.active = false;
                    }
                }
                if self.heartbeat_elapsed >= self.cfg.heartbeat_ticks {
                    self.heartbeat_elapsed = 0;
                    self.broadcast_append();
                }
            }
            _ => {
                self.elapsed += 1;
                if self.elapsed >= self.timeout {
                    self.start_pre_vote();
                }
            }
        }
    }

    fn start_pre_vote(&mut self) {
        self.role = Role::PreCandidate;
        self.leader = None;
        self.votes.clear();
        self.votes.insert(self.cfg.id, true);
        self.reset_timeout();
        if self.votes_granted() >= self.quorum() {
            self.start_election();
            return;
        }
        let (term, last_index, last_term) = (self.term + 1, self.last_index(), self.last_term());
        for peer in self.cfg.peers.clone() {
            self.send(
                peer,
                Message::PreVote {
                    term,
                    last_index,
                    last_term,
                },
            );
        }
    }

    fn start_election(&mut self) {
        self.role = Role::Candidate;
        self.leader = None;
        self.set_term(self.term + 1);
        self.voted_for = Some(self.cfg.id);
        self.hs_dirty = true;
        self.votes.clear();
        self.votes.insert(self.cfg.id, true);
        self.reset_timeout();
        if self.votes_granted() >= self.quorum() {
            self.become_leader();
            return;
        }
        let (term, last_index, last_term) = (self.term, self.last_index(), self.last_term());
        for peer in self.cfg.peers.clone() {
            self.send(
                peer,
                Message::Vote {
                    term,
                    last_index,
                    last_term,
                },
            );
        }
    }

    fn votes_granted(&self) -> usize {
        self.votes.values().filter(|g| **g).count()
    }

    fn votes_rejected(&self) -> usize {
        self.votes.values().filter(|g| !**g).count()
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.leader = Some(self.cfg.id);
        self.heartbeat_elapsed = 0;
        self.quorum_elapsed = 0;
        let next = self.last_index() + 1;
        self.progress = self
            .cfg
            .peers
            .iter()
            .map(|p| {
                (
                    *p,
                    Progress {
                        next,
                        matched: 0,
                        active: false,
                    },
                )
            })
            .collect();
        // Entries from earlier terms can only commit once an entry from the current
        // term commits, so a new leader immediately appends a no-op.
        self.append_local(Vec::new());
        self.broadcast_append();
        self.maybe_commit();
    }

    fn append_local(&mut self, data: Vec<u8>) -> Index {
        let index = self.last_index() + 1;
        self.dirty_from.get_or_insert(index);
        self.log.push(Entry {
            term: self.term,
            index,
            data,
        });
        index
    }

    /// Appends `data` to the leader's log and returns its index. The entry is not
    /// committed until a later [`Ready`] lists it under `committed`.
    pub fn propose(&mut self, data: Vec<u8>) -> Result<Index, ProposeError> {
        if self.role != Role::Leader {
            return Err(ProposeError::NotLeader {
                leader: self.leader,
            });
        }
        let index = self.append_local(data);
        let caught_up: Vec<NodeId> = self
            .progress
            .iter()
            .filter(|(_, p)| p.next == index)
            .map(|(id, _)| *id)
            .collect();
        for peer in caught_up {
            self.send_append(peer);
        }
        self.maybe_commit();
        Ok(index)
    }

    fn broadcast_append(&mut self) {
        for peer in self.cfg.peers.clone() {
            self.send_append(peer);
        }
    }

    fn send_append(&mut self, peer: NodeId) {
        let Some(progress) = self.progress.get(&peer).copied() else {
            return;
        };
        if progress.next <= self.snap_index {
            let Some(snapshot) = self.snapshot.clone() else {
                return;
            };
            let next = snapshot.last_index + 1;
            if let Some(p) = self.progress.get_mut(&peer) {
                p.next = next;
            }
            let term = self.term;
            self.send(peer, Message::Snapshot { term, snapshot });
            return;
        }

        let prev_index = progress.next - 1;
        let Some(prev_term) = self.term_at(prev_index) else {
            return;
        };
        let start = (progress.next - self.snap_index - 1) as usize;
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        for e in self.log.iter().skip(start) {
            if entries.len() >= self.cfg.max_entries_per_append {
                break;
            }
            // Always make progress: a single oversized entry still goes out alone.
            if !entries.is_empty() && bytes + e.data.len() > self.cfg.max_bytes_per_append {
                break;
            }
            bytes += e.data.len();
            entries.push(e.clone());
        }
        if let Some(p) = self.progress.get_mut(&peer) {
            // Optimistic pipelining. A lost message surfaces as a rejected heartbeat,
            // whose hint rewinds `next`.
            p.next += entries.len() as u64;
        }
        let (term, commit) = (self.term, self.commit);
        self.send(
            peer,
            Message::Append {
                term,
                prev_index,
                prev_term,
                entries,
                commit,
            },
        );
    }

    fn maybe_commit(&mut self) -> bool {
        if self.role != Role::Leader {
            return false;
        }
        let mut matches: Vec<Index> = self.progress.values().map(|p| p.matched).collect();
        matches.push(self.last_index());
        matches.sort_unstable_by(|a, b| b.cmp(a));
        let candidate = matches[self.quorum() - 1];
        // Figure 8 of the Raft paper: only entries from the current term may be
        // committed by counting replicas.
        if candidate > self.commit && self.term_at(candidate) == Some(self.term) {
            self.commit = candidate;
            self.hs_dirty = true;
            return true;
        }
        false
    }

    /// Handles one inbound message.
    pub fn step(&mut self, from: NodeId, msg: Message) {
        if from == self.cfg.id || !self.cfg.peers.contains(&from) {
            return;
        }
        match msg {
            Message::PreVote {
                term,
                last_index,
                last_term,
            } => {
                let granted = term > self.term
                    && self.up_to_date(last_index, last_term)
                    && !self.leader_is_live();
                let reply_term = if granted { term } else { self.term };
                self.send(
                    from,
                    Message::PreVoteResp {
                        term: reply_term,
                        granted,
                    },
                );
                return;
            }
            Message::PreVoteResp { term, granted } => {
                if granted {
                    if self.role == Role::PreCandidate && term == self.term + 1 {
                        self.votes.insert(from, true);
                        if self.votes_granted() >= self.quorum() {
                            self.start_election();
                        }
                    }
                } else if term > self.term {
                    self.become_follower(term, None);
                } else if self.role == Role::PreCandidate {
                    self.votes.insert(from, false);
                    if self.votes_rejected() >= self.quorum() {
                        let current = self.term;
                        self.become_follower(current, None);
                    }
                }
                return;
            }
            _ => {}
        }

        let msg_term = msg.term();
        if msg_term > self.term {
            let leader =
                matches!(msg, Message::Append { .. } | Message::Snapshot { .. }).then_some(from);
            self.become_follower(msg_term, leader);
        } else if msg_term < self.term {
            // Tell stale leaders and candidates about the newer term.
            match msg {
                Message::Append { .. } => {
                    let term = self.term;
                    let hint = self.last_index() + 1;
                    self.send(
                        from,
                        Message::AppendResp {
                            term,
                            success: false,
                            match_index: 0,
                            hint,
                        },
                    );
                }
                Message::Vote { .. } => {
                    let term = self.term;
                    self.send(
                        from,
                        Message::VoteResp {
                            term,
                            granted: false,
                        },
                    );
                }
                Message::Snapshot { .. } => {
                    let term = self.term;
                    let index = self.commit;
                    self.send(from, Message::SnapshotResp { term, index });
                }
                _ => {}
            }
            return;
        }

        match msg {
            Message::Vote {
                last_index,
                last_term,
                ..
            } => self.handle_vote(from, last_index, last_term),
            Message::VoteResp { granted, .. } => self.handle_vote_resp(from, granted),
            Message::Append {
                prev_index,
                prev_term,
                entries,
                commit,
                ..
            } => self.handle_append(from, prev_index, prev_term, entries, commit),
            Message::AppendResp {
                success,
                match_index,
                hint,
                ..
            } => self.handle_append_resp(from, success, match_index, hint),
            Message::Snapshot { snapshot, .. } => self.handle_snapshot(from, snapshot),
            Message::SnapshotResp { index, .. } => self.handle_snapshot_resp(from, index),
            Message::PreVote { .. } | Message::PreVoteResp { .. } => {}
        }
    }

    fn handle_vote(&mut self, from: NodeId, last_index: Index, last_term: Term) {
        let can_vote = self.voted_for.is_none() || self.voted_for == Some(from);
        let granted =
            can_vote && self.role != Role::Leader && self.up_to_date(last_index, last_term);
        if granted {
            self.voted_for = Some(from);
            self.hs_dirty = true;
            self.reset_timeout();
        }
        let term = self.term;
        self.send(from, Message::VoteResp { term, granted });
    }

    fn handle_vote_resp(&mut self, from: NodeId, granted: bool) {
        if self.role != Role::Candidate {
            return;
        }
        self.votes.insert(from, granted);
        if self.votes_granted() >= self.quorum() {
            self.become_leader();
        } else if self.votes_rejected() >= self.quorum() {
            let term = self.term;
            self.become_follower(term, None);
        }
    }

    fn accept_leader(&mut self, from: NodeId) {
        if self.role != Role::Follower {
            let term = self.term;
            self.become_follower(term, Some(from));
        } else {
            self.leader = Some(from);
            self.reset_timeout();
        }
    }

    fn handle_append(
        &mut self,
        from: NodeId,
        mut prev_index: Index,
        mut prev_term: Term,
        mut entries: Vec<Entry>,
        leader_commit: Index,
    ) {
        self.accept_leader(from);
        let term = self.term;

        // Everything at or below the snapshot is committed, so it cannot conflict.
        if prev_index < self.snap_index {
            entries.retain(|e| e.index > self.snap_index);
            prev_index = self.snap_index;
            prev_term = self.snap_term;
        }

        if prev_index > self.last_index() {
            let hint = self.last_index() + 1;
            self.send(
                from,
                Message::AppendResp {
                    term,
                    success: false,
                    match_index: 0,
                    hint,
                },
            );
            return;
        }

        let local_term = self.term_at(prev_index);
        if local_term != Some(prev_term) {
            // Skip back over the entire conflicting term in one round trip.
            let conflict = local_term.unwrap_or(0);
            let mut hint = prev_index;
            while hint > self.snap_index + 1 && self.term_at(hint - 1) == Some(conflict) {
                hint -= 1;
            }
            self.send(
                from,
                Message::AppendResp {
                    term,
                    success: false,
                    match_index: 0,
                    hint,
                },
            );
            return;
        }

        let match_index = prev_index + entries.len() as u64;
        for e in entries {
            if e.index <= self.last_index() {
                if self.term_at(e.index) == Some(e.term) {
                    continue;
                }
                assert!(
                    e.index > self.commit,
                    "raft safety violation: truncating committed entry {} (commit {})",
                    e.index,
                    self.commit
                );
                self.log.truncate((e.index - self.snap_index - 1) as usize);
                self.dirty_from = Some(self.dirty_from.map_or(e.index, |d| d.min(e.index)));
            }
            self.dirty_from.get_or_insert(e.index);
            self.log.push(e);
        }

        // Only advance to what this message proves matches the leader. The local log
        // may still hold an unverified tail beyond `match_index`.
        let new_commit = leader_commit.min(match_index);
        if new_commit > self.commit {
            self.commit = new_commit;
            self.hs_dirty = true;
        }
        self.send(
            from,
            Message::AppendResp {
                term,
                success: true,
                match_index,
                hint: 0,
            },
        );
    }

    fn handle_append_resp(&mut self, from: NodeId, success: bool, match_index: Index, hint: Index) {
        if self.role != Role::Leader {
            return;
        }
        let last = self.last_index();
        let Some(p) = self.progress.get_mut(&from) else {
            return;
        };
        p.active = true;
        if success {
            // Replies can arrive reordered, so matched only ever moves forward. A
            // peer cannot have matched past this leader's log; ignore such claims.
            if match_index <= last && match_index > p.matched {
                p.matched = match_index;
            }
            p.next = p.next.max(p.matched + 1);
            let next = p.next;
            if self.maybe_commit() {
                self.broadcast_append();
            } else if next <= last {
                self.send_append(from);
            }
        } else {
            let rewound = hint.max(p.matched + 1).min(last + 1);
            if rewound < p.next {
                p.next = rewound;
                self.send_append(from);
            }
        }
    }

    fn handle_snapshot(&mut self, from: NodeId, snapshot: Snapshot) {
        self.accept_leader(from);
        let term = self.term;
        if snapshot.last_index <= self.commit {
            let index = self.commit;
            self.send(from, Message::SnapshotResp { term, index });
            return;
        }
        let index = snapshot.last_index;
        if self.term_at(index) == Some(snapshot.last_term) {
            // The local log already extends this snapshot, so keep the suffix.
            let keep_from = (index - self.snap_index) as usize;
            self.log.drain(..keep_from);
            if let Some(d) = self.dirty_from
                && d <= index
            {
                self.dirty_from = if self.log.is_empty() {
                    None
                } else {
                    Some(index + 1)
                };
            }
        } else {
            self.log.clear();
            self.dirty_from = None;
            self.force_truncate = Some(index + 1);
            self.stable_last = index;
        }
        self.stable_last = self.stable_last.max(index);
        self.snap_index = index;
        self.snap_term = snapshot.last_term;
        self.commit = index;
        self.applied = index;
        self.hs_dirty = true;
        self.snapshot = Some(snapshot.clone());
        self.pending_restore = Some(snapshot);
        self.send(from, Message::SnapshotResp { term, index });
    }

    fn handle_snapshot_resp(&mut self, from: NodeId, index: Index) {
        if self.role != Role::Leader {
            return;
        }
        let last = self.last_index();
        let Some(p) = self.progress.get_mut(&from) else {
            return;
        };
        p.active = true;
        if index <= last && index > p.matched {
            p.matched = index;
        }
        p.next = p.next.max(p.matched + 1);
        let next = p.next;
        if self.maybe_commit() {
            self.broadcast_append();
        } else if next <= last {
            self.send_append(from);
        }
    }

    /// Captures a snapshot produced by the application at `index`, which must already
    /// be applied, and drops the log prefix it covers. The driver is responsible for
    /// persisting the returned snapshot.
    pub fn compact(&mut self, index: Index, data: Vec<u8>) -> Result<Snapshot, CompactError> {
        if index > self.applied {
            return Err(CompactError::NotApplied);
        }
        if index <= self.snap_index {
            return Err(CompactError::AlreadyCompacted);
        }
        let last_term = self.term_at(index).ok_or(CompactError::AlreadyCompacted)?;
        let drop = (index - self.snap_index) as usize;
        self.log.drain(..drop);
        self.snap_index = index;
        self.snap_term = last_term;
        let snapshot = Snapshot {
            last_index: index,
            last_term,
            data,
        };
        self.snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }

    /// Whether [`Raft::take_ready`] would return a non-empty batch.
    pub fn has_ready(&self) -> bool {
        self.hs_dirty
            || self.pending_restore.is_some()
            || self.dirty_from.is_some()
            || self.force_truncate.is_some()
            || !self.outbox.is_empty()
            || self.applied < self.commit
    }

    /// Drains all pending work. See the module documentation for the required order.
    pub fn take_ready(&mut self) -> Ready {
        let mut ready = Ready {
            install_snapshot: self.pending_restore.take(),
            messages: std::mem::take(&mut self.outbox),
            ..Ready::default()
        };
        if self.hs_dirty {
            self.hs_dirty = false;
            ready.hard_state = Some(self.hard_state());
        }

        let mut truncate = self.force_truncate.take();
        if let Some(dirty) = self.dirty_from.take() {
            if dirty <= self.stable_last {
                truncate = Some(truncate.map_or(dirty, |t| t.min(dirty)));
            }
            let start = dirty.saturating_sub(self.snap_index + 1) as usize;
            ready.entries = self.log.iter().skip(start).cloned().collect();
        }
        ready.truncate_from = truncate;
        self.stable_last = self.last_index();

        if self.applied < self.commit {
            let start = (self.applied - self.snap_index) as usize;
            let count = (self.commit - self.applied) as usize;
            ready.committed = self.log[start..start + count].to_vec();
            self.applied = self.commit;
        }
        ready
    }
}
