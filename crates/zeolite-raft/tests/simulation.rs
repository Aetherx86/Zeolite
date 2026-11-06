//! Deterministic fault-injection simulation of the Raft core.
//!
//! Each seed drives a cluster through message loss, duplication, reordering, partitions,
//! crashes and log compaction, then heals the network and requires convergence. The
//! safety properties from the Raft paper are checked continuously:
//!
//! - Election Safety: at most one leader per term.
//! - Log Matching: the same index and term implies an identical prefix.
//! - Leader Completeness: a leader holds every entry committed in earlier terms.
//! - State Machine Safety: no two nodes apply different entries at one index.

use std::collections::{BTreeMap, BTreeSet};
use zeolite_raft::{
    Config, Entry, Envelope, HardState, Index, NodeId, Raft, Recovered, Role, Snapshot, Term,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

#[derive(Default, Clone)]
struct Disk {
    hard_state: HardState,
    snapshot: Option<Snapshot>,
    entries: Vec<Entry>,
}

struct Node {
    raft: Option<Raft>,
    disk: Disk,
    /// Reconstructed state machine: the digest of every applied entry, in order.
    state: u64,
    applied: Index,
    last_role: Role,
    last_term: Term,
}

fn mix(state: u64, entry_term: Term, index: Index, data: &[u8]) -> u64 {
    let mut h = state ^ 0xCBF2_9CE4_8422_2325;
    for byte in index
        .to_le_bytes()
        .iter()
        .chain(entry_term.to_le_bytes().iter())
        .chain(data.iter())
    {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

fn encode_state(state: u64, applied: Index) -> Vec<u8> {
    let mut v = state.to_le_bytes().to_vec();
    v.extend_from_slice(&applied.to_le_bytes());
    v
}

fn decode_state(bytes: &[u8]) -> (u64, Index) {
    let mut a = [0u8; 8];
    a.copy_from_slice(&bytes[..8]);
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[8..16]);
    (u64::from_le_bytes(a), u64::from_le_bytes(b))
}

struct Sim {
    rng: Rng,
    nodes: BTreeMap<NodeId, Node>,
    in_flight: Vec<(u64, Envelope)>,
    now: u64,
    groups: BTreeMap<NodeId, u32>,
    drop_percent: u64,
    dup_percent: u64,
    max_delay: u64,
    leaders_by_term: BTreeMap<Term, NodeId>,
    /// Index -> (entry term, payload, highest node term seen when it was applied).
    committed: BTreeMap<Index, (Term, Vec<u8>, Term)>,
    /// Applied state digest per index, which every node must agree on.
    digest_at: BTreeMap<Index, u64>,
    next_payload: u64,
    leader_elections: u64,
    compact_every: Option<u64>,
}

impl Sim {
    fn new(seed: u64, ids: &[NodeId]) -> Self {
        let mut nodes = BTreeMap::new();
        for id in ids {
            let raft = Raft::new(config(*id, ids, seed), Recovered::default());
            nodes.insert(
                *id,
                Node {
                    raft: Some(raft),
                    disk: Disk::default(),
                    state: 0,
                    applied: 0,
                    last_role: Role::Follower,
                    last_term: 0,
                },
            );
        }
        Sim {
            rng: Rng(seed | 1),
            nodes,
            in_flight: Vec::new(),
            now: 0,
            groups: ids.iter().map(|i| (*i, 0)).collect(),
            drop_percent: 0,
            dup_percent: 0,
            max_delay: 3,
            leaders_by_term: BTreeMap::new(),
            committed: BTreeMap::new(),
            digest_at: BTreeMap::new(),
            next_payload: 0,
            leader_elections: 0,
            compact_every: None,
        }
    }

    fn ids(&self) -> Vec<NodeId> {
        self.nodes.keys().copied().collect()
    }

    fn drain(&mut self, id: NodeId) {
        loop {
            let Some(node) = self.nodes.get_mut(&id) else {
                return;
            };
            let Some(raft) = node.raft.as_mut() else {
                return;
            };
            if !raft.has_ready() {
                break;
            }
            let ready = raft.take_ready();
            let term = raft.term();

            // Persist in the order the driver contract requires.
            if let Some(snapshot) = &ready.install_snapshot {
                node.disk.snapshot = Some(snapshot.clone());
            }
            if let Some(from) = ready.truncate_from {
                node.disk.entries.retain(|e| e.index < from);
            }
            for e in &ready.entries {
                while node.disk.entries.last().is_some_and(|x| x.index >= e.index) {
                    node.disk.entries.pop();
                }
                node.disk.entries.push(e.clone());
            }
            if let Some(hs) = ready.hard_state {
                node.disk.hard_state = hs;
            }

            // Apply.
            if let Some(snapshot) = &ready.install_snapshot {
                let (state, applied) = decode_state(&snapshot.data);
                assert_eq!(applied, snapshot.last_index, "snapshot metadata disagrees");
                node.state = state;
                node.applied = applied;
            }
            let mut newly = Vec::new();
            for e in &ready.committed {
                assert_eq!(e.index, node.applied + 1, "node {id} applied out of order");
                node.state = mix(node.state, e.term, e.index, &e.data);
                node.applied = e.index;
                newly.push((e.clone(), node.state));
            }
            let (state, applied) = (node.state, node.applied);
            let should_compact = self
                .compact_every
                .is_some_and(|every| !newly.is_empty() && applied % every == 0);
            if should_compact {
                let raft = node.raft.as_mut().unwrap();
                let snapshot = raft.compact(applied, encode_state(state, applied)).unwrap();
                node.disk.entries.retain(|e| e.index > snapshot.last_index);
                node.disk.snapshot = Some(snapshot);
            }

            for (e, digest) in newly {
                let previous =
                    self.committed
                        .entry(e.index)
                        .or_insert((e.term, e.data.clone(), term));
                assert_eq!(
                    (previous.0, &previous.1),
                    (e.term, &e.data),
                    "state machine safety violated at index {}",
                    e.index
                );
                previous.2 = previous.2.min(term);
                let d = self.digest_at.entry(e.index).or_insert(digest);
                assert_eq!(*d, digest, "state digest diverged at index {}", e.index);
            }
            if let Some(snapshot) = &ready.install_snapshot {
                let (state, applied) = decode_state(&snapshot.data);
                if let Some(d) = self.digest_at.get(&applied) {
                    assert_eq!(*d, state, "snapshot digest diverged at index {applied}");
                }
            }

            for env in ready.messages {
                self.enqueue(env);
            }
        }
        self.observe_role(id);
    }

    fn observe_role(&mut self, id: NodeId) {
        let Some(node) = self.nodes.get_mut(&id) else {
            return;
        };
        let Some(raft) = node.raft.as_ref() else {
            return;
        };
        let (role, term) = (raft.role(), raft.term());
        let became_leader =
            role == Role::Leader && (node.last_role != Role::Leader || node.last_term != term);
        node.last_role = role;
        node.last_term = term;
        if !became_leader {
            return;
        }
        let previous = self.leaders_by_term.insert(term, id);
        if let Some(other) = previous {
            assert_eq!(other, id, "two leaders elected in term {term}");
        }
        self.leader_elections += 1;

        // Leader Completeness, restricted to entries provably committed in an earlier
        // term than this leader's.
        let raft = self.nodes[&id].raft.as_ref().unwrap();
        for (index, (entry_term, data, seen_term)) in &self.committed {
            if *seen_term >= term || *index <= raft.snapshot_index() {
                continue;
            }
            assert_eq!(
                raft.term_at(*index),
                Some(*entry_term),
                "leader {id} of term {term} is missing committed index {index}"
            );
            let held = &raft.log()[(*index - raft.snapshot_index() - 1) as usize];
            assert_eq!(&held.data, data, "leader {id} holds a different payload");
        }
    }

    fn enqueue(&mut self, env: Envelope) {
        if self.groups.get(&env.from) != self.groups.get(&env.to) {
            return;
        }
        if self.rng.chance(self.drop_percent) {
            return;
        }
        if self.rng.chance(self.dup_percent) {
            let at = self.now + 1 + self.rng.below(self.max_delay);
            self.in_flight.push((at, env.clone()));
        }
        let at = self.now + 1 + self.rng.below(self.max_delay);
        self.in_flight.push((at, env));
    }

    fn step_time(&mut self) {
        self.now += 1;
        for id in self.ids() {
            if let Some(raft) = self.nodes.get_mut(&id).and_then(|n| n.raft.as_mut()) {
                raft.tick();
            }
            self.drain(id);
        }
        let now = self.now;
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.in_flight)
            .into_iter()
            .partition(|(at, _)| *at <= now);
        self.in_flight = later;
        for (_, env) in due {
            // A partition also blocks anything already on the wire.
            if self.groups.get(&env.from) != self.groups.get(&env.to) {
                continue;
            }
            let to = env.to;
            if let Some(raft) = self.nodes.get_mut(&to).and_then(|n| n.raft.as_mut()) {
                raft.step(env.from, env.msg);
                self.drain(to);
            }
        }
    }

    fn propose_to_leader(&mut self) -> bool {
        for id in self.ids() {
            let payload = self.next_payload;
            if let Some(raft) = self.nodes.get_mut(&id).and_then(|n| n.raft.as_mut())
                && raft.role() == Role::Leader
                && raft.propose(payload.to_le_bytes().to_vec()).is_ok()
            {
                self.next_payload += 1;
                self.drain(id);
                return true;
            }
        }
        false
    }

    fn crash(&mut self, id: NodeId) {
        let node = self.nodes.get_mut(&id).unwrap();
        node.raft = None;
        self.in_flight.retain(|(_, env)| env.to != id);
    }

    fn restart(&mut self, id: NodeId, seed: u64) {
        let ids = self.ids();
        let node = self.nodes.get_mut(&id).unwrap();
        if node.raft.is_some() {
            return;
        }
        let recovered = Recovered {
            hard_state: node.disk.hard_state,
            snapshot: node.disk.snapshot.clone(),
            entries: node.disk.entries.clone(),
        };
        // A restart rebuilds the state machine from the durable snapshot.
        (node.state, node.applied) = match &recovered.snapshot {
            Some(snapshot) => decode_state(&snapshot.data),
            None => (0, 0),
        };
        node.raft = Some(Raft::new(config(id, &ids, seed), recovered));
        node.last_role = Role::Follower;
    }

    fn check_log_matching(&self) {
        let logs: Vec<(NodeId, &Raft)> = self
            .nodes
            .iter()
            .filter_map(|(id, n)| n.raft.as_ref().map(|r| (*id, r)))
            .collect();
        for (i, (a_id, a)) in logs.iter().enumerate() {
            for (b_id, b) in logs.iter().skip(i + 1) {
                let top = a.last_index().min(b.last_index());
                let low = a.snapshot_index().max(b.snapshot_index());
                let mut matched_above = false;
                let mut index = top;
                while index > low {
                    let (ta, tb) = (a.term_at(index).unwrap(), b.term_at(index).unwrap());
                    if matched_above {
                        assert_eq!(
                            ta, tb,
                            "log matching violated between {a_id} and {b_id} at {index}"
                        );
                    } else if ta == tb {
                        matched_above = true;
                    }
                    if matched_above {
                        let ea = &a.log()[(index - a.snapshot_index() - 1) as usize];
                        let eb = &b.log()[(index - b.snapshot_index() - 1) as usize];
                        assert_eq!(ea, eb, "entries differ at {index}");
                    }
                    index -= 1;
                }
            }
        }
    }

    fn heal(&mut self) {
        for group in self.groups.values_mut() {
            *group = 0;
        }
        self.drop_percent = 0;
        self.dup_percent = 0;
    }

    fn converged(&self) -> bool {
        let mut applied = BTreeSet::new();
        let mut leaders = 0;
        for node in self.nodes.values() {
            let Some(raft) = node.raft.as_ref() else {
                return false;
            };
            applied.insert((node.applied, node.state));
            if raft.role() == Role::Leader {
                leaders += 1;
            }
            if raft.last_index() != node.applied {
                return false;
            }
        }
        applied.len() == 1 && leaders == 1
    }
}

fn config(id: NodeId, ids: &[NodeId], seed: u64) -> Config {
    let mut cfg = Config::new(id, ids.iter().copied().filter(|p| *p != id).collect());
    cfg.seed ^= seed.wrapping_mul(id.wrapping_add(31));
    cfg
}

fn run_chaos(seed: u64, ids: &[NodeId], compact_every: Option<u64>) -> (u64, u64) {
    let mut sim = Sim::new(seed, ids);
    sim.compact_every = compact_every;
    sim.drop_percent = 8;
    sim.dup_percent = 5;
    sim.max_delay = 6;

    for step in 0..6000u64 {
        sim.step_time();
        if sim.rng.chance(25) {
            sim.propose_to_leader();
        }
        if step % 50 == 0 {
            sim.check_log_matching();
        }
        match sim.rng.below(1000) {
            // Split the cluster at random.
            0..=3 => {
                for id in sim.ids() {
                    let g = sim.rng.below(2) as u32;
                    sim.groups.insert(id, g);
                }
            }
            4..=9 => {
                for group in sim.groups.values_mut() {
                    *group = 0;
                }
            }
            // Crash one node, keeping a majority of the cluster up.
            10..=12 => {
                let live = sim.nodes.values().filter(|n| n.raft.is_some()).count();
                if live > ids.len() / 2 + 1 {
                    let victim = ids[sim.rng.below(ids.len() as u64) as usize];
                    sim.crash(victim);
                }
            }
            13..=20 => {
                let id = ids[sim.rng.below(ids.len() as u64) as usize];
                let reseed = sim.rng.next();
                sim.restart(id, reseed);
            }
            _ => {}
        }
    }

    // Heal everything and require convergence.
    sim.heal();
    for id in ids.iter().copied() {
        let reseed = sim.rng.next();
        sim.restart(id, reseed);
    }
    let mut proposed_after_heal = false;
    for _ in 0..6000 {
        sim.step_time();
        if !proposed_after_heal && sim.propose_to_leader() {
            proposed_after_heal = true;
        }
        if proposed_after_heal && sim.converged() {
            break;
        }
    }
    sim.check_log_matching();
    assert!(
        sim.converged(),
        "seed {seed}: cluster failed to converge after healing"
    );
    (sim.next_payload, sim.leader_elections)
}

#[test]
fn three_node_cluster_survives_chaos() {
    let mut proposals = 0;
    let mut elections = 0;
    for seed in 1..=30 {
        let (p, e) = run_chaos(seed * 0x9E37_79B9, &[1, 2, 3], None);
        proposals += p;
        elections += e;
    }
    // Guards against a harness so aggressive that it never exercises anything.
    assert!(proposals > 3000, "only {proposals} proposals were accepted");
    assert!(elections > 60, "only {elections} leaders were elected");
}

#[test]
fn five_node_cluster_survives_chaos() {
    for seed in 1..=20 {
        run_chaos(seed * 0xB5297A4D, &[1, 2, 3, 4, 5], None);
    }
}

#[test]
fn chaos_with_compaction_and_snapshot_install() {
    for seed in 1..=30 {
        run_chaos(seed * 0x68E31DA4, &[1, 2, 3], Some(16));
    }
    for seed in 1..=10 {
        run_chaos(seed * 0xD1B54A32, &[1, 2, 3, 4, 5], Some(8));
    }
}

#[test]
fn single_node_commits_alone() {
    let mut sim = Sim::new(99, &[1]);
    for _ in 0..40 {
        sim.step_time();
    }
    assert!(sim.propose_to_leader());
    for _ in 0..5 {
        sim.step_time();
    }
    assert!(sim.converged());
    assert!(!sim.committed.is_empty());
}

#[test]
fn isolated_follower_does_not_disrupt_the_leader() {
    let mut sim = Sim::new(7, &[1, 2, 3]);
    for _ in 0..80 {
        sim.step_time();
    }
    let leader = sim
        .ids()
        .into_iter()
        .find(|id| sim.nodes[id].raft.as_ref().unwrap().role() == Role::Leader)
        .expect("a leader should have been elected");
    let term = sim.nodes[&leader].raft.as_ref().unwrap().term();
    let follower = sim.ids().into_iter().find(|id| *id != leader).unwrap();

    sim.groups.insert(follower, 1);
    for _ in 0..400 {
        sim.step_time();
    }
    // Pre-vote keeps the isolated node's term from climbing while it times out.
    assert_eq!(sim.nodes[&follower].raft.as_ref().unwrap().term(), term);

    sim.groups.insert(follower, 0);
    for _ in 0..80 {
        sim.step_time();
    }
    let raft = sim.nodes[&leader].raft.as_ref().unwrap();
    assert_eq!(
        raft.role(),
        Role::Leader,
        "the rejoining node deposed the leader"
    );
    assert_eq!(raft.term(), term);
}

#[test]
fn leader_cut_off_from_majority_steps_down() {
    let mut sim = Sim::new(11, &[1, 2, 3]);
    for _ in 0..80 {
        sim.step_time();
    }
    let leader = sim
        .ids()
        .into_iter()
        .find(|id| sim.nodes[id].raft.as_ref().unwrap().role() == Role::Leader)
        .expect("a leader should have been elected");
    sim.groups.insert(leader, 1);
    for _ in 0..200 {
        sim.step_time();
    }
    assert_ne!(
        sim.nodes[&leader].raft.as_ref().unwrap().role(),
        Role::Leader,
        "an isolated leader must step down through check-quorum"
    );
    let others_have_leader = sim
        .ids()
        .into_iter()
        .filter(|id| *id != leader)
        .any(|id| sim.nodes[&id].raft.as_ref().unwrap().role() == Role::Leader);
    assert!(
        others_have_leader,
        "the majority side should elect a new leader"
    );
}

#[test]
fn lagging_node_catches_up_through_a_snapshot() {
    let mut sim = Sim::new(21, &[1, 2, 3]);
    sim.compact_every = Some(4);
    for _ in 0..80 {
        sim.step_time();
    }
    let leader = sim
        .ids()
        .into_iter()
        .find(|id| sim.nodes[id].raft.as_ref().unwrap().role() == Role::Leader)
        .expect("a leader should have been elected");
    let lagging = sim.ids().into_iter().find(|id| *id != leader).unwrap();
    sim.crash(lagging);
    for _ in 0..60 {
        sim.propose_to_leader();
        sim.step_time();
    }
    assert!(sim.nodes[&leader].raft.as_ref().unwrap().snapshot_index() > 0);

    sim.restart(lagging, 1234);
    for _ in 0..200 {
        sim.step_time();
    }
    assert!(sim.converged(), "the lagging node did not catch up");
    let node = &sim.nodes[&lagging];
    assert!(
        node.raft.as_ref().unwrap().snapshot_index() > 0,
        "catching up should have gone through a snapshot"
    );
}
