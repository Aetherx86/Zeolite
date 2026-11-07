//! Directed protocol scenarios that random chaos is unlikely to reach.

use zeolite_raft::{Config, Entry, HardState, Message, Raft, Recovered, Role};

fn entry(term: u64, index: u64) -> Entry {
    Entry {
        term,
        index,
        data: vec![index as u8],
    }
}

fn node(id: u64, peers: &[u64], recovered: Recovered) -> Raft {
    Raft::new(Config::new(id, peers.to_vec()), recovered)
}

/// Drives a node through pre-vote and vote until it leads, with `granters` voting for it.
/// The caller supplies enough granters to reach a quorum.
fn elect(raft: &mut Raft, granters: &[u64]) {
    while raft.role() != Role::PreCandidate {
        raft.tick();
    }
    let term = raft.term() + 1;
    for granter in granters {
        raft.step(
            *granter,
            Message::PreVoteResp {
                term,
                granted: true,
            },
        );
    }
    assert_eq!(raft.role(), Role::Candidate);
    for granter in granters {
        raft.step(
            *granter,
            Message::VoteResp {
                term,
                granted: true,
            },
        );
    }
    assert_eq!(raft.role(), Role::Leader);
}

/// Figure 8 of the Raft paper: an entry from an earlier term stored on a majority is
/// not yet safe, because a later leader could still overwrite it. Replica counting may
/// only commit entries from the current term.
#[test]
fn old_term_entries_do_not_commit_by_counting_replicas() {
    let mut raft = node(
        1,
        &[2, 3],
        Recovered {
            hard_state: HardState {
                term: 3,
                voted_for: None,
                commit: 1,
            },
            snapshot: None,
            entries: vec![entry(1, 1), entry(2, 2)],
        },
    );
    elect(&mut raft, &[2]);
    assert_eq!(raft.term(), 4);
    assert_eq!(
        raft.last_index(),
        3,
        "the new leader appends a no-op at index 3"
    );

    // Peer 2 reports holding the term 2 entry, so it now sits on a majority.
    raft.step(
        2,
        Message::AppendResp {
            term: 4,
            success: true,
            match_index: 2,
            hint: 0,
        },
    );
    assert_eq!(
        raft.commit_index(),
        1,
        "a term 2 entry must not commit in term 4"
    );

    // Once the current-term no-op reaches a majority, both entries commit together.
    raft.step(
        2,
        Message::AppendResp {
            term: 4,
            success: true,
            match_index: 3,
            hint: 0,
        },
    );
    assert_eq!(raft.commit_index(), 3);
}

/// A vote cast within the current term must reach disk. Otherwise a crash and restart
/// could let the node vote twice in one term and elect two leaders.
#[test]
fn a_same_term_vote_is_persisted_and_binding_after_restart() {
    let mut raft = node(
        1,
        &[2, 3],
        Recovered {
            hard_state: HardState {
                term: 5,
                voted_for: None,
                commit: 0,
            },
            snapshot: None,
            entries: vec![],
        },
    );
    raft.step(
        2,
        Message::Vote {
            term: 5,
            last_index: 0,
            last_term: 0,
        },
    );
    let ready = raft.take_ready();
    assert!(
        matches!(
            ready.messages[0].msg,
            Message::VoteResp {
                term: 5,
                granted: true
            }
        ),
        "the first candidate should get the vote"
    );
    let durable = ready
        .hard_state
        .expect("casting a vote must produce a hard state to persist");
    assert_eq!(durable.voted_for, Some(2));

    let mut restarted = node(
        1,
        &[2, 3],
        Recovered {
            hard_state: durable,
            snapshot: None,
            entries: vec![],
        },
    );
    restarted.step(
        3,
        Message::Vote {
            term: 5,
            last_index: 0,
            last_term: 0,
        },
    );
    let ready = restarted.take_ready();
    assert!(
        matches!(
            ready.messages[0].msg,
            Message::VoteResp {
                term: 5,
                granted: false
            }
        ),
        "a second candidate in the same term must be refused"
    );
}

/// Pre-vote protects a healthy leader: a follower still hearing from it refuses to help
/// a would-be candidate, even one with an up-to-date log and a higher proposed term.
#[test]
fn a_follower_with_a_live_leader_refuses_pre_votes() {
    let mut raft = node(1, &[2, 3], Recovered::default());
    raft.step(
        2,
        Message::Append {
            term: 1,
            prev_index: 0,
            prev_term: 0,
            entries: vec![entry(1, 1)],
            commit: 0,
        },
    );
    raft.take_ready();

    raft.step(
        3,
        Message::PreVote {
            term: 2,
            last_index: 1,
            last_term: 1,
        },
    );
    let ready = raft.take_ready();
    assert!(
        matches!(
            ready.messages[0].msg,
            Message::PreVoteResp {
                term: 1,
                granted: false
            }
        ),
        "got {:?}",
        ready.messages[0].msg
    );

    // Once the leader has been silent for a full election timeout, the same request
    // is legitimate and must be granted, or the cluster could never replace it.
    for _ in 0..20 {
        if raft.role() != Role::Follower {
            break;
        }
        raft.tick();
    }
    raft.take_ready();
    raft.step(
        3,
        Message::PreVote {
            term: 2,
            last_index: 1,
            last_term: 1,
        },
    );
    let ready = raft.take_ready();
    assert!(
        matches!(
            ready.messages[0].msg,
            Message::PreVoteResp {
                term: 2,
                granted: true
            }
        ),
        "got {:?}",
        ready.messages[0].msg
    );
}

/// Replies can be duplicated or reordered, so `matched` must never move backwards and
/// must never pass the leader's own log.
#[test]
fn stale_or_forged_acknowledgements_cannot_commit_unreplicated_entries() {
    let mut raft = node(1, &[2, 3, 4, 5], Recovered::default());
    elect(&mut raft, &[2, 3]);
    let term = raft.term();
    let last = raft.last_index();

    // A claim past the end of the leader's log proves nothing.
    for peer in [2, 3] {
        raft.step(
            peer,
            Message::AppendResp {
                term,
                success: true,
                match_index: last + 100,
                hint: 0,
            },
        );
    }
    assert_eq!(raft.commit_index(), 0);

    for peer in [2, 3] {
        raft.step(
            peer,
            Message::AppendResp {
                term,
                success: true,
                match_index: last,
                hint: 0,
            },
        );
    }
    assert_eq!(raft.commit_index(), last);

    // A stale reply arriving afterwards leaves commitment untouched.
    raft.step(
        2,
        Message::AppendResp {
            term,
            success: true,
            match_index: 0,
            hint: 0,
        },
    );
    assert_eq!(raft.commit_index(), last);
}

/// Messages from a node that is not a configured member are ignored outright.
#[test]
fn messages_from_non_members_are_ignored() {
    let mut raft = node(1, &[2, 3], Recovered::default());
    raft.step(
        99,
        Message::Append {
            term: 50,
            prev_index: 0,
            prev_term: 0,
            entries: vec![entry(50, 1)],
            commit: 1,
        },
    );
    assert_eq!(raft.term(), 0);
    assert_eq!(raft.last_index(), 0);
    assert!(!raft.has_ready());
}

/// A follower only commits what the current message proves. An unverified tail left by
/// a previous leader stays uncommitted, even if the leader's commit index is higher.
#[test]
fn commit_never_covers_an_unverified_local_tail() {
    let mut raft = node(
        1,
        &[2, 3],
        Recovered {
            hard_state: HardState {
                term: 3,
                voted_for: None,
                commit: 0,
            },
            snapshot: None,
            entries: vec![entry(1, 1), entry(2, 2), entry(2, 3)],
        },
    );
    raft.step(
        2,
        Message::Append {
            term: 3,
            prev_index: 1,
            prev_term: 1,
            entries: vec![],
            commit: 3,
        },
    );
    assert_eq!(raft.commit_index(), 1);
}

#[test]
fn conflict_hint_skips_the_whole_conflicting_term() {
    let mut raft = node(
        1,
        &[2, 3],
        Recovered {
            hard_state: HardState {
                term: 4,
                voted_for: None,
                commit: 0,
            },
            snapshot: None,
            entries: vec![entry(1, 1), entry(2, 2), entry(2, 3), entry(2, 4)],
        },
    );
    raft.step(
        2,
        Message::Append {
            term: 4,
            prev_index: 4,
            prev_term: 3,
            entries: vec![],
            commit: 0,
        },
    );
    let ready = raft.take_ready();
    match &ready.messages[0].msg {
        Message::AppendResp {
            success: false,
            hint,
            ..
        } => assert_eq!(*hint, 2),
        other => panic!("expected a rejection, got {other:?}"),
    }
}
