//! Directed protocol scenarios that random chaos is unlikely to reach.

use zeolite_raft::{
    Config, Entry, Envelope, HardState, Message, ProposeError, Raft, Recovered, Role, TransferError,
};

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

fn sent_to(messages: &[Envelope], to: u64) -> Vec<&Message> {
    messages
        .iter()
        .filter(|e| e.to == to)
        .map(|e| &e.msg)
        .collect()
}

fn has_timeout_now(messages: &[Envelope], to: u64) -> bool {
    sent_to(messages, to)
        .iter()
        .any(|m| matches!(m, Message::TimeoutNow { .. }))
}

/// A leader whose peers have acknowledged its whole log.
fn caught_up_leader() -> Raft {
    let mut raft = node(1, &[2, 3], Recovered::default());
    elect(&mut raft, &[2]);
    let (term, last) = (raft.term(), raft.last_index());
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
    raft.take_ready();
    raft
}

/// A target that already holds the leader's whole log is told to campaign at once, and
/// the leader stops accepting writes so that the target stays caught up.
#[test]
fn transfer_to_a_caught_up_follower_sends_timeout_now_and_pauses_writes() {
    let mut raft = caught_up_leader();
    let term = raft.term();
    raft.transfer_leadership(3).unwrap();
    assert_eq!(raft.transfer_target(), Some(3));
    let ready = raft.take_ready();
    assert!(
        sent_to(&ready.messages, 3)
            .iter()
            .any(|m| **m == Message::TimeoutNow { term }),
        "got {:?}",
        ready.messages
    );
    assert!(!has_timeout_now(&ready.messages, 2));
    assert_eq!(
        raft.propose(b"late".to_vec()),
        Err(ProposeError::NotLeader { leader: Some(3) }),
        "writes during a transfer are redirected to the target"
    );
}

/// A lagging target is first brought up to date. Only an acknowledgement of the
/// leader's last index triggers `TimeoutNow`.
#[test]
fn transfer_to_a_lagging_follower_waits_for_it_to_catch_up() {
    let mut raft = node(1, &[2, 3], Recovered::default());
    elect(&mut raft, &[2]);
    let term = raft.term();
    for data in [b"a", b"b", b"c"] {
        raft.propose(data.to_vec()).unwrap();
    }
    let last = raft.last_index();
    raft.take_ready();

    raft.transfer_leadership(2).unwrap();
    let ready = raft.take_ready();
    assert!(!has_timeout_now(&ready.messages, 2));
    assert!(
        sent_to(&ready.messages, 2)
            .iter()
            .any(|m| matches!(m, Message::Append { .. })),
        "the leader should replicate to the target first"
    );

    // A partial acknowledgement is not enough.
    raft.step(
        2,
        Message::AppendResp {
            term,
            success: true,
            match_index: last - 1,
            hint: 0,
        },
    );
    assert!(!has_timeout_now(&raft.take_ready().messages, 2));

    raft.step(
        2,
        Message::AppendResp {
            term,
            success: true,
            match_index: last,
            hint: 0,
        },
    );
    assert!(has_timeout_now(&raft.take_ready().messages, 2));
}

/// A transfer that does not complete within an election timeout is abandoned, and the
/// leader goes back to accepting writes instead of refusing them forever.
#[test]
fn an_unfinished_transfer_is_abandoned_after_an_election_timeout() {
    let mut raft = caught_up_leader();
    raft.transfer_leadership(2).unwrap();
    raft.take_ready();
    let mut ticks = 0;
    while raft.transfer_target().is_some() {
        // Keep the leader in contact with its peers so check-quorum does not depose it.
        let (term, last) = (raft.term(), raft.last_index());
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
        raft.tick();
        raft.take_ready();
        ticks += 1;
        assert!(ticks <= 10, "the transfer was never abandoned");
    }
    assert_eq!(ticks, 10, "the deadline is one base election timeout");
    assert_eq!(raft.role(), Role::Leader);
    assert!(raft.propose(b"resumed".to_vec()).is_ok());
}

#[test]
fn transfer_requests_are_validated() {
    let mut follower = node(1, &[2, 3], Recovered::default());
    assert_eq!(
        follower.transfer_leadership(2),
        Err(TransferError::NotLeader { leader: None })
    );

    let mut raft = caught_up_leader();
    assert_eq!(
        raft.transfer_leadership(9),
        Err(TransferError::UnknownPeer(9))
    );
    assert_eq!(raft.transfer_target(), None);
    // Transferring to itself is a successful no-op that also cancels a pending transfer.
    raft.transfer_leadership(2).unwrap();
    raft.transfer_leadership(1).unwrap();
    assert_eq!(raft.transfer_target(), None);
    assert!(raft.propose(b"x".to_vec()).is_ok());
}

/// The target skips pre-vote and the randomized timeout: it becomes a candidate in the
/// next term immediately and asks every peer for its vote.
#[test]
fn timeout_now_starts_an_immediate_election() {
    let mut raft = node(2, &[1, 3], Recovered::default());
    raft.step(
        1,
        Message::Append {
            term: 4,
            prev_index: 0,
            prev_term: 0,
            entries: vec![entry(4, 1)],
            commit: 1,
        },
    );
    raft.take_ready();
    assert_eq!(raft.role(), Role::Follower);

    raft.step(1, Message::TimeoutNow { term: 4 });
    assert_eq!(raft.role(), Role::Candidate);
    assert_eq!(raft.term(), 5);
    let ready = raft.take_ready();
    for peer in [1, 3] {
        assert!(
            sent_to(&ready.messages, peer).iter().any(|m| matches!(
                m,
                Message::Vote {
                    term: 5,
                    last_index: 1,
                    last_term: 4
                }
            )),
            "no vote request to {peer}: {:?}",
            ready.messages
        );
    }
    assert_eq!(ready.hard_state.map(|h| h.voted_for), Some(Some(2)));
}

/// A stale `TimeoutNow` from an earlier term must not trigger an election.
#[test]
fn stale_timeout_now_is_ignored() {
    let mut raft = node(2, &[1, 3], Recovered::default());
    raft.step(
        1,
        Message::Append {
            term: 6,
            prev_index: 0,
            prev_term: 0,
            entries: vec![],
            commit: 0,
        },
    );
    raft.take_ready();
    raft.step(1, Message::TimeoutNow { term: 5 });
    assert_eq!(raft.role(), Role::Follower);
    assert_eq!(raft.term(), 6);
}

/// Followers grant the transfer target's vote even though they heard from the old leader
/// moments ago, which pre-vote alone would refuse.
#[test]
fn followers_with_a_live_leader_still_vote_for_a_transfer_target() {
    let mut raft = node(3, &[1, 2], Recovered::default());
    raft.step(
        1,
        Message::Append {
            term: 2,
            prev_index: 0,
            prev_term: 0,
            entries: vec![entry(2, 1)],
            commit: 1,
        },
    );
    raft.take_ready();
    raft.step(
        2,
        Message::Vote {
            term: 3,
            last_index: 1,
            last_term: 2,
        },
    );
    let ready = raft.take_ready();
    assert!(
        sent_to(&ready.messages, 2).iter().any(|m| matches!(
            m,
            Message::VoteResp {
                term: 3,
                granted: true
            }
        )),
        "got {:?}",
        ready.messages
    );
}
