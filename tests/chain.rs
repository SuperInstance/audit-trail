//! The tests that matter here are the ones that try to break the chain.
//! A suite that only asserts "record works" would pass on the original Vec
//! implementation too, which is the thing this crate was rewritten to stop being.

use audit_trail::{fnv1a64, AuditAction, AuditEvent, AuditTrail, CANARY};
use audit_trail::AuditTrail as _Trail;
const GENESIS: u64 = _Trail::GENESIS;

fn fixed_clock() -> u64 { 1_700_000_000 }

fn three_events() -> AuditTrail {
    let mut t = AuditTrail::with_clock(fixed_clock);
    t.record("alice", AuditAction::Login, "cell/1", "ok");
    t.record("bob", AuditAction::Update, "cell/1", "tick=4");
    t.record("carol", AuditAction::Read, "cell/2", "");
    t
}

#[test]
fn canary_agrees_with_the_fleet() {
    assert_eq!(fnv1a64("café Δ 日本語".as_bytes()), CANARY);
}

#[test]
fn known_answer_control() {
    fn reference(s: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in s { h = (h ^ b as u64).wrapping_mul(0x100000001b3); }
        h
    }
    assert_eq!(fnv1a64(b"quilt"), reference(b"quilt"));
    assert_eq!(fnv1a64(b""), reference(b""));
    assert_eq!(fnv1a64(&[0xff; 1000]), reference(&[0xff; 1000]));
}

#[test]
fn empty_trail_is_intact_and_head_is_genesis() {
    let t = AuditTrail::new();
    assert!(t.is_empty());
    assert!(t.intact());
    assert_eq!(t.head(), GENESIS);
    assert_ne!(GENESIS, 0, "a zero genesis is indistinguishable from a truncated chain");
}

#[test]
fn each_event_commits_to_its_predecessor() {
    let t = three_events();
    let e = t.events();
    assert_eq!(e.len(), 3);
    assert_eq!(e[0].prev_hash, GENESIS);
    for w in e.windows(2) {
        assert_eq!(w[1].prev_hash, w[0].hash, "event N+1 must commit to event N");
    }
    assert_eq!(t.head(), e[2].hash);
    assert!(t.intact());
}

#[test]
fn ids_are_sequential() {
    let t = three_events();
    let ids: Vec<u64> = t.events().iter().map(|e| e.id).collect();
    assert_eq!(ids, vec![1, 2, 3]);
}

#[test]
fn NORMAL_injecting_a_field_breaks_the_chain() {
    let mut t = three_events();
    t.events_mut()[1].actor = "mallory".to_string();
    assert!(!t.intact(), "altering a historical actor must invalidate the chain");
    assert_eq!(t.verify(), Some(2), "the failure must be reported at the altered event");
}

#[test]
fn NORMAL_deleting_an_event_breaks_the_chain() {
    let mut t = three_events();
    t.events_mut().remove(1);
    assert!(!t.intact());
}

#[test]
fn NORMAL_reordering_breaks_the_chain() {
    let mut t = three_events();
    t.events_mut().swap(1, 2);
    assert!(!t.intact());
}

#[test]
fn NORMAL_retimestamping_breaks_the_chain() {
    let mut t = three_events();
    t.events_mut()[2].timestamp += 1;
    assert!(!t.intact());
}

#[test]
fn NORMAL_verification_does_not_mutate() {
    let t = three_events();
    assert!(t.intact());
    t.verify();
    t.verify();
    assert!(t.intact(), "verification must not mutate the chain");
}

#[test]
fn field_boundaries_do_not_collide() {
    let mk = |a: &str, r: &str, m: &str| AuditEvent {
        id: 1, actor: a.into(), action: AuditAction::Update, resource: r.into(),
        timestamp: 0, metadata: m.into(), prev_hash: GENESIS, hash: 0,
    };
    let a = mk("ab", "c", "d");
    let b = mk("a", "bc", "d");
    assert_ne!(a.compute_hash(), b.compute_hash());
    assert_ne!(b.compute_hash(), mk("a", "b", "cd").compute_hash());
}

#[test]
fn action_is_part_of_the_hash() {
    let mk = |act| AuditEvent {
        id: 1, actor: "a".into(), action: act, resource: "r".into(),
        timestamp: 0, metadata: String::new(), prev_hash: GENESIS, hash: 0,
    };
    assert_ne!(mk(AuditAction::Create).compute_hash(), mk(AuditAction::Delete).compute_hash());
}

#[test]
fn by_actor_filters() {
    let t = three_events();
    assert_eq!(t.by_actor("bob").len(), 1);
    assert_eq!(t.by_actor("nobody").len(), 0);
}

#[test]
fn clock_is_injectable_so_tests_are_deterministic() {
    let t = three_events();
    for e in t.events() { assert_eq!(e.timestamp, fixed_clock()); }
}
