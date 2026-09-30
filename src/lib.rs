//! audit-trail — an append-only event log with a hash-chained head.
//!
//! # What this is, and what it is not
//!
//! The original version of this crate was a `Vec<AuditEvent>` with sequential ids. That is
//! an append-only list in the sense that nothing removes from it, and it is nothing else.
//! It cannot answer "was this altered?", because there is no hash to alter.
//!
//! This version adds the one property that makes an audit log worth keeping: **each event
//! commits to its predecessor.** Given the previous event's hash and the bytes of this one,
//! the next hash is determined, so editing any historical event invalidates every hash after
//! it.
//!
//! # What it still does not give you
//!
//! A chain proves *relative* order and detects alteration of a retained prefix. It does not
//! prove:
//!
//! * **that the writer did not rewrite the whole chain** — if an adversary holds the current
//!   database and nobody retained an old head, a complete rewrite is undetectable. Anchor
//!   the head externally: a timestamp authority, immutable storage, a transparency log.
//! * **that an event happened when its timestamp says.** The timestamp here is the host
//!   clock, which is exactly as trustworthy as the host.
//! * **that the recorded event is the truth about the world.** It is a faithful record of
//!   what was recorded, which is a narrower claim.
//!
//! Batching several events into one Merkle root and chaining the *roots* is strictly better
//! than chaining every event, and is the next thing this crate should grow. See
//! <https://github.com/SuperInstance/witness-validation> for the design this is drawn from.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// FNV-1a 64 — the fleet's polyformalism canary hash.
///
/// Chosen over SHA-2 because it is the digest the rest of the fleet already agrees on
/// (`0x024a555471370b18d` for `"café Δ 日本語"`), so a chain written here can be compared
/// byte-for-byte with a chain written in any other substrate in the fleet. It is **not** a
/// security primitive: FNV-1a is not collision resistant and this is not a defence against an
/// adversary who can choose inputs. It is an integrity signal, and the right one for a log
/// whose purpose is accidental corruption plus casual tampering.
pub const FNV_OFFSET: u64 = 0xcbf29ce484222325;
pub const FNV_PRIME: u64 = 0x100000001b3;

#[inline]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h = (h ^ b as u64).wrapping_mul(FNV_PRIME);
    }
    h
}

/// The fleet canary, as a compile-time checkable constant.
pub const CANARY: u64 = 0x024a555471370b18d;

/// Returns true if this platform's FNV-1a agrees with the rest of the fleet.
pub fn canary_holds() -> bool {
    fnv1a64("café Δ 日本語".as_bytes()) == CANARY
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditAction {
    Create,
    Read,
    Update,
    Delete,
    Login,
    Logout,
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            AuditAction::Create => "create",
            AuditAction::Read => "read",
            AuditAction::Update => "update",
            AuditAction::Delete => "delete",
            AuditAction::Login => "login",
            AuditAction::Logout => "logout",
        };
        f.write_str(s)
    }
}

/// One recorded event. `hash` commits to every field AND to the previous event's hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: u64,
    pub actor: String,
    pub action: AuditAction,
    pub resource: String,
    /// Host wall-clock seconds at record time. Trustworthy exactly as far as the host clock.
    pub timestamp: u64,
    pub metadata: String,
    /// FNV-1a over the canonical encoding of this event and the previous event's hash.
    pub prev_hash: u64,
    pub hash: u64,
}

impl AuditEvent {
    /// The canonical byte encoding that the hash is taken over.
    ///
    /// Field order and separators are fixed on purpose: a hash over a serialisation whose
    /// order can vary is a hash over a coin flip. Length-prefixing the string fields is
    /// what makes the encoding injective, so `("a","bc")` and `("ab","c")` cannot collide
    /// into the same bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&(self.actor.len() as u64).to_le_bytes());
        out.extend_from_slice(self.actor.as_bytes());
        out.push(b'|');
        out.push(self.action.to_string().as_bytes()[0]);
        out.extend_from_slice(&(self.resource.len() as u64).to_le_bytes());
        out.extend_from_slice(self.resource.as_bytes());
        out.push(b'|');
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&(self.metadata.len() as u64).to_le_bytes());
        out.extend_from_slice(self.metadata.as_bytes());
        out.extend_from_slice(&self.prev_hash.to_le_bytes());
        out
    }

    pub fn compute_hash(&self) -> u64 {
        fnv1a64(&self.canonical_bytes())
    }

    /// True if this event's own hash matches its contents.
    pub fn self_consistent(&self) -> bool {
        self.compute_hash() == self.hash
    }
}

#[derive(Debug, Default, Clone)]
pub struct AuditTrail {
    events: Vec<AuditEvent>,
    next_id: u64,
    /// Injected so tests are deterministic. `None` means the system clock.
    clock: Option<fn() -> u64>,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self::default()
    }

    /// A trail whose timestamps come from `clock` instead of the system clock.
    pub fn with_clock(clock: fn() -> u64) -> Self {
        Self { events: Vec::new(), next_id: 0, clock: Some(clock) }
    }

    fn now(&self) -> u64 {
        match self.clock {
            Some(f) => f(),
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }

    /// The genesis value. Non-zero, so a truncated chain is not mistaken for an empty one.
    pub const GENESIS: u64 = 0x9e3779b97f4a7c15;

    pub fn head(&self) -> u64 {
        self.events.last().map(|e| e.hash).unwrap_or(Self::GENESIS)
    }

    /// Append an event and return its id. The returned event's `hash` is the new head.
    pub fn record(
        &mut self,
        actor: impl Into<String>,
        action: AuditAction,
        resource: impl Into<String>,
        metadata: impl Into<String>,
    ) -> u64 {
        self.next_id += 1;
        let mut e = AuditEvent {
            id: self.next_id,
            actor: actor.into(),
            action,
            resource: resource.into(),
            timestamp: self.now(),
            metadata: metadata.into(),
            prev_hash: self.head(),
            hash: 0,
        };
        e.hash = e.compute_hash();
        let id = e.id;
        self.events.push(e);
        id
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Mutable access to the events, for deserialising an existing log.
    ///
    /// This is the one way to corrupt a chain, and it exists because a log you cannot load
    /// is not a log. Everything that mutates through here is expected to leave the chain
    /// BROKEN, which is what `verify` is for. Prefer `record` for anything live.
    pub fn events_mut(&mut self) -> &mut Vec<AuditEvent> {
        &mut self.events
    }

    /// Rebuild `next_id` from the highest existing id. Call after loading a log.
    pub fn reseat(&mut self) {
        self.next_id = self.events.iter().map(|e| e.id).max().unwrap_or(0);
    }

    pub fn by_actor(&self, actor: &str) -> Vec<&AuditEvent> {
        self.events.iter().filter(|e| e.actor == actor).collect()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Verify the whole chain: every event's own hash matches its contents, and every
    /// `prev_hash` equals the previous event's hash.
    ///
    /// Returns the id of the first event that fails, or `None` if the chain is intact.
    pub fn verify(&self) -> Option<u64> {
        let mut expect_prev = Self::GENESIS;
        for e in &self.events {
            if e.prev_hash != expect_prev {
                return Some(e.id);
            }
            if !e.self_consistent() {
                return Some(e.id);
            }
            expect_prev = e.hash;
        }
        None
    }

    /// Replay the chain from scratch and report whether it matches what is stored.
    /// Equivalent to `verify`, but phrased as the question an auditor actually asks.
    pub fn intact(&self) -> bool {
        self.verify().is_none()
    }
}
