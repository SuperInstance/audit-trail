# audit-trail

An append-only audit log where **each event commits to its predecessor**, in the shape the
SuperInstance witness log needs.

```rust
use audit_trail::{AuditAction, AuditTrail};

let mut t = AuditTrail::new();
t.record("alice", AuditAction::Login, "cell/1", "ok");
t.record("bob",   AuditAction::Update, "cell/1", "tick=4");

assert!(t.intact());
```

## What this replaces

The first version of this crate was `Vec<AuditEvent>` with sequential ids. That is an
append-only list in the sense nothing removes from it, and it is nothing else — there is no
hash, so there is nothing to alter and therefore nothing to detect. The README at the time
described an "immutable, append-only event logging" architecture that the code did not have.

This version has the one property that makes an audit log worth keeping:

```
hash(N) = FNV-1a-64( canonical(N) ‖ hash(N-1) )
```

Editing any historical event invalidates the hash of every event after it, and `verify`
reports the id of the first break.

## The fleet canary

The hash is FNV-1a 64 because it is the digest the rest of the fleet already agrees on, so
a chain written here compares byte-for-byte with one written in any other substrate.

```
$ cargo run
fnv1a64("café Δ 日本語") = 0x24a555471370b18d
fleet canary           = 0x24a555471370b18d
agrees                 = true
```

Verified in Python, TypeScript, Rust, C#, and Julia. `canary_holds()` re-checks it at
runtime, so a port that drifts is caught by its own test suite.

**FNV-1a is not a security primitive.** It is not collision resistant, and this is not a
defence against an adversary who can choose their inputs. It is an integrity signal — the
right one for a log whose purpose is accidental corruption plus casual tampering. If you
need to resist a motivated adversary, read the section below and then the rest of this file.

## What a chain does NOT give you

This is the part that is usually wrong, so it is stated first and prominently.

A chain proves **relative order** and detects alteration of a **retained prefix**. It does
not prove:

- **that the writer did not rewrite the whole chain.** If an adversary holds the current
  database and nobody kept an old head, a complete rewrite is undetectable. Anchor the head
  externally — timestamp authority, immutable storage, a transparency log.
- **that an event happened when its timestamp says.** `timestamp` is the host clock, which
  is exactly as trustworthy as the host.
- **that the recorded event is true about the world.** It is a faithful record of what was
  recorded, which is a much narrower claim.

Cryptographic integrity proves *none* of: that a prediction preceded the event, that the
measurement was truthful, that the model was implemented correctly, or that the model is
statistically valid. Four separate assumptions.

## Design notes

**Canonical encoding is injective.** String fields are length-prefixed, so `("ab","c")` and
`("a","bc")` cannot produce the same bytes and therefore cannot hash the same. A hash over
a serialisation whose order can vary is a hash over a coin flip.

**Non-zero genesis.** `GENESIS = 0x9e3779b97f4a7c15`. A zero genesis is indistinguishable
from a chain truncated back to nothing, which is exactly the attack you want to catch.

**`events_mut` exists on purpose.** A log you cannot deserialise is not a log. Everything
that mutates through it is *expected* to leave the chain broken — that is what `verify` is
for. Live code should use `record`. `reseat()` rebuilds `next_id` after loading.

**Injectable clock.** `with_clock` exists so the tests are deterministic; timestamps are
otherwise host wall-clock seconds.

## Tests

```
cargo test
```

14 tests. The five that matter are the negative controls — injecting a field, deleting an
event, reordering, retimestamping, and verifying twice. **A suite that only asserted
"record works" would pass on the original `Vec` implementation**, which is the thing this
crate was rewritten to stop being.

## What should be built next

This is the smallest honest version. In order of value:

1. **Batch the chain.** Merkle tree over events within a batch, hash-chain the *roots*.
   Chaining every event is O(n) hashes for a log that is only ever checked at checkpoints;
   the batched form is what the fleet's design calls for. See
   [`SuperInstance/witness-validation`](https://github.com/SuperInstance/witness-validation)
   for the full design and why consistency proofs matter.
2. **Serialise.** A canonical, versioned encoding on disk, so a log survives the process
   that wrote it.
3. **Signed checkpoints.** Sign the head, publish it somewhere the writer does not control.
   Without this, the chain detects accidents and nothing else.
4. **A model version field.** A model change must be a new segment with an explicit version
   bump, never a retroactive rewrite — that is the rule that keeps an error budget intact,
   and it is the one a self-updating log violates first.

## Licence

MIT OR Apache-2.0, at your option.
