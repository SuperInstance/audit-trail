//! Prints the fleet canary and a two-event chain, so `cargo run` shows the shape.
use audit_trail::{canary_holds, fnv1a64, AuditAction, AuditTrail, CANARY};

fn main() {
    println!("fnv1a64(\"café Δ 日本語\") = {:#018x}", fnv1a64("café Δ 日本語".as_bytes()));
    println!("fleet canary           = {:#018x}", CANARY);
    println!("agrees                 = {}", canary_holds());

    let mut t = AuditTrail::new();
    t.record("alice", AuditAction::Login, "cell/1", "ok");
    t.record("bob", AuditAction::Update, "cell/1", "tick=4");
    for e in t.events() {
        println!("  #{} prev={:#018x} hash={:#018x}", e.id, e.prev_hash, e.hash);
    }
    println!("chain intact           = {}", t.intact());
}
