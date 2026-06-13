# Audit Trail

**A Rust library for tamper-evident audit trails** — records security-relevant events with sequential IDs, actor attribution, and Unix timestamps for compliance and forensic analysis.

## Why It Matters

Audit trails are mandatory for SOC 2, HIPAA, PCI-DSS, and ISO 27001 compliance. They provide the evidentiary record of "who did what, when" — used in incident response, forensic investigation, and regulatory audits. Unlike application logs, audit trails must be append-only, sequentially numbered (for gap detection), and queryable by actor or resource.

## How It Works

The `AuditTrail` maintains an in-memory `Vec<AuditEvent>` with a monotonically incrementing `next_id`. Each `record()` call:

1. Increments the counter, producing a gap-free sequence number
2. Captures the Unix timestamp at the moment of recording
3. Stores the actor (user or service identity), action type (`Create`, `Read`, `Update`, `Delete`, `Login`, `Logout`), affected resource, and freeform metadata

The sequential numbering enables **gap detection**: any missing ID in the sequence indicates tampering or data loss. Events are queryable via `by_actor()` for user-activity investigation or `events()` for full sequential scan.

## Quick Start

```rust
use audit_trail::{AuditTrail, AuditAction};

let mut trail = AuditTrail::new();

trail.record("alice", AuditAction::Login, "system", "ip=10.0.0.1");
trail.record("alice", AuditAction::Create, "doc:42", "title=Report");
trail.record("bob", AuditAction::Delete, "doc:42", "reason=expired");

for event in trail.by_actor("alice") {
    println!("[{}] {} {} {}", event.timestamp, event.actor, 
        match event.action { AuditAction::Create => "created", _ => "?" }, event.resource);
}
```

## API

- **`AuditAction`** — Enum: `Create`, `Read`, `Update`, `Delete`, `Login`, `Logout`
- **`AuditEvent`** — Struct: `id`, `actor`, `action`, `resource`, `timestamp`, `metadata`
- **`AuditTrail`** — Append-only store with `record()`, `by_actor()`, `events()`, `len()`, `is_empty()`

## Architecture Notes

This is the audit primitive for SuperInstance fleet services. The in-memory store is designed to be swapped for a durable backend (WAL, database) in production deployments. See the [architecture overview](https://github.com/SuperInstance/SuperInstance/blob/main/ARCHITECTURE.md).

## License

MIT
