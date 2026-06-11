use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub enum AuditAction {
    Create,
    Read,
    Update,
    Delete,
    Login,
    Logout,
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub id: u64,
    pub actor: String,
    pub action: AuditAction,
    pub resource: String,
    pub timestamp: u64,
    pub metadata: String,
}

#[derive(Debug, Default)]
pub struct AuditTrail {
    events: Vec<AuditEvent>,
    next_id: u64,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &mut self,
        actor: impl Into<String>,
        action: AuditAction,
        resource: impl Into<String>,
        metadata: impl Into<String>,
    ) -> u64 {
        self.next_id += 1;
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.events.push(AuditEvent {
            id: self.next_id,
            actor: actor.into(),
            action,
            resource: resource.into(),
            timestamp: ts,
            metadata: metadata.into(),
        });
        self.next_id
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
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
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_record() {
        let mut trail = AuditTrail::new();
        trail.record("alice", AuditAction::Login, "system", "ok");
        assert_eq!(trail.len(), 1);
    }
}
