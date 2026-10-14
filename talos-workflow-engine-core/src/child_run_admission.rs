//! Whether a child run may start for the actor it will run as (security
//! review 2026-10-14, G-8).
//!
//! An actor's spend caps were admitted once, when its execution ROW was
//! created. A child run has no row (a recorded decision: child runs are not
//! charged to the actor's hourly EXECUTION budget), so a run admitted once
//! could start any number of children — a `loop` of 100 over an `ensemble`
//! of 10 is a thousand children — and a child bound to another actor spent
//! that actor's fuel without that actor ever being asked.
//!
//! The engine asks this port before each child run, for the actor the child
//! runs AS (its own bound actor, or the parent's it inherits). The controller
//! answers from the actor's hourly FUEL cap; an `Err` carries the sentence
//! the child's error envelope shows. A port that cannot answer must refuse:
//! this is a spend gate.

use async_trait::async_trait;
use uuid::Uuid;

/// See the module docs.
#[async_trait]
pub trait ChildRunAdmission: Send + Sync {
    /// `Ok(())` to start a child run as `actor_id`; `Err(reason)` to refuse.
    async fn admit_child_run(&self, actor_id: Uuid) -> Result<(), String>;
}
