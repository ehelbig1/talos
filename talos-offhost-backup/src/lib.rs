//! Off-host backup egress (Tier 2) — the pure half.
//!
//! # Why this crate exists
//!
//! Tier 1 (2026-08-13) escrowed the master KEK, so the restore drill's claim
//! became *"these artifacts + the escrowed KEK ⇒ readable data"*. The half
//! that stayed open is where the artifacts LIVE: `$BACKUP_DIR` on one laptop
//! SSD. Losing that disk loses 22,360 module payloads, 7,122 workflow
//! outputs, and — the only genuinely irreplaceable slice — 1,544
//! `ml_examples` plus 384 `ml_disagreements`, a month of human labelling
//! that cannot be regenerated at any price. Code re-clones; labels do not.
//!
//! # Why it is a separate, dependency-light crate
//!
//! Following `cosign_verify_argv` (`talos-worker-runtime`): the
//! security-critical parts are PURE FUNCTIONS so they are unit-tested
//! without invoking the tool. Here that means the object key, the `aws`
//! argv, the retention/freshness arithmetic, the failure classification and
//! the metric rendering are all exercised offline. The B2 bucket, the
//! application key and the `age` passphrase do not exist yet and require the
//! operator's account; nothing in this crate needs them to be tested.
//!
//! # What is enforced HERE, and what is not
//!
//! "Append-only" is three separate things and only one of them is code:
//!
//! | Property | Enforced by |
//! |---|---|
//! | Unique, timestamped, non-reusable object keys | **this crate** ([`object_key`]) |
//! | Never PUT over a key that already exists | **this crate**, by a pre-flight `head-object` — see the TOCTOU note on [`aws::head_object_argv`] |
//! | The credential physically cannot delete or overwrite | **the operator's B2 application key** (no `deleteFiles`) — this crate cannot check it, only PROBE it (`probe-append-only`) |
//! | Old versions survive a hostile overwrite | **the operator's bucket lifecycle/versioning rule**, set with the MASTER key so the host credential cannot shorten its own retention |
//!
//! The first two are guards that a racing or malicious writer defeats. The
//! last two are the actual controls, and neither of them lives here. Saying
//! so is the point: describing a convention as a control is the defect class
//! this whole area of the repo has been burning down.
//!
//! # Residual risk, stated plainly
//!
//! The upload credential lives on the host it protects. **It is
//! compromised if the host is compromised** — there is no way around that
//! for an unattended push. What the design buys is that an attacker holding
//! it can only ADD objects: they cannot delete yesterday's archive and they
//! cannot overwrite it, so recoverability survives. Retention plus distinct
//! keys is the whole of that guarantee, and both are properties of the
//! bucket, not of this code.

pub mod aws;
pub mod classify;
pub mod crypto;
pub mod key;
pub mod metrics;
pub mod passphrase;
pub mod plan;

pub use aws::S3Target;
pub use classify::FailureReason;
pub use key::{object_key, ArtifactKind, KeyError, Stamp};
pub use plan::{LocalArtifact, UploadMode};
