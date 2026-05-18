// Integrations endpoints (`/api/integrations`, `/api/briefing/latest`)
// moved to the `talos-integrations` workspace crate.
#![allow(unused_imports)]
pub use talos_integrations::*;

pub mod handlers {
    pub use talos_integrations::handlers::*;
}
pub mod provider_config {
    pub use talos_integrations::provider_config::*;
}
