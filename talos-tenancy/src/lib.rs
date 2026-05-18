// MCP-941 (2026-05-15): kept `#![allow(dead_code)]` deliberately. The
// crate is a documented placeholder per MCP-704 (controller/src/main.rs
// around line 897): `TenantIsolation::new()` is NOT wired into
// controller boot — tenant isolation is actually enforced at the
// repository layer via per-user / per-org SQL gates. The
// `limits_cache` field has no reader until a real consumer is built.
// Removing the attribute would surface the dead-field warning on
// every workspace build without any operator-actionable cleanup.
// Sibling of `talos-feature-flags`'s MCP-940 placeholder retention.
#![allow(dead_code)]
//! Multi-tenancy isolation and resource limits.
//!
//! Ensures:
//! - Tenant-scoped data access
//! - Resource quotas per tenant
//! - Isolated execution contexts
//! - Cross-tenant access prevention

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Tenant resource limits
#[derive(Debug, Clone)]
pub struct TenantLimits {
    /// Max workflows
    pub max_workflows: u32,
    /// Max active executions
    pub max_executions: u32,
    /// Max secrets
    pub max_secrets: u32,
    /// Max API calls per minute
    pub api_rate_limit: u32,
    /// Max compute time (fuel units)
    pub max_fuel_per_execution: u64,
    /// Max memory per execution (MB)
    pub max_memory_per_execution: u32,
}

impl Default for TenantLimits {
    fn default() -> Self {
        Self {
            max_workflows: 100,
            max_executions: 50,
            max_secrets: 100,
            api_rate_limit: 1000,
            max_fuel_per_execution: 100_000,
            max_memory_per_execution: 256,
        }
    }
}

/// Tenant context
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub tenant_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub limits: TenantLimits,
}

/// Tenant isolation service
pub struct TenantIsolation {
    /// Cached tenant limits
    limits_cache: Arc<RwLock<HashMap<Uuid, TenantLimits>>>,
}

impl TenantIsolation {
    pub fn new() -> Self {
        Self {
            limits_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Validate resource access belongs to tenant
    pub fn validate_access(&self, context: &TenantContext, resource_tenant_id: Uuid) -> Result<()> {
        if context.tenant_id != resource_tenant_id {
            return Err(anyhow!(
                "Cross-tenant access denied: {} accessing {}",
                context.tenant_id,
                resource_tenant_id
            ));
        }
        Ok(())
    }

    /// Check if tenant is within resource limits
    pub async fn check_limits(
        &self,
        context: &TenantContext,
        resource_type: &str,
        current_usage: u32,
    ) -> Result<bool> {
        let limit = match resource_type {
            "workflows" => context.limits.max_workflows,
            "executions" => context.limits.max_executions,
            "secrets" => context.limits.max_secrets,
            _ => return Ok(true), // Unknown resource type
        };

        Ok(current_usage < limit)
    }
}

impl Default for TenantIsolation {
    fn default() -> Self {
        Self::new()
    }
}
