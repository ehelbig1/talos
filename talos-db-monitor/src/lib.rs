//! Database query monitoring and performance tracking.
//!
//! Tracks:
//! - Query execution times
//! - Slow query detection
//! - Query patterns
//! - Performance metrics

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Query execution metrics
#[derive(Debug, Clone)]
pub struct QueryMetrics {
    pub query_hash: String,
    pub execution_count: u64,
    pub total_duration_ms: u64,
    pub avg_duration_ms: u64,
    pub max_duration_ms: u64,
    pub slow_count: u64,
    pub last_executed: Option<Instant>,
}

impl QueryMetrics {
    /// Get average execution time using checked division
    pub fn avg_duration_ms(&self) -> u64 {
        self.total_duration_ms
            .checked_div(self.execution_count)
            .unwrap_or(0)
    }

    /// Get percentage of slow queries
    pub fn slow_percentage(&self) -> f64 {
        if self.execution_count == 0 {
            0.0
        } else {
            (self.slow_count as f64 / self.execution_count as f64) * 100.0
        }
    }
}

/// Query monitor for tracking database performance
#[derive(Debug, Clone)]
pub struct QueryMonitor {
    metrics: Arc<RwLock<HashMap<String, QueryMetrics>>>,
    slow_threshold_ms: u64,
}

impl QueryMonitor {
    /// Create a new query monitor
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            slow_threshold_ms: 100, // Default 100ms threshold
        }
    }

    /// Record a query execution
    pub async fn record_query(&self, query_hash: &str, duration_ms: u64) {
        let mut metrics = self.metrics.write().await;
        let entry = metrics
            .entry(query_hash.to_string())
            .or_insert_with(|| QueryMetrics {
                query_hash: query_hash.to_string(),
                execution_count: 0,
                total_duration_ms: 0,
                avg_duration_ms: 0,
                max_duration_ms: 0,
                slow_count: 0,
                last_executed: None,
            });

        entry.execution_count += 1;
        entry.total_duration_ms += duration_ms;
        entry.avg_duration_ms = entry.total_duration_ms / entry.execution_count;
        if duration_ms > entry.max_duration_ms {
            entry.max_duration_ms = duration_ms;
        }
        if duration_ms > self.slow_threshold_ms {
            entry.slow_count += 1;
        }
        entry.last_executed = Some(Instant::now());
    }

    /// Get all metrics
    pub async fn get_metrics(&self) -> Vec<QueryMetrics> {
        let metrics = self.metrics.read().await;
        metrics.values().cloned().collect()
    }

    /// Export metrics for Prometheus
    pub async fn export_prometheus_metrics(&self) {
        let query_metrics = self.get_metrics().await;

        for m in query_metrics {
            // These would need to be added to TalosMetrics
            tracing::info!(
                query_hash = %m.query_hash,
                execution_count = m.execution_count,
                avg_duration_ms = m.avg_duration_ms,
                max_duration_ms = m.max_duration_ms,
                slow_count = m.slow_count,
                "Query metrics"
            );
        }
    }
}

impl Default for QueryMonitor {
    fn default() -> Self {
        Self::new()
    }
}
