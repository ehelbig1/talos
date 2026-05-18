//! Graceful shutdown handling for Talos controller.
//!
//! Provides clean shutdown with:
//! - Signal handling (SIGTERM, SIGINT)
//! - Connection draining
//! - In-flight request completion
//! - Resource cleanup

use std::sync::Arc;
use tokio::signal;
use tokio::sync::{mpsc, RwLock};

/// Shutdown coordinator
#[derive(Debug, Clone)]
pub struct ShutdownCoordinator {
    shutdown_tx: mpsc::Sender<()>,
    state: Arc<RwLock<ShutdownState>>,
}

#[derive(Debug)]
enum ShutdownState {
    Running,
    ShuttingDown,
    ShutDown,
}

/// Shutdown handle for components
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    state: Arc<RwLock<ShutdownState>>,
}

impl ShutdownHandle {
    /// Check if shutdown has been initiated
    pub async fn is_shutting_down(&self) -> bool {
        let state = self.state.read().await;
        matches!(
            *state,
            ShutdownState::ShuttingDown | ShutdownState::ShutDown
        )
    }

    /// Check if fully shut down
    pub async fn is_shutdown(&self) -> bool {
        let state = self.state.read().await;
        matches!(*state, ShutdownState::ShutDown)
    }
}

impl ShutdownCoordinator {
    /// Create new shutdown coordinator
    pub fn new() -> (Self, mpsc::Receiver<()>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let state = Arc::new(RwLock::new(ShutdownState::Running));

        let coordinator = Self {
            shutdown_tx,
            state: state.clone(),
        };

        (coordinator, shutdown_rx)
    }

    /// Get a shutdown handle
    pub fn handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            state: self.state.clone(),
        }
    }

    /// Initiate shutdown
    pub async fn shutdown(&self) {
        tracing::info!("Initiating graceful shutdown...");

        {
            let mut state = self.state.write().await;
            *state = ShutdownState::ShuttingDown;
        }

        // Notify all listeners
        let _ = self.shutdown_tx.send(()).await;

        tracing::info!("Shutdown signal sent to all components");
    }

    /// Mark as fully shut down
    pub async fn complete(&self) {
        let mut state = self.state.write().await;
        *state = ShutdownState::ShutDown;
        tracing::info!("Shutdown complete");
    }
}

/// Wait for shutdown signal.
///
/// MCP-501: the pre-fix code matched its own comment incorrectly.
/// "Continue with shutdown anyway - we can still receive SIGINT"
/// was followed by an immediate `return`, so a SIGTERM-install
/// failure caused `wait_for_shutdown` to return synchronously —
/// triggering instant graceful-shutdown on the caller at startup
/// instead of waiting for a real signal. Same shape on the SIGINT
/// branch. Now each handler is installed independently; only when
/// BOTH fail do we return without waiting (and log an error so the
/// operator knows the binary is unable to receive graceful-shutdown
/// signals).
pub async fn wait_for_shutdown() {
    let sigterm_install = signal::unix::signal(signal::unix::SignalKind::terminate());
    let sigint_install = signal::unix::signal(signal::unix::SignalKind::interrupt());

    let mut sigterm = match sigterm_install {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::error!("Failed to install SIGTERM handler: {}", e);
            None
        }
    };
    let mut sigint = match sigint_install {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::error!("Failed to install SIGINT handler: {}", e);
            None
        }
    };

    match (&mut sigterm, &mut sigint) {
        (Some(t), Some(i)) => {
            tokio::select! {
                _ = t.recv() => {
                    tracing::info!("Received SIGTERM, initiating shutdown");
                }
                _ = i.recv() => {
                    tracing::info!("Received SIGINT, initiating shutdown");
                }
            }
        }
        (Some(t), None) => {
            t.recv().await;
            tracing::info!("Received SIGTERM, initiating shutdown");
        }
        (None, Some(i)) => {
            i.recv().await;
            tracing::info!("Received SIGINT, initiating shutdown");
        }
        (None, None) => {
            tracing::error!(
                "Both SIGTERM and SIGINT handlers failed to install — \
                 wait_for_shutdown cannot block on a signal. Returning so \
                 the caller's shutdown path runs; this binary will not \
                 receive graceful-shutdown signals and must be SIGKILLed."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_coordinator() {
        let (coordinator, mut rx) = ShutdownCoordinator::new();
        let handle = coordinator.handle();

        // Initially not shutting down
        assert!(!handle.is_shutting_down().await);

        // Initiate shutdown
        coordinator.shutdown().await;

        // Should be shutting down
        assert!(handle.is_shutting_down().await);

        // Signal should be sent
        assert!(rx.recv().await.is_some());
    }
}
