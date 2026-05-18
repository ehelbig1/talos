//! Structured error types for Talos controller.
//!
//! This module provides strongly-typed errors with:
//! - HTTP status code mapping
//! - User-friendly error messages
//! - Error categorization for monitoring
//! - Structured logging support

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::fmt;

/// Categorizes errors for monitoring and alerting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Authentication errors (invalid credentials, expired tokens)
    Authentication,
    /// Authorization errors (insufficient permissions)
    Authorization,
    /// Validation errors (invalid input, malformed data)
    Validation,
    /// Resource not found
    NotFound,
    /// Rate limiting
    RateLimit,
    /// Database errors
    Database,
    /// External service errors (Redis, NATS, etc.)
    ExternalService,
    /// Internal server errors
    Internal,
    /// Configuration errors
    Configuration,
}

impl ErrorCategory {
    /// Get the HTTP status code for this error category
    pub fn status_code(self) -> StatusCode {
        match self {
            ErrorCategory::Authentication => StatusCode::UNAUTHORIZED,
            ErrorCategory::Authorization => StatusCode::FORBIDDEN,
            ErrorCategory::Validation => StatusCode::BAD_REQUEST,
            ErrorCategory::NotFound => StatusCode::NOT_FOUND,
            ErrorCategory::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            ErrorCategory::Database => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCategory::ExternalService => StatusCode::BAD_GATEWAY,
            ErrorCategory::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCategory::Configuration => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get a short code for logging/metrics
    pub fn code(self) -> &'static str {
        match self {
            ErrorCategory::Authentication => "AUTH",
            ErrorCategory::Authorization => "AUTHZ",
            ErrorCategory::Validation => "VALID",
            ErrorCategory::NotFound => "NOT_FOUND",
            ErrorCategory::RateLimit => "RATE_LIMIT",
            ErrorCategory::Database => "DB",
            ErrorCategory::ExternalService => "EXT_SVC",
            ErrorCategory::Internal => "INTERNAL",
            ErrorCategory::Configuration => "CONFIG",
        }
    }
}

/// Structured application error
#[derive(Debug)]
pub struct AppError {
    pub category: ErrorCategory,
    pub message: String,
    pub details: Option<String>,
    pub request_id: Option<String>,
    pub user_message: String,
}

impl AppError {
    /// Create a new authentication error
    pub fn authentication(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            category: ErrorCategory::Authentication,
            user_message: "Authentication failed. Please check your credentials.".to_string(),
            message,
            details: None,
            request_id: None,
        }
    }

    /// Create a new authorization error
    pub fn authorization(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            category: ErrorCategory::Authorization,
            user_message: "You do not have permission to perform this action.".to_string(),
            message,
            details: None,
            request_id: None,
        }
    }

    /// Create a new validation error
    pub fn validation(field: impl AsRef<str>, message: impl Into<String>) -> Self {
        let message = message.into();
        let field = field.as_ref();
        Self {
            category: ErrorCategory::Validation,
            user_message: format!("Invalid input for '{}': {}", field, message),
            message: format!("Validation failed for field '{}': {}", field, message),
            details: None,
            request_id: None,
        }
    }

    /// Create a new not found error
    pub fn not_found(resource: impl AsRef<str>, id: impl AsRef<str>) -> Self {
        let resource = resource.as_ref();
        let id = id.as_ref();
        Self {
            category: ErrorCategory::NotFound,
            user_message: format!("{} not found.", resource),
            message: format!("{} with id '{}' not found", resource, id),
            details: None,
            request_id: None,
        }
    }

    /// Create a new rate limit error
    pub fn rate_limit(resource: impl AsRef<str>, retry_after_secs: u64) -> Self {
        let resource = resource.as_ref();
        Self {
            category: ErrorCategory::RateLimit,
            user_message: format!(
                "Rate limit exceeded for {}. Please try again in {} seconds.",
                resource, retry_after_secs
            ),
            message: format!("Rate limit exceeded for {}", resource),
            details: Some(format!("Retry after: {}s", retry_after_secs)),
            request_id: None,
        }
    }

    /// Create a new database error
    pub fn database(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            category: ErrorCategory::Database,
            user_message: "A database error occurred. Please try again later.".to_string(),
            message,
            details: None,
            request_id: None,
        }
    }

    /// Create a new external service error
    pub fn external_service(service: impl AsRef<str>, message: impl Into<String>) -> Self {
        let service = service.as_ref();
        let message = message.into();
        Self {
            category: ErrorCategory::ExternalService,
            user_message: format!(
                "The {} service is temporarily unavailable. Please try again later.",
                service
            ),
            message: format!("External service error ({}): {}", service, message),
            details: None,
            request_id: None,
        }
    }

    /// Create a new internal error
    pub fn internal(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            category: ErrorCategory::Internal,
            user_message: "An internal error occurred. Please try again later.".to_string(),
            message,
            details: None,
            request_id: None,
        }
    }

    /// Create a new configuration error
    pub fn configuration(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            category: ErrorCategory::Configuration,
            user_message: "Service is misconfigured. Please contact support.".to_string(),
            message: format!("Configuration error: {}", message),
            details: None,
            request_id: None,
        }
    }

    /// Add request ID for correlation
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Add internal details (not exposed to client)
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Get the HTTP status code
    pub fn status_code(&self) -> StatusCode {
        self.category.status_code()
    }

    /// Get the error code for metrics
    pub fn error_code(&self) -> &'static str {
        self.category.code()
    }

    /// Log this error with appropriate level
    pub fn log(&self) {
        let request_id = self.request_id.as_deref().unwrap_or("unknown");
        match self.category {
            ErrorCategory::Authentication
            | ErrorCategory::Authorization
            | ErrorCategory::RateLimit => {
                tracing::warn!(
                    request_id = request_id,
                    error_code = self.error_code(),
                    message = %self.message,
                    "Client error"
                );
            }
            ErrorCategory::Validation | ErrorCategory::NotFound => {
                tracing::info!(
                    request_id = request_id,
                    error_code = self.error_code(),
                    message = %self.message,
                    "Client validation error"
                );
            }
            ErrorCategory::Database
            | ErrorCategory::ExternalService
            | ErrorCategory::Internal
            | ErrorCategory::Configuration => {
                tracing::error!(
                    request_id = request_id,
                    error_code = self.error_code(),
                    message = %self.message,
                    details = ?self.details,
                    "Server error"
                );
            }
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.error_code(), self.message)
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Log the error before responding
        self.log();

        let body = json!({
            "error": {
                "code": self.error_code(),
                "message": self.user_message,
                "request_id": self.request_id,
            }
        });

        (self.status_code(), Json(body)).into_response()
    }
}

/// Convert anyhow::Error to AppError
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::internal(err.to_string())
    }
}

/// Convert sqlx::Error to AppError
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => AppError::not_found("resource", "unknown"),
            sqlx::Error::Database(db_err) => {
                // Check for specific database error codes
                if db_err.is_unique_violation() {
                    AppError::validation("id", "already exists")
                } else {
                    AppError::database(db_err.to_string())
                }
            }
            _ => AppError::database(err.to_string()),
        }
    }
}

/// Convert bcrypt errors
impl From<bcrypt::BcryptError> for AppError {
    fn from(_: bcrypt::BcryptError) -> Self {
        AppError::internal("Password hashing error")
    }
}

/// Convert JWT errors
impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                AppError::authentication("Token has expired")
            }
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                AppError::authentication("Invalid token format")
            }
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                AppError::authentication("Invalid token signature")
            }
            _ => AppError::authentication("Token validation failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_category_status_codes() {
        assert_eq!(
            ErrorCategory::Authentication.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ErrorCategory::Authorization.status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(ErrorCategory::NotFound.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(
            ErrorCategory::RateLimit.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_app_error_creation() {
        let err = AppError::authentication("Invalid credentials");
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(err.error_code(), "AUTH");

        let err = AppError::not_found("user", "12345");
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
        assert!(err.message.contains("user"));
        assert!(err.message.contains("12345"));
    }

    #[test]
    fn test_app_error_with_request_id() {
        let err = AppError::validation("email", "invalid format").with_request_id("req-12345");
        assert_eq!(err.request_id, Some("req-12345".to_string()));
    }
}
