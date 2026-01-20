//! Authentication handlers

mod basic;
mod bearer;
mod digest;
mod jwt;
mod oauth2;

pub use basic::BasicAuth;
pub use bearer::BearerAuth;
pub use digest::DigestAuth;
pub use jwt::JwtAuth;
pub use oauth2::OAuth2Auth;

use anyhow::Result;
use async_trait::async_trait;

/// Trait for authentication handlers
#[async_trait]
pub trait AuthHandler {
    /// Get the authorization header value
    async fn get_auth_header(&self) -> Result<String>;

    /// Refresh credentials if needed
    async fn refresh(&mut self) -> Result<()>;

    /// Check if credentials are expired
    fn is_expired(&self) -> bool;
}
