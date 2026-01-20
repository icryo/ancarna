//! Bearer token authentication

use anyhow::Result;
use async_trait::async_trait;

use super::AuthHandler;

/// Bearer token authentication handler
pub struct BearerAuth {
    token: String,
}

impl BearerAuth {
    pub fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
        }
    }
}

#[async_trait]
impl AuthHandler for BearerAuth {
    async fn get_auth_header(&self) -> Result<String> {
        Ok(format!("Bearer {}", self.token))
    }

    async fn refresh(&mut self) -> Result<()> {
        // Static bearer token doesn't need refresh
        Ok(())
    }

    fn is_expired(&self) -> bool {
        false
    }
}
