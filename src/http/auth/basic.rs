//! Basic authentication

use anyhow::Result;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};

use super::AuthHandler;

/// Basic authentication handler
pub struct BasicAuth {
    username: String,
    password: String,
}

impl BasicAuth {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

#[async_trait]
impl AuthHandler for BasicAuth {
    async fn get_auth_header(&self) -> Result<String> {
        let credentials = format!("{}:{}", self.username, self.password);
        let encoded = STANDARD.encode(credentials);
        Ok(format!("Basic {}", encoded))
    }

    async fn refresh(&mut self) -> Result<()> {
        // Basic auth doesn't need refresh
        Ok(())
    }

    fn is_expired(&self) -> bool {
        false
    }
}
