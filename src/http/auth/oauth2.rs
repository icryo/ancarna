//! OAuth 2.0 authentication

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use super::AuthHandler;

/// OAuth 2.0 authentication handler
pub struct OAuth2Auth {
    /// Client ID
    client_id: String,
    /// Client secret
    client_secret: Option<String>,
    /// Token endpoint URL
    token_url: String,
    /// Grant type
    grant_type: OAuth2GrantType,
    /// Scope
    scope: Option<String>,
    /// Cached access token
    access_token: Option<String>,
    /// Refresh token
    refresh_token: Option<String>,
    /// Token expiration timestamp
    expires_at: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
pub enum OAuth2GrantType {
    ClientCredentials,
    AuthorizationCode,
    Password,
    RefreshToken,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

impl OAuth2Auth {
    pub fn new(client_id: &str, token_url: &str, grant_type: OAuth2GrantType) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: None,
            token_url: token_url.to_string(),
            grant_type,
            scope: None,
            access_token: None,
            refresh_token: None,
            expires_at: None,
        }
    }

    pub fn with_secret(mut self, secret: &str) -> Self {
        self.client_secret = Some(secret.to_string());
        self
    }

    pub fn with_scope(mut self, scope: &str) -> Self {
        self.scope = Some(scope.to_string());
        self
    }

    /// Fetch a new access token
    pub async fn fetch_token(&mut self) -> Result<()> {
        let client = reqwest::Client::new();

        let mut params = vec![("client_id", self.client_id.clone())];

        if let Some(secret) = &self.client_secret {
            params.push(("client_secret", secret.clone()));
        }

        if let Some(scope) = &self.scope {
            params.push(("scope", scope.clone()));
        }

        match self.grant_type {
            OAuth2GrantType::ClientCredentials => {
                params.push(("grant_type", "client_credentials".to_string()));
            }
            OAuth2GrantType::RefreshToken => {
                params.push(("grant_type", "refresh_token".to_string()));
                if let Some(token) = &self.refresh_token {
                    params.push(("refresh_token", token.clone()));
                }
            }
            _ => {
                // Other grant types need additional parameters
                return Err(anyhow::anyhow!("Grant type requires additional parameters"));
            }
        }

        let response = client
            .post(&self.token_url)
            .form(&params)
            .send()
            .await
            .context("Failed to request token")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Token request failed: {} - {}", status, body));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .context("Failed to parse token response")?;

        self.access_token = Some(token_response.access_token);
        self.refresh_token = token_response.refresh_token;

        if let Some(expires_in) = token_response.expires_in {
            self.expires_at = Some(chrono::Utc::now().timestamp() + expires_in);
        }

        Ok(())
    }
}

#[async_trait]
impl AuthHandler for OAuth2Auth {
    async fn get_auth_header(&self) -> Result<String> {
        let token = self
            .access_token
            .as_ref()
            .context("No access token available")?;
        Ok(format!("Bearer {}", token))
    }

    async fn refresh(&mut self) -> Result<()> {
        self.fetch_token().await
    }

    fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => chrono::Utc::now().timestamp() >= exp,
            None => false,
        }
    }
}
