//! JWT authentication

use anyhow::{Context, Result};
use async_trait::async_trait;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::AuthHandler;

/// JWT authentication handler
pub struct JwtAuth {
    secret: String,
    algorithm: Algorithm,
    claims: JwtClaims,
    cached_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issued at
    pub iat: i64,
    /// Expiration
    pub exp: i64,
    /// Subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl JwtAuth {
    pub fn new(secret: &str, algorithm: &str) -> Result<Self> {
        let alg = match algorithm.to_uppercase().as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            "ES256" => Algorithm::ES256,
            "ES384" => Algorithm::ES384,
            _ => Algorithm::HS256,
        };

        Ok(Self {
            secret: secret.to_string(),
            algorithm: alg,
            claims: JwtClaims::default(),
            cached_token: None,
        })
    }

    pub fn with_claims(mut self, claims: HashMap<String, serde_json::Value>) -> Self {
        self.claims.custom = claims;
        self
    }

    pub fn with_subject(mut self, sub: &str) -> Self {
        self.claims.sub = Some(sub.to_string());
        self
    }

    pub fn with_issuer(mut self, iss: &str) -> Self {
        self.claims.iss = Some(iss.to_string());
        self
    }

    pub fn with_expiration(mut self, exp_seconds: i64) -> Self {
        let now = chrono::Utc::now().timestamp();
        self.claims.iat = now;
        self.claims.exp = now + exp_seconds;
        self
    }

    fn generate_token(&self) -> Result<String> {
        let header = Header::new(self.algorithm);
        let key = EncodingKey::from_secret(self.secret.as_bytes());

        encode(&header, &self.claims, &key).context("Failed to generate JWT")
    }
}

impl Default for JwtClaims {
    fn default() -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            iat: now,
            exp: now + 3600, // 1 hour default
            sub: None,
            iss: None,
            aud: None,
            custom: HashMap::new(),
        }
    }
}

#[async_trait]
impl AuthHandler for JwtAuth {
    async fn get_auth_header(&self) -> Result<String> {
        let token = self.generate_token()?;
        Ok(format!("Bearer {}", token))
    }

    async fn refresh(&mut self) -> Result<()> {
        self.cached_token = None;
        Ok(())
    }

    fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.claims.exp <= now
    }
}
