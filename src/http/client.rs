//! HTTP client implementation

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, Instant};

use super::auth::AuthHandler;
use super::request::{AuthConfig, Request};
use super::response::{Response, ResponseTiming};
use crate::app::Config;

/// HTTP client wrapper
pub struct HttpClient {
    /// Inner reqwest client
    client: reqwest::Client,

    /// Default timeout
    default_timeout: Duration,

    /// Follow redirects by default
    follow_redirects: bool,

    /// User agent string
    user_agent: String,
}

impl HttpClient {
    /// Create a new HTTP client
    pub fn new(config: &Config) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.scanner.request_timeout))
            .redirect(reqwest::redirect::Policy::limited(config.scanner.max_redirects))
            .user_agent(&config.scanner.user_agent)
            .cookie_store(true)
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            default_timeout: Duration::from_secs(config.scanner.request_timeout),
            follow_redirects: config.scanner.follow_redirects,
            user_agent: config.scanner.user_agent.clone(),
        })
    }

    /// Execute a request
    pub async fn execute(&self, request: &Request) -> Result<Response> {
        let start = Instant::now();

        // Build the reqwest request
        let method = reqwest::Method::from_str(&request.method)
            .context("Invalid HTTP method")?;

        let url = request.full_url();

        let mut builder = self.client.request(method, &url);

        // Set headers
        let mut headers = HeaderMap::new();
        for (key, value) in &request.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_str(key),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, val);
            }
        }
        builder = builder.headers(headers);

        // Set body
        if let Some(body) = &request.body {
            builder = builder.body(body.clone());
        }

        // Set timeout
        if let Some(timeout) = request.timeout {
            builder = builder.timeout(Duration::from_secs(timeout));
        }

        // Apply authentication
        if let Some(auth_config) = &request.auth {
            builder = self.apply_auth(builder, auth_config).await?;
        }

        // Execute request
        let response = builder.send().await.context("Request failed")?;

        let duration = start.elapsed();

        // Build response
        self.build_response(response, duration).await
    }

    /// Apply authentication to request builder
    async fn apply_auth(
        &self,
        mut builder: reqwest::RequestBuilder,
        auth: &AuthConfig,
    ) -> Result<reqwest::RequestBuilder> {
        match auth {
            AuthConfig::None => {}
            AuthConfig::Basic { username, password } => {
                builder = builder.basic_auth(username, Some(password));
            }
            AuthConfig::Bearer { token } => {
                builder = builder.bearer_auth(token);
            }
            AuthConfig::ApiKey { key, value, in_header } => {
                if *in_header {
                    builder = builder.header(key.as_str(), value.as_str());
                }
                // Query param handled in request.full_url()
            }
            AuthConfig::Digest { username, password } => {
                // Digest auth requires the server's challenge first
                // For the initial request, we don't add auth - server will respond with 401
                // and WWW-Authenticate header containing the challenge.
                // The caller should then retry with the digest response.
                // For simplicity in single requests, we generate a pre-emptive digest
                // using a placeholder nonce (some servers accept this).
                let mut digest_auth = crate::http::auth::DigestAuth::new(username, password);
                // Use a default realm and generate a placeholder response
                // This works with some servers but proper implementation would need
                // to handle the 401 challenge-response flow
                digest_auth.parse_challenge(r#"Digest realm="default", nonce="placeholder""#)?;
                if let Ok(auth_header) = digest_auth.generate_response("GET", "/") {
                    builder = builder.header("Authorization", auth_header);
                    tracing::debug!("Applied digest auth (pre-emptive mode)");
                }
            }
            AuthConfig::OAuth2 { .. } => {
                // OAuth2 token should be obtained first via token endpoint
                tracing::warn!("OAuth2 token should be obtained before request");
            }
            AuthConfig::Jwt { secret, algorithm, claims } => {
                // Generate JWT token and add as bearer auth
                let jwt_auth = crate::http::auth::JwtAuth::new(secret, algorithm)?
                    .with_expiration(3600); // 1 hour default

                // Add custom claims if provided
                let jwt_auth = if !claims.is_empty() {
                    jwt_auth.with_claims(claims.clone())
                } else {
                    jwt_auth
                };

                let auth_header = jwt_auth.get_auth_header().await?;
                builder = builder.header("Authorization", auth_header);
                tracing::debug!("Applied JWT auth");
            }
        }

        Ok(builder)
    }

    /// Build response from reqwest response
    async fn build_response(
        &self,
        response: reqwest::Response,
        duration: Duration,
    ) -> Result<Response> {
        let status = response.status().as_u16();
        let status_text = response
            .status()
            .canonical_reason()
            .unwrap_or("")
            .to_string();

        let http_version = format!("{:?}", response.version());
        let remote_addr = response.remote_addr().map(|a| a.to_string());

        // Convert headers
        let mut headers = HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(key.as_str().to_string(), v.to_string());
            }
        }

        // Extract cookies
        let cookies: Vec<super::response::Cookie> = response
            .cookies()
            .map(|c| super::response::Cookie {
                name: c.name().to_string(),
                value: c.value().to_string(),
                domain: c.domain().map(|s| s.to_string()),
                path: c.path().map(|s| s.to_string()),
                expires: None, // Would need to parse from raw cookie
                max_age: c.max_age().map(|d| d.as_secs() as i64),
                secure: c.secure(),
                http_only: c.http_only(),
                same_site: None,
            })
            .collect();

        // Get body
        let body = response.bytes().await.context("Failed to read response body")?;
        let size = body.len();

        Ok(Response {
            status,
            status_text,
            headers,
            body: body.to_vec(),
            duration_ms: duration.as_millis() as u64,
            size,
            http_version,
            remote_addr,
            tls_info: None, // Would need custom TLS handling
            timing: Some(ResponseTiming {
                dns_ms: 0,
                connect_ms: 0,
                tls_ms: None,
                ttfb_ms: 0,
                transfer_ms: 0,
                total_ms: duration.as_millis() as u64,
            }),
            cookies,
        })
    }

    /// Execute a simple GET request
    pub async fn get(&self, url: &str) -> Result<Response> {
        let request = Request::new("GET", url);
        self.execute(&request).await
    }

    /// Execute a simple POST request with JSON body
    pub async fn post_json<T: serde::Serialize>(&self, url: &str, body: &T) -> Result<Response> {
        let request = Request::builder()
            .method("POST")
            .url(url)
            .json(body)
            .build();
        self.execute(&request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let config = Config::default();
        let client = HttpClient::new(&config);
        assert!(client.is_ok());
    }
}
