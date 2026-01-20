//! Digest authentication

use anyhow::Result;
use async_trait::async_trait;

use super::AuthHandler;

/// Digest authentication handler
pub struct DigestAuth {
    username: String,
    password: String,
    // Digest auth challenge parameters (populated after first request)
    realm: Option<String>,
    nonce: Option<String>,
    qop: Option<String>,
    nc: u32,
    cnonce: String,
    // Stored method and URI for pre-emptive auth via get_auth_header
    method: String,
    uri: String,
}

impl DigestAuth {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            realm: None,
            nonce: None,
            qop: None,
            nc: 0,
            cnonce: uuid::Uuid::new_v4().to_string().replace("-", "")[..16].to_string(),
            method: "GET".to_string(),
            uri: "/".to_string(),
        }
    }

    /// Set the HTTP method and URI for pre-emptive authentication
    pub fn with_request(mut self, method: &str, uri: &str) -> Self {
        self.method = method.to_string();
        self.uri = uri.to_string();
        self
    }

    /// Set method and URI (mutable version)
    pub fn set_request(&mut self, method: &str, uri: &str) {
        self.method = method.to_string();
        self.uri = uri.to_string();
    }

    /// Parse WWW-Authenticate header from 401 response
    pub fn parse_challenge(&mut self, www_authenticate: &str) -> Result<()> {
        // Parse digest challenge parameters
        // Format: Digest realm="...", nonce="...", qop="...", ...
        for part in www_authenticate.trim_start_matches("Digest ").split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let value = value.trim_matches('"');
                match key.trim() {
                    "realm" => self.realm = Some(value.to_string()),
                    "nonce" => self.nonce = Some(value.to_string()),
                    "qop" => self.qop = Some(value.to_string()),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Generate digest response for a request
    pub fn generate_response(&mut self, method: &str, uri: &str) -> Result<String> {
        let realm = self.realm.as_deref().unwrap_or("");
        let nonce = self.nonce.as_deref().unwrap_or("");

        self.nc += 1;
        let nc = format!("{:08x}", self.nc);

        // Calculate HA1 = MD5(username:realm:password)
        let ha1_input = format!("{}:{}:{}", self.username, realm, self.password);
        let ha1 = format!("{:x}", md5::compute(ha1_input.as_bytes()));

        // Calculate HA2 = MD5(method:uri)
        let ha2_input = format!("{}:{}", method, uri);
        let ha2 = format!("{:x}", md5::compute(ha2_input.as_bytes()));

        // Calculate response
        let response_input = if self.qop.is_some() {
            format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, self.cnonce, ha2)
        } else {
            format!("{}:{}:{}", ha1, nonce, ha2)
        };
        let response = format!("{:x}", md5::compute(response_input.as_bytes()));

        // Build Authorization header
        let mut auth = format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}""#,
            self.username, realm, nonce, uri, response
        );

        if self.qop.is_some() {
            auth.push_str(&format!(
                r#", qop=auth, nc={}, cnonce="{}""#,
                nc, self.cnonce
            ));
        }

        Ok(auth)
    }
}

#[async_trait]
impl AuthHandler for DigestAuth {
    async fn get_auth_header(&self) -> Result<String> {
        // If no challenge has been received, cannot generate valid digest
        if self.nonce.is_none() {
            return Err(anyhow::anyhow!(
                "Digest auth requires server challenge (WWW-Authenticate header). \
                 Send an initial unauthenticated request first."
            ));
        }

        // Generate response using stored method and URI
        // Note: This is a workaround since we need &mut self for nc increment
        // In practice, the caller should use generate_response() directly
        let realm = self.realm.as_deref().unwrap_or("");
        let nonce = self.nonce.as_deref().unwrap_or("");
        let nc = format!("{:08x}", self.nc + 1);

        // Calculate HA1 = MD5(username:realm:password)
        let ha1_input = format!("{}:{}:{}", self.username, realm, self.password);
        let ha1 = format!("{:x}", md5::compute(ha1_input.as_bytes()));

        // Calculate HA2 = MD5(method:uri)
        let ha2_input = format!("{}:{}", self.method, self.uri);
        let ha2 = format!("{:x}", md5::compute(ha2_input.as_bytes()));

        // Calculate response
        let response_input = if self.qop.is_some() {
            format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, self.cnonce, ha2)
        } else {
            format!("{}:{}:{}", ha1, nonce, ha2)
        };
        let response = format!("{:x}", md5::compute(response_input.as_bytes()));

        // Build Authorization header
        let mut auth = format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}""#,
            self.username, realm, nonce, self.uri, response
        );

        if self.qop.is_some() {
            auth.push_str(&format!(
                r#", qop=auth, nc={}, cnonce="{}""#,
                nc, self.cnonce
            ));
        }

        Ok(auth)
    }

    async fn refresh(&mut self) -> Result<()> {
        // Reset nonce count for new challenge
        self.nc = 0;
        self.nonce = None;
        self.realm = None;
        Ok(())
    }

    fn is_expired(&self) -> bool {
        // Digest auth can expire if nonce becomes stale
        // For now, consider it valid if we have a nonce
        self.nonce.is_none()
    }
}
