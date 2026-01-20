//! HTTP request types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// HTTP request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Unique request ID
    pub id: String,

    /// Request name/label
    pub name: String,

    /// HTTP method
    pub method: String,

    /// Request URL
    pub url: String,

    /// Request headers
    pub headers: HashMap<String, String>,

    /// Query parameters
    pub params: HashMap<String, String>,

    /// Request body
    pub body: Option<String>,

    /// Body content type
    pub content_type: Option<ContentType>,

    /// Authentication configuration
    pub auth: Option<AuthConfig>,

    /// Pre-request script
    pub pre_script: Option<String>,

    /// Post-request script
    pub post_script: Option<String>,

    /// Request timeout in seconds
    pub timeout: Option<u64>,

    /// Follow redirects
    pub follow_redirects: bool,
}

/// Content type for request body
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentType {
    Json,
    Form,
    Multipart,
    Xml,
    Text,
    Binary,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    None,
    Basic {
        username: String,
        password: String,
    },
    Bearer {
        token: String,
    },
    Digest {
        username: String,
        password: String,
    },
    OAuth2 {
        grant_type: OAuth2GrantType,
        client_id: String,
        client_secret: Option<String>,
        token_url: String,
        scope: Option<String>,
    },
    Jwt {
        secret: String,
        algorithm: String,
        claims: HashMap<String, serde_json::Value>,
    },
    ApiKey {
        key: String,
        value: String,
        in_header: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2GrantType {
    ClientCredentials,
    AuthorizationCode,
    Password,
    RefreshToken,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: "New Request".to_string(),
            method: "GET".to_string(),
            url: String::new(),
            headers: HashMap::new(),
            params: HashMap::new(),
            body: None,
            content_type: None,
            auth: None,
            pre_script: None,
            post_script: None,
            timeout: None,
            follow_redirects: true,
        }
    }
}

impl Request {
    /// Create a new request
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            method: method.to_uppercase(),
            url: url.to_string(),
            ..Default::default()
        }
    }

    /// Create a builder for constructing requests
    pub fn builder() -> RequestBuilder {
        RequestBuilder::default()
    }

    /// Get the full URL with query parameters
    pub fn full_url(&self) -> String {
        if self.params.is_empty() {
            return self.url.clone();
        }

        let params: Vec<String> = self
            .params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect();

        if self.url.contains('?') {
            format!("{}&{}", self.url, params.join("&"))
        } else {
            format!("{}?{}", self.url, params.join("&"))
        }
    }
}

/// Builder for constructing requests
#[derive(Debug, Default)]
pub struct RequestBuilder {
    request: Request,
}

impl RequestBuilder {
    /// Set the request method
    pub fn method(mut self, method: &str) -> Self {
        self.request.method = method.to_uppercase();
        self
    }

    /// Set the request URL
    pub fn url(mut self, url: &str) -> Self {
        self.request.url = url.to_string();
        self
    }

    /// Set the request name
    pub fn name(mut self, name: &str) -> Self {
        self.request.name = name.to_string();
        self
    }

    /// Add a header
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.request.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Add multiple headers
    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.request.headers.extend(headers);
        self
    }

    /// Add a query parameter
    pub fn param(mut self, key: &str, value: &str) -> Self {
        self.request.params.insert(key.to_string(), value.to_string());
        self
    }

    /// Set the request body
    pub fn body(mut self, body: &str) -> Self {
        self.request.body = Some(body.to_string());
        self
    }

    /// Set JSON body
    pub fn json<T: Serialize>(mut self, body: &T) -> Self {
        self.request.body = serde_json::to_string_pretty(body).ok();
        self.request.content_type = Some(ContentType::Json);
        self.request
            .headers
            .insert("Content-Type".to_string(), "application/json".to_string());
        self
    }

    /// Set authentication
    pub fn auth(mut self, auth: AuthConfig) -> Self {
        self.request.auth = Some(auth);
        self
    }

    /// Set basic authentication
    pub fn basic_auth(self, username: &str, password: &str) -> Self {
        self.auth(AuthConfig::Basic {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    /// Set bearer token
    pub fn bearer_auth(self, token: &str) -> Self {
        self.auth(AuthConfig::Bearer {
            token: token.to_string(),
        })
    }

    /// Set request timeout
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.request.timeout = Some(seconds);
        self
    }

    /// Set follow redirects
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.request.follow_redirects = follow;
        self
    }

    /// Set pre-request script
    pub fn pre_script(mut self, script: &str) -> Self {
        self.request.pre_script = Some(script.to_string());
        self
    }

    /// Set post-request script
    pub fn post_script(mut self, script: &str) -> Self {
        self.request.post_script = Some(script.to_string());
        self
    }

    /// Build the request
    pub fn build(self) -> Request {
        self.request
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_builder() {
        let req = Request::builder()
            .method("POST")
            .url("https://api.example.com/users")
            .header("X-Custom", "value")
            .param("page", "1")
            .body(r#"{"name": "test"}"#)
            .build();

        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "https://api.example.com/users");
        assert_eq!(req.headers.get("X-Custom"), Some(&"value".to_string()));
        assert_eq!(req.params.get("page"), Some(&"1".to_string()));
    }

    #[test]
    fn test_full_url() {
        let req = Request::builder()
            .url("https://api.example.com/users")
            .param("page", "1")
            .param("limit", "10")
            .build();

        let full_url = req.full_url();
        assert!(full_url.contains("page=1"));
        assert!(full_url.contains("limit=10"));
    }
}
