//! Request interception and modification

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::oneshot;

/// Decision made by user for an intercepted request
#[derive(Debug)]
pub struct InterceptDecision {
    /// Whether to forward the request (false = drop)
    pub forward: bool,
    /// The potentially modified request
    pub request: InterceptedRequest,
}

/// Pending intercept with response channel
pub struct PendingIntercept {
    /// The intercepted request
    pub request: InterceptedRequest,
    /// Channel to send the decision back to proxy
    pub response_tx: oneshot::Sender<InterceptDecision>,
}

/// Intercepted request/response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptedRequest {
    /// History entry ID
    pub id: u64,

    /// HTTP method
    pub method: String,

    /// Full URL
    pub url: String,

    /// HTTP version
    pub http_version: String,

    /// Request headers
    pub headers: HashMap<String, String>,

    /// Request body
    pub body: Option<Vec<u8>>,

    /// Whether this is a response (vs request)
    pub is_response: bool,

    /// Response status code (if response)
    pub status: Option<u16>,

    /// Response status text (if response)
    pub status_text: Option<String>,

    /// Whether the request/response has been modified
    pub modified: bool,

    /// Whether to drop (not forward) the request
    pub drop: bool,
}

impl InterceptedRequest {
    /// Create a new intercepted request
    pub fn new_request(id: u64, method: &str, url: &str) -> Self {
        Self {
            id,
            method: method.to_string(),
            url: url.to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: None,
            is_response: false,
            status: None,
            status_text: None,
            modified: false,
            drop: false,
        }
    }

    /// Create a new intercepted response
    pub fn new_response(id: u64, status: u16, status_text: &str) -> Self {
        Self {
            id,
            method: String::new(),
            url: String::new(),
            http_version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: None,
            is_response: true,
            status: Some(status),
            status_text: Some(status_text.to_string()),
            modified: false,
            drop: false,
        }
    }

    /// Get body as string
    pub fn body_text(&self) -> Option<String> {
        self.body
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).to_string())
    }

    /// Set body from string
    pub fn set_body_text(&mut self, text: &str) {
        self.body = Some(text.as_bytes().to_vec());
        self.modified = true;
    }

    /// Add or update header
    pub fn set_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
        self.modified = true;
    }

    /// Remove header
    pub fn remove_header(&mut self, key: &str) {
        self.headers.remove(key);
        self.modified = true;
    }
}

/// Rule for automatic interception
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    /// Rule name
    pub name: String,

    /// Whether the rule is enabled
    pub enabled: bool,

    /// Match on URL pattern (regex)
    pub url_pattern: Option<String>,

    /// Match on host
    pub host: Option<String>,

    /// Match on method
    pub method: Option<String>,

    /// Match on content type
    pub content_type: Option<String>,

    /// Whether to intercept requests
    pub intercept_requests: bool,

    /// Whether to intercept responses
    pub intercept_responses: bool,

    /// Action to take
    pub action: InterceptAction,
}

/// Action to take when a rule matches
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InterceptAction {
    /// Pause for manual review
    Pause,

    /// Automatically modify
    Modify {
        /// Headers to add/replace
        add_headers: Option<HashMap<String, String>>,
        /// Headers to remove
        remove_headers: Option<Vec<String>>,
        /// Body replacement (if any)
        replace_body: Option<String>,
    },

    /// Drop the request/response
    Drop,

    /// Forward without modification (bypass intercept)
    Forward,
}

impl Default for InterceptRule {
    fn default() -> Self {
        Self {
            name: "New Rule".to_string(),
            enabled: true,
            url_pattern: None,
            host: None,
            method: None,
            content_type: None,
            intercept_requests: true,
            intercept_responses: false,
            action: InterceptAction::Pause,
        }
    }
}

/// Intercept manager
pub struct InterceptManager {
    /// Interception rules
    rules: Vec<InterceptRule>,

    /// Global intercept enabled
    enabled: bool,

    /// Pending intercepted requests (legacy)
    pending: Vec<InterceptedRequest>,

    /// Pending intercept decisions - keyed by request ID
    /// The proxy awaits on the receiver; app sends decision through sender
    pending_decisions: HashMap<u64, oneshot::Sender<InterceptDecision>>,

    /// Next request ID for intercepts
    next_intercept_id: u64,
}

impl InterceptManager {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            enabled: false,
            pending: Vec::new(),
            pending_decisions: HashMap::new(),
            next_intercept_id: 1,
        }
    }

    /// Enable/disable global interception
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if interception is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: InterceptRule) {
        self.rules.push(rule);
    }

    /// Remove a rule by index
    pub fn remove_rule(&mut self, index: usize) {
        if index < self.rules.len() {
            self.rules.remove(index);
        }
    }

    /// Check if a request should be intercepted
    pub fn should_intercept(&self, request: &InterceptedRequest) -> Option<&InterceptRule> {
        if !self.enabled {
            return None;
        }

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if request.is_response && !rule.intercept_responses {
                continue;
            }

            if !request.is_response && !rule.intercept_requests {
                continue;
            }

            // Check URL pattern
            if let Some(pattern) = &rule.url_pattern {
                if let Ok(regex) = regex::Regex::new(pattern) {
                    if !regex.is_match(&request.url) {
                        continue;
                    }
                }
            }

            // Check host
            if let Some(host) = &rule.host {
                let url_host = url::Url::parse(&request.url)
                    .ok()
                    .and_then(|u| u.host_str().map(|s| s.to_string()));
                if url_host.as_deref() != Some(host) {
                    continue;
                }
            }

            // Check method
            if let Some(method) = &rule.method {
                if request.method.to_uppercase() != method.to_uppercase() {
                    continue;
                }
            }

            // All checks passed
            return Some(rule);
        }

        None
    }

    /// Add a request to pending
    pub fn add_pending(&mut self, request: InterceptedRequest) {
        self.pending.push(request);
    }

    /// Get next pending request
    pub fn get_pending(&mut self) -> Option<InterceptedRequest> {
        if self.pending.is_empty() {
            None
        } else {
            Some(self.pending.remove(0))
        }
    }

    /// Get pending count
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Create a new intercept and return the receiver to await on
    /// The request will be assigned an ID and stored
    /// Returns (intercept_id, request_with_id, receiver)
    pub fn create_intercept(&mut self, mut request: InterceptedRequest) -> (u64, InterceptedRequest, oneshot::Receiver<InterceptDecision>) {
        let id = self.next_intercept_id;
        self.next_intercept_id += 1;
        request.id = id;

        let (tx, rx) = oneshot::channel();
        self.pending_decisions.insert(id, tx);

        (id, request, rx)
    }

    /// Resolve an intercept by ID - sends the decision back to the proxy
    /// Returns true if the intercept was found and resolved
    pub fn resolve_intercept(&mut self, id: u64, decision: InterceptDecision) -> bool {
        if let Some(tx) = self.pending_decisions.remove(&id) {
            // Ignore send errors (proxy may have timed out)
            let _ = tx.send(decision);
            true
        } else {
            false
        }
    }

    /// Check if there's a pending intercept for the given ID
    pub fn has_pending_intercept(&self, id: u64) -> bool {
        self.pending_decisions.contains_key(&id)
    }

    /// Cancel all pending intercepts (e.g., on shutdown)
    pub fn cancel_all_intercepts(&mut self) {
        self.pending_decisions.clear();
    }
}

impl Default for InterceptManager {
    fn default() -> Self {
        Self::new()
    }
}
