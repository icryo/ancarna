//! Attack modules for active scanning

pub mod command_injection;
pub mod path_traversal;
pub mod request_smuggling;
pub mod sqli;
pub mod ssrf;
pub mod xss;
pub mod xxe;

use crate::http::{HttpClient, Request, Response};
use crate::scanner::findings::Finding;

/// Common interface for attack modules
#[async_trait::async_trait]
pub trait AttackModule {
    /// Module name
    fn name(&self) -> &str;

    /// Check if module is applicable to the request
    fn is_applicable(&self, request: &Request) -> bool;

    /// Generate attack payloads
    fn generate_payloads(&self, parameter_value: &str) -> Vec<String>;

    /// Analyze response for vulnerability indicators
    fn analyze_response(&self, request: &Request, response: &Response, payload: &str) -> Option<Finding>;
}
