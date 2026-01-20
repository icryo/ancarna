//! Active security scanner
//!
//! Performs active security testing by sending attack payloads.

pub mod attacks;

use anyhow::Result;
use std::sync::Arc;

use super::findings::{Finding, Severity};
use super::policies::ScanPolicy;
use crate::app::Config;
use crate::http::{HttpClient, Request};

/// Active scanner
pub struct ActiveScanner {
    /// HTTP client
    client: Option<HttpClient>,

    /// Configuration
    config: Config,
}

impl ActiveScanner {
    pub fn new(config: &Config) -> Self {
        Self {
            client: HttpClient::new(config).ok(),
            config: config.clone(),
        }
    }

    /// Perform active scan on a target
    pub async fn scan(&self, target_url: &str, policy: &ScanPolicy) -> Result<Vec<Finding>> {
        let client = self.client.as_ref()
            .ok_or_else(|| anyhow::anyhow!("HTTP client not initialized"))?;

        let mut findings = Vec::new();

        // Run enabled attack modules
        if policy.is_enabled("sqli") {
            let sqli_findings = attacks::sqli::scan(client, target_url).await?;
            findings.extend(sqli_findings);
        }

        if policy.is_enabled("xss") {
            let xss_findings = attacks::xss::scan(client, target_url).await?;
            findings.extend(xss_findings);
        }

        if policy.is_enabled("path_traversal") {
            let pt_findings = attacks::path_traversal::scan(client, target_url).await?;
            findings.extend(pt_findings);
        }

        if policy.is_enabled("command_injection") {
            let cmd_findings = attacks::command_injection::scan(client, target_url).await?;
            findings.extend(cmd_findings);
        }

        Ok(findings)
    }
}
