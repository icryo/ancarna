//! Active security scanner
//!
//! Performs active security testing by sending attack payloads.

#![allow(dead_code)]

pub mod attacks;

use anyhow::Result;

use super::findings::{Finding, Severity};
use super::param_discovery::{CachePoisonTester, ParamMiner, ParamMinerConfig};
use super::policies::ScanPolicy;
use crate::app::Config;
use crate::http::HttpClient;

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

        if policy.is_enabled("xxe") {
            let xxe_findings = attacks::xxe::scan(client, target_url).await?;
            findings.extend(xxe_findings);
        }

        if policy.is_enabled("ssrf") {
            let ssrf_findings = attacks::ssrf::scan(client, target_url).await?;
            findings.extend(ssrf_findings);
        }

        // Parameter mining
        if policy.is_enabled("param_miner") {
            let param_findings = self.run_param_miner(target_url).await?;
            findings.extend(param_findings);
        }

        // Cache poisoning testing
        if policy.is_enabled("cache_poison") {
            let cache_findings = self.run_cache_poison_test(target_url).await?;
            findings.extend(cache_findings);
        }

        Ok(findings)
    }

    /// Run parameter discovery (ParamMiner)
    async fn run_param_miner(&self, target_url: &str) -> Result<Vec<Finding>> {
        let config = ParamMinerConfig::default();
        let miner = ParamMiner::new(config)?;

        let discovered = miner.mine(target_url).await?;
        let mut findings = Vec::new();

        for param in discovered {
            if param.is_interesting {
                let severity = if param.response_status != param.baseline_status {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                let finding = Finding::new("Hidden Parameter Discovered", severity, target_url)
                    .with_description(&format!(
                        "Discovered hidden {} parameter '{}' that causes a response change. {}",
                        param.location.name(),
                        param.name,
                        param.reason.as_deref().unwrap_or("")
                    ))
                    .with_parameter(&param.name)
                    .with_evidence(&format!(
                        "Baseline: {} bytes, {} status | With param: {} bytes, {} status | Time diff: {}ms",
                        param.baseline_length,
                        param.baseline_status,
                        param.response_length,
                        param.response_status,
                        param.time_difference_ms
                    ))
                    .with_scanner("param_miner")
                    .with_confidence(0.7)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_remediation("Review if this parameter is intentional. Hidden parameters may indicate debug functionality or undocumented features that could be exploited.");

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    /// Run cache poisoning tests
    async fn run_cache_poison_test(&self, target_url: &str) -> Result<Vec<Finding>> {
        let tester = CachePoisonTester::new()?;
        let results = tester.test_cache_poisoning(target_url).await?;
        let mut findings = Vec::new();

        for result in results {
            if result.reflected {
                let severity = if result.cached {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let finding = Finding::new("Potential Cache Poisoning", severity, target_url)
                    .with_description(&format!(
                        "The {} header value is reflected in the response, which may allow cache poisoning attacks. {}",
                        result.header,
                        if result.cached { "The poisoned response was cached." } else { "Caching status unknown - verify manually." }
                    ))
                    .with_parameter(&result.header)
                    .with_evidence(&result.details)
                    .with_scanner("cache_poison")
                    .with_confidence(if result.cached { 0.9 } else { 0.6 })
                    .with_cwe(525) // CWE-525: Information Exposure Through Browser Caching
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_reference("https://portswigger.net/research/practical-web-cache-poisoning")
                    .with_remediation("Ensure that unkeyed headers like X-Forwarded-Host are not reflected in cached responses. Consider using Vary headers or disabling caching for dynamic content.");

                findings.push(finding);
            }
        }

        Ok(findings)
    }
}
